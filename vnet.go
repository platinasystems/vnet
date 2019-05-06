// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vnet

import (
	"net"
	"sync"

	"github.com/platinasystems/elib"
	"github.com/platinasystems/elib/cpu"
	"github.com/platinasystems/elib/dep"
	"github.com/platinasystems/elib/loop"
	"github.com/platinasystems/elib/parse"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/xeth"
)

//Debug Flags
var AdjDebug bool

// drivers/net/ethernet/xeth/platina_mk1.c: xeth.MsgIfinfo
//
// vnetd.go moved to go/platform/mk1/vnetd.go
// PortEntry go/main/goes-platina-mk1/vnetd.go:vnetdInit() xeth.XETH_MSG_KIND_IFINFO
// PortProvision go/main/goes-platina-mk1/vnetd.go:parsePortConfig() from entry Ports
//
// PortConfig fe1/platform.go:parsePortConfig() PortProvision
// Port fe1/internal/fe1a/port_init.go:PortInit()
//
// 1. go/main/goes-platina-mk1/vnetd
// 2. vnet/unix/fdb PortEntry from msg(1)
// vnetd makes PortProvision(3) from PortEntry
// platform.go parses portprovision to create PortConfig(4)
// which PortInit uses to set config structure(5).
//
// NOTE: PortEntry is used by port, vlan, and bridge devtypes

type PortEntry struct {
	Net          uint64
	Ifindex      int32
	Iflinkindex  int32 // system side eth# ifindex
	Ifname       string
	Flags        xeth.EthtoolPrivFlags
	Iff          net.Flags
	Speed        xeth.Mbps
	Autoneg      uint8
	PortVid      uint16
	Stag         uint16 // internal vlan tag for bridge
	Ctag         uint16 // vlan tag to identify vlan member and set l3_iif/vrf via vlan_xlate
	Portindex    int16
	Subportindex int8
	PuntIndex    uint8 // 0-based meth#, derived from Iflinkindex
	Devtype      uint8
	StationAddr  net.HardwareAddr
	IPNets       []*net.IPNet
}

//var Ports map[string]*PortEntry       // FIXME ifname of bridge need not be unique across netns
//var PortsByIndex map[int32]*PortEntry // FIXME - driver only sends platina-mk1 type
//var SiByIfindex map[int32]Si          // FIXME ifindex is not unique across netns, also impacts PortsByIndex[]

type PortsMap struct {
	sync.Map             // indexed by ifname, value is *PortEntry
	nameByIndex sync.Map //indexed by ifindex, value is ifname
	siByIndex   sync.Map // indexed by ifindex, value is vnet.Si
}

var Ports PortsMap

type BridgeNotifierFn func()

func (p *PortsMap) SetSiByIfindex(ifindex int32, si Si) {
	p.siByIndex.Store(ifindex, si)
}

// port or bridge member
func (p *PortsMap) SetPort(ifname string) (pe *PortEntry) {
	entry, found := p.Load(ifname)
	if !found {
		pe = new(PortEntry)
		pe.StationAddr = make(net.HardwareAddr, 6)
	} else {
		pe = entry.(*PortEntry)
	}
	pe.Ifname = ifname
	p.Store(ifname, pe)
	return
}

func (p *PortsMap) SetPortByIndex(ifindex int32, ifname string) *PortEntry {
	p.nameByIndex.LoadOrStore(ifindex, ifname)
	if entry, found := p.Load(ifname); found {
		return entry.(*PortEntry)
	}
	return nil
}

func (p *PortsMap) GetPortByName(ifname string) (*PortEntry, bool) {
	if entry, found := p.Load(ifname); found {
		return entry.(*PortEntry), found
	}
	return nil, false
}

func (p *PortsMap) GetPortByIndex(ifindex int32) (*PortEntry, bool) {
	if ifname, ok := p.nameByIndex.Load(ifindex); ok {
		if entry, found := p.Load(ifname); found {
			return entry.(*PortEntry), found
		}
	}
	return nil, false
}

func (p *PortsMap) GetSiByIndex(ifindex int32) (Si, bool) {
	if entry, found := p.siByIndex.Load(ifindex); found {
		return entry.(Si), found
	}
	return SiNil, false
}

func (p *PortsMap) GetNameByIndex(ifindex int32) (string, bool) {
	if entry, found := p.nameByIndex.Load(ifindex); found {
		return entry.(string), found
	}
	return "", false
}

func (p *PortsMap) UnsetPort(ifname string) {
	dbgvnet.Bridge.Log(ifname)

	entry, found := p.Load(ifname)

	if found {
		pe := entry.(*PortEntry)
		dbgvnet.Bridge.Logf("delete port %v ctag:%v stag:%v, ifindex %v",
			ifname, pe.Ctag, pe.Stag, pe.Ifindex)
		p.nameByIndex.Delete(pe.Ifindex)
		p.siByIndex.Delete(pe.Ifindex)
		p.Delete(ifname)
	} else {
		dbgvnet.Bridge.Logf("delete port %v, not found", ifname)
	}
}

func (p *PortsMap) Foreach(f func(ifname string, pe *PortEntry)) {
	p.Range(func(key, value interface{}) bool {
		ifname := key.(string)
		pe := value.(*PortEntry)
		f(ifname, pe)
		return true
	})
}

func (p *PortsMap) ForeachNameByIndex(f func(ifindex int32, ifname string)) {
	p.nameByIndex.Range(func(key, value interface{}) bool {
		ifindex := key.(int32)
		ifname := value.(string)
		f(ifindex, ifname)
		return true
	})
}

func (p *PortsMap) ForeachSiByIndex(f func(ifindex int32, si Si)) {
	p.siByIndex.Range(func(key, value interface{}) bool {
		ifindex := key.(int32)
		si := value.(Si)
		f(ifindex, si)
		return true
	})
}

func (p *PortsMap) GetNumSubports(ifname string) (numSubports uint) {
	numSubports = 0
	entry, found := p.Load(ifname)
	if !found {
		return
	}
	portindex := entry.(*PortEntry).Portindex
	p.Foreach(func(ifname string, pe *PortEntry) {
		if pe.Devtype == xeth.XETH_DEVTYPE_XETH_PORT &&
			pe.Portindex == int16(portindex) {
			numSubports++
		}
	})
	return
}

func (p *PortsMap) IfName(portindex, subportindex int) (name string) {
	name = ""
	p.Range(func(key, value interface{}) bool {
		pe := value.(*PortEntry)
		if int(pe.Portindex) == portindex && int(pe.Subportindex) == subportindex {
			name = pe.Ifname
			return false // sync.Map Range stopes after false
		}
		return true // sync.Map Range continues if true
	})
	return
}

var (
	PortIsCopper = func(ifname string) bool { return false }
	PortIsFec74  = func(ifname string) bool { return false }
	PortIsFec91  = func(ifname string) bool { return false }
)

type RxTx int

const (
	Rx RxTx = iota
	Tx
	NRxTx
)

var rxTxStrings = [...]string{
	Rx: "rx",
	Tx: "tx",
}

func (x RxTx) String() (s string) {
	return elib.Stringer(rxTxStrings[:], int(x))
}

type IsDel bool

func (x IsDel) String() string {
	if x {
		return "delete"
	}
	return "add"
}

//go:generate gentemplate -id initHook -d Package=vnet -d DepsType=initHookVec -d Type=initHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
type initHook func(v *Vnet)

var initHooks initHookVec

func AddInit(f initHook, deps ...*dep.Dep) { initHooks.Add(f, deps...) }

func (v *Vnet) configure(in *parse.Input) (err error) {
	if err = v.ConfigurePackages(in); err != nil {
		return
	}
	if err = v.InitPackages(); err != nil {
		return
	}
	return
}
func (v *Vnet) TimeDiff(t0, t1 cpu.Time) float64 { return v.loop.TimeDiff(t1, t0) }

func (v *Vnet) Run(in *parse.Input) (err error) {
	loop.AddInit(func(l *loop.Loop) {
		v.interfaceMain.init()
		v.CliInit()
		v.eventInit()
		for i := range initHooks.hooks {
			initHooks.Get(i)(v)
		}
		if err := v.configure(in); err != nil {
			panic(err)
		}
	})
	v.loop.Run()
	err = v.ExitPackages()
	return
}

func (v *Vnet) Quit() { v.loop.Quit() }

func (pe *PortEntry) AddIPNet(ipnet *net.IPNet) {
	pe.IPNets = append(pe.IPNets, ipnet)
}

func (pe *PortEntry) DelIPNet(ipnet *net.IPNet) {
	for i, peipnet := range pe.IPNets {
		if peipnet.IP.Equal(ipnet.IP) {
			n := len(pe.IPNets) - 1
			copy(pe.IPNets[i:], pe.IPNets[i+1:])
			pe.IPNets = pe.IPNets[:n]
			break
		}
	}
}

type ActionType int

const (
	PreVnetd       ActionType = iota // before vnetd is started
	ReadyVnetd                       // vnetd has declared it's ready
	PostReadyVnetd                   // vnetd processing something initated from previous state
	Dynamic                          // free-run case
)

// Could collapse all vnet Hooks calls into this message
// to avoid direct function calls from vnet to fe
type SviVnetFeMsg struct {
	data []byte
}

const (
	MSG_FROM_VNET = iota
	MSG_SVI_BRIDGE_ADD
	MSG_SVI_BRIDGE_DELETE
	MSG_SVI_BRIDGE_MEMBER_ADD
	MSG_SVI_BRIDGE_MEMBER_DELETE
)

const (
	MSG_FROM_FE = iota + 128
	MSG_SVI_FDB_ADD
	MSG_SVI_FDB_DELETE
)

type FromFeMsg struct {
	MsgId    uint8
	Addr     [6]uint8
	Stag     uint16
	PipePort uint16
}

var SviFromFeCh chan FromFeMsg // for l2-mod learning event reporting

// simplified hooks for direct calls to fe1 from vnet
type BridgeAddDelHook_t func(brsi Si, stag uint16, puntIndex uint8, addr net.HardwareAddr, isAdd bool) (err error)

type BridgeMemberAddDelHook_t func(stag uint16, brmSi Si, pipe_port uint16, ctag uint16, isAdd bool, nBrm uint8) (err error)

type BridgeMemberLookup_t func(stag uint16, addr net.HardwareAddr) (pipe_port uint16, err error)

func (v *Vnet) RegisterBridgeAddDelHook(h BridgeAddDelHook_t) {
	v.BridgeAddDelHook = h
}
func (v *Vnet) RegisterBridgeMemberAddDelHook(h BridgeMemberAddDelHook_t) {
	v.BridgeMemberAddDelHook = h
}
func (v *Vnet) RegisterBridgeMemberLookup(h BridgeMemberLookup_t) {
	v.BridgeMemberLookup = h
}
