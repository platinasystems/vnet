// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vnet

import (
	"net"

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
	Addr         net.HardwareAddr
	IPNets       []*net.IPNet
}

var Ports map[string]*PortEntry       // FIXME ifname of bridge need not be unique across netns
var PortsByIndex map[int32]*PortEntry // FIXME - driver only sends platina-mk1 type
var SiByIfindex map[int32]Si          // FIXME ifindex is not unique across netns, also impacts PortsByIndex[]

type BridgeNotifierFn func()

func (v *Vnet) SetSiByIfindex(ifindex uint32, si Si) {
	if SiByIfindex == nil {
		SiByIfindex = make(map[int32]Si)
	}
	SiByIfindex[int32(ifindex)] = si
}

// port or bridge member
func SetPort(ifname string) *PortEntry {
	if Ports == nil {
		Ports = make(map[string]*PortEntry)
	}
	entry, found := Ports[ifname]
	if !found {
		entry = new(PortEntry)
		Ports[ifname] = entry
	}
	entry.Ifname = ifname
	return entry
}

func SetPortByIndex(ifindex int32, ifname string) *PortEntry {
	if PortsByIndex == nil {
		PortsByIndex = make(map[int32]*PortEntry)
	}
	PortsByIndex[ifindex] = Ports[ifname]
	return PortsByIndex[ifindex]
}

func GetPortByIndex(ifindex int32) (entry *PortEntry) {
	if PortsByIndex == nil {
		return nil
	}
	entry, _ = PortsByIndex[ifindex]
	return entry
}

func UnsetPort(ifname string) {
	dbgvnet.Bridge.Log(ifname)

	entry, found := Ports[ifname]
	if found {
		dbgvnet.Bridge.Logf("delete port %v, ifindex %v", ifname, entry.Ifindex)
		delete(SiByIfindex, entry.Ifindex)
		delete(PortsByIndex, entry.Ifindex)
		delete(Ports, ifname)
	}
}

func GetNumSubports(ifname string) (numSubports uint) {
	numSubports = 0
	entry, found := Ports[ifname]
	if !found {
		return
	}
	portindex := entry.Portindex
	for _, pe := range Ports {
		if pe.Devtype == xeth.XETH_DEVTYPE_XETH_PORT &&
			pe.Portindex == int16(portindex) {
			numSubports++
		}
	}
	return
}

func IfName(portindex, subportindex int) (name string) {
	name = ""
	for _, pe := range Ports {
		if int(pe.Portindex) == portindex && int(pe.Subportindex) == subportindex {
			name = pe.Ifname
		}
	}
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

/* removed to avoid concurrent pci
var SviFromVnetCh chan FromVnetMsg

type FromVnetMsg struct {
	MsgId     uint8
	PuntIndex uint8
	Stag      uint16
	PortVid   uint16
	PipePort  uint16
	Ctag      uint16
	Addr      [6]uint8
}

if vnet.SviFromVnetCh != nil {
	feCfg := vnet.FromVnetMsg{
		MsgId:    vnet.MSG_SVI_BRIDGE_MEMBER_DELETE,
		Stag:     brPort.Stag,
		PipePort: PipePortByPortVid[brPort.PortVid],
		Ctag:     brPort.Ctag}
	dbgvnet.Adj.Log("FromVnet", feCfg)
	vnet.SviFromVnetCh <- feCfg
}
*/

var SviFromFeCh chan FromFeMsg // for l2-mod learning event reporting

// simplified hooks for direct calls to fe1 from vnet
type BridgeAddDelHook_t func(si Si, stag uint16, puntIndex uint8, addr net.HardwareAddr, isAdd bool) (err error)

type BridgeMemberAddDelHook_t func(si Si, stag uint16, brmSi Si, pipe_port uint16, ctag uint16, isAdd bool) (err error)

func (v *Vnet) RegisterBridgeAddDelHook(h BridgeAddDelHook_t) {
	v.BridgeAddDelHook = h
}
func (v *Vnet) RegisterBridgeMemberAddDelHook(h BridgeMemberAddDelHook_t) {
	v.BridgeMemberAddDelHook = h
}
