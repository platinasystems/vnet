// Copyright 2018 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// File to catch message updates from linux kernel (via platina-mk1 driver) that
// signal different networking events (replacement for netlink.go)
//  - prefix/nexthop add/delete/replace
//  - ifaddr add/delete
//  - ifinfo (admin up/down)
//  - neighbor add/delete/replace
//
package unix

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/platinasystems/elib/cli"
	"github.com/platinasystems/elib/loop"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/ethernet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/vnet/ip"
	"github.com/platinasystems/vnet/ip4"
	"github.com/platinasystems/vnet/unix/internal/dbgfdb"
	"github.com/platinasystems/xeth"
	"github.com/platinasystems/xeth/dbgxeth"
)

var (
	// Function flags
	FdbOn       bool = true
	AllowBridge bool = true
)

const (
	UNSUPPORTED_VLAN_CTAG_RANGE_MIN = 3000 + iota
	UNSUPPORTED_VLAN_CTAG_RANGE_MAX = 3999
)

const MAXMSGSPEREVENT = 1000

type fdbEvent struct {
	vnet.Event
	fm      *FdbMain
	evType  vnet.ActionType
	NumMsgs int
	Msgs    [MAXMSGSPEREVENT][]byte
}

type FdbMain struct {
	loop.Node
	m         *Main
	eventPool sync.Pool
}

func (fm *FdbMain) Init(m *Main) {
	fm.m = m
	fm.eventPool.New = fm.newEvent
	l := fm.m.v.GetLoop()
	fm.cliInit()
	l.RegisterNode(fm, "fdb-listener")
}

// This needs to be used to initialize the eventpool
func (m *FdbMain) newEvent() interface{} {
	return &fdbEvent{fm: m}
}

func (m *FdbMain) GetEvent(evType vnet.ActionType) *fdbEvent {
	v := m.eventPool.Get().(*fdbEvent)
	*v = fdbEvent{fm: m, evType: evType}
	return v
}

func (e *fdbEvent) Signal() {
	if len(e.Msgs) > 0 {
		e.fm.m.v.SignalEvent(e)
	}
}

func (e *fdbEvent) put() {
	e.NumMsgs = 0
	// Zero out array?
	e.fm.eventPool.Put(e)
}

func (e *fdbEvent) String() (s string) {
	l := e.NumMsgs
	s = fmt.Sprintf("fdb %d:", l)
	return
}

func (e *fdbEvent) EnqueueMsg(msg []byte) bool {
	if e.NumMsgs+1 > MAXMSGSPEREVENT {
		return false
	}
	e.Msgs[e.NumMsgs] = msg
	e.NumMsgs++
	if dbgfdb.XethMsg > 0 {
		logMsg("EnqueueMsg " + Summary(msg, e.fm.m.v))
	}
	return true
}

func initVnetFromXeth(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain

	// Initiate walk of PortEntry map to send vnetd
	// interface info and namespaces
	ProcessInterfaceInfo(nil, vnet.ReadyVnetd, v)

	// Initiate walk of PortEntry map to send IFAs
	ProcessInterfaceAddr(nil, vnet.ReadyVnetd, v)

	// Initiate walk of PortEntry map to send vnetd ethtool data
	InitInterfaceEthtool(v)

	// Send events for initial dump of fib entries
	fe := fdbm.GetEvent(vnet.Dynamic)
	xeth.DumpFib()
	for msg := range xeth.RxCh {
		if kind := xeth.KindOf(msg); kind == xeth.XETH_MSG_KIND_BREAK {
			xeth.Pool.Put(msg)
			break
		}
		if ok := fe.EnqueueMsg(msg); !ok {
			// filled event with messages so send it and continue
			fe.Signal()
			fe = fdbm.GetEvent(vnet.Dynamic)
			if ok = fe.EnqueueMsg(msg); !ok {
				panic("can't enqueue initial fdb dump")
			}
		}
	}
	fe.Signal()

	// Drain XETH channel into vnet events.
	go gofdb(v)
}

func gofdb(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.Dynamic)
	dbgfdb.XethMsg.Log("start")
	numMsgs := 0
	for msg := range xeth.RxCh {
		numMsgs++
		if ok := fe.EnqueueMsg(msg); !ok {
			if dbgfdb.XethMsg > 0 {
				logMsg(fmt.Sprintf("gofdb Signal from EnqueueMsg full %v msgs last(%v)", numMsgs, Summary(msg, v)))
			}
			fe.Signal()
			numMsgs = 0
			fe = fdbm.GetEvent(vnet.Dynamic)
			if ok = fe.EnqueueMsg(msg); !ok {
				panic("Can't enqueue fdb")
			}
		}
		if len(xeth.RxCh) == 0 {
			if dbgfdb.XethMsg > 0 {
				logMsg(fmt.Sprintf("gofdb Signal from xeth.RxCh empty %v msgs last(%v)", numMsgs, Summary(msg, v)))
			}
			fe.Signal()
			numMsgs = 0
			fe = fdbm.GetEvent(vnet.Dynamic)
		}
	}
	dbgfdb.XethMsg.Log("quit")
}

func (e *fdbEvent) EventAction() {
	var err error
	m := e.fm
	vn := m.m.v

	if dbgfdb.XethMsg > 0 {
		logMsg(fmt.Sprintf("EventAction %v msgs", e.NumMsgs))
	}

	for i := 0; i < e.NumMsgs; i++ {
		msg := e.Msgs[i]
		kind := xeth.KindOf(msg)
		ptr := unsafe.Pointer(&msg[0])
		switch xeth.KindOf(msg) {
		case xeth.XETH_MSG_KIND_NEIGH_UPDATE:
			err = ProcessIpNeighbor((*xeth.MsgNeighUpdate)(ptr), vn)
		case xeth.XETH_MSG_KIND_FIBENTRY:
			err = ProcessFibEntry((*xeth.MsgFibentry)(ptr), vn)
		case xeth.XETH_MSG_KIND_IFA:
			err = ProcessInterfaceAddr((*xeth.MsgIfa)(ptr), e.evType, vn)
		case xeth.XETH_MSG_KIND_IFINFO:
			err = ProcessInterfaceInfo((*xeth.MsgIfinfo)(ptr), e.evType, vn)
		case xeth.XETH_MSG_KIND_CHANGE_UPPER:
			if AllowBridge {
				err = ethernet.ProcessChangeUpper((*xeth.MsgChangeUpper)(ptr), e.evType, vn)
			}
		case xeth.XETH_MSG_KIND_ETHTOOL_FLAGS:
			msg := (*xeth.MsgEthtoolFlags)(ptr)
			xethif := xeth.Interface.Indexed(msg.Ifindex)
			ifname := xethif.Ifinfo.Name
			vnet.SetPort(ifname).Flags =
				xeth.EthtoolPrivFlags(msg.Flags)
			fec91 := vnet.PortIsFec91(ifname)
			fec74 := vnet.PortIsFec74(ifname)
			dbgfdb.IfETFlag.Log(ifname, "fec91", fec91, "fec74", fec74)
			var fec ethernet.ErrorCorrectionType
			// if both fec91 and fec74 are on, set fec to fec91
			if fec91 {
				fec = ethernet.ErrorCorrectionCL91
			} else if fec74 {
				fec = ethernet.ErrorCorrectionCL74
			} else {
				fec = ethernet.ErrorCorrectionNone
			}
			media := "fiber"
			if vnet.PortIsCopper(ifname) {
				media = "copper"
			}
			dbgfdb.IfETFlag.Log(ifname, media)
			hi, found := vn.HwIfByName(ifname)
			if found {
				dbgfdb.IfETFlag.Log(ifname, "setting",
					"media", media, "fec", fec)
				hi.SetMedia(vn, media)
				err = ethernet.SetInterfaceErrorCorrection(vn, hi, fec)
				dbgfdb.IfETFlag.Log(err, "on", ifname)
			}
		case xeth.XETH_MSG_KIND_ETHTOOL_SETTINGS:
			msg := (*xeth.MsgEthtoolSettings)(ptr)
			xethif := xeth.Interface.Indexed(msg.Ifindex)
			ifname := xethif.Ifinfo.Name
			vnet.SetPort(ifname).Speed =
				xeth.Mbps(msg.Speed)
			hi, found := vn.HwIfByName(ifname)
			if found {
				var bw float64
				if msg.Autoneg == 0 {
					bw = float64(msg.Speed)
				}
				speedOk := false
				dbgfdb.IfETSetting.Log(ifname, "setting speed", bw)
				switch bw {
				case 0, 1000, 10000, 20000, 25000, 40000, 50000, 100000:
					speedOk = true
				}
				if !speedOk {
					err = fmt.Errorf("unexpected speed: %v",
						bw)
					dbgfdb.IfETSetting.Log(err, "on", ifname)
				} else {
					bw *= 1e6
					err = hi.SetSpeed(vn, vnet.Bandwidth(bw))
					dbgfdb.IfETSetting.Log(err, "on", ifname)
				}
			}

		}
		dbgfdb.XethMsg.Log(err, "with kind", kind)
		xeth.Pool.Put(msg)
	}
	e.put()
}

func ipnetToIP4Prefix(ipnet *net.IPNet) (p ip4.Prefix) {
	for i := range ipnet.IP {
		p.Address[i] = ipnet.IP[i]
	}
	maskOnes, _ := ipnet.Mask.Size()
	p.Len = uint32(maskOnes)
	return
}

func (ns *net_namespace) parseIP4NextHops(msg *xeth.MsgFibentry) (nhs ip.NextHopVec) {
	if ns == nil {
		dbgfdb.Fib.Log("ns is nil")
	} else {
		dbgfdb.Fib.Log("ns is", ns.name)
	}
	xethNhs := msg.NextHops()
	dbgfdb.Fib.Log(len(xethNhs), "nexthops")
	nh := ip.NextHop{}
	for _, xnh := range xethNhs {
		intf := ns.interface_by_index[uint32(xnh.Ifindex)]
		if intf == nil {
			dbgfdb.Fib.Log("no ns-intf for ifindex",
				xnh.Ifindex)
			continue
		}
		nh.Si = intf.si
		nh.Weight = ip.NextHopWeight(xnh.Weight)
		if nh.Weight == 0 {
			nh.Weight = 1
		}
		nh.Address = xnh.IP()
		dbgvnet.Adj.Logf("nh.Address %v xnh.IP() %v xnh %v",
			nh.Address, xnh.IP(), xnh)
		nhs = append(nhs, nh)
	}
	return
}

func (ns *net_namespace) parseIP4NextHops_old(msg *xeth.MsgFibentry) (nhs []ip4_next_hop) {
	if ns.ip4_next_hops != nil {
		ns.ip4_next_hops = ns.ip4_next_hops[:0]
	}
	nhs = ns.ip4_next_hops

	if ns == nil {
		dbgfdb.Fib.Log("ns is nil")
	} else {
		dbgfdb.Fib.Log("ns is", ns.name)
	}
	xethNhs := msg.NextHops()
	dbgfdb.Fib.Log(len(xethNhs), "nexthops")
	for i, _ := range xethNhs {
		dbgfdb.Fib.Logf("nexthops[%d]: %#v", i, xethNhs[i])
	}

	// If only 1 nh then assume this is single OIF nexthop
	// otherwise it's multipath
	nh := ip4_next_hop{}
	nh.Weight = 1
	if len(xethNhs) == 1 {
		nh.intf = ns.interface_by_index[uint32(xethNhs[0].Ifindex)]
		if nh.intf == nil {
			dbgfdb.Fib.Log("no ns-intf for ifindex",
				xethNhs[0].Ifindex)
			return
		}
		nh.Si = nh.intf.si
		copy(nh.Address[:], xethNhs[0].IP())
		nhs = append(nhs, nh)
	} else {
		for _, xnh := range xethNhs {
			intf := ns.interface_by_index[uint32(xnh.Ifindex)]
			if intf == nil {
				dbgfdb.Fib.Log("no ns-intf for ifindex",
					xnh.Ifindex)
				continue
			}
			nh.Si = intf.si
			nh.Weight = ip.NextHopWeight(xnh.Weight)
			if nh.Weight == 0 {
				nh.Weight = 1
			}
			copy(nh.Address[:], xnh.IP())
			nhs = append(nhs, nh)
		}
	}
	ns.ip4_next_hops = nhs // save for next call
	return
}

func ProcessIpNeighbor(msg *xeth.MsgNeighUpdate, v *vnet.Vnet) (err error) {

	// For now only doing IPv4
	if msg.Family != syscall.AF_INET {
		dbgfdb.Neigh.Log("msg:", msg, "not actioned because not IPv4")
		return
	}
	if msg.Net == 1 && msg.Ifindex == 2 {
		// ignore eth0 in netns default
		return
	}

	kind := xeth.Kind(msg.Kind)
	netns := xeth.Netns(msg.Net)
	dbgfdb.Neigh.Log(kind, "netns:", netns, "family:", msg.Family)
	var macIsZero bool = true
	for _, i := range msg.Lladdr {
		if i != 0 {
			macIsZero = false
			break
		}
	}
	isDel := macIsZero
	m := GetMain(v)
	ns := getNsByInode(m, msg.Net)
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	addr := msg.CloneIP() // this makes a net.IP out of msg.Dst
	if ns == nil {
		dbgfdb.Ns.Log("namespace", netns, "not found")
		if !lo.Contains(addr) {
			dbgfdb.Neigh.Log("INFO", vnet.IsDel(isDel).String(), "msg:", msg, "not actioned because namespace", netns, "not found")
		}
		return
	}
	si, ok := ns.siForIfIndex(uint32(msg.Ifindex))
	if !ok {
		//dbgfdb.Neigh.Log("no si for", msg.Ifindex, "in", ns.name)
		// Ifindex 2 is eth0
		if !lo.Contains(addr) && msg.Ifindex != 2 {
			dbgfdb.Neigh.Log("INFO", vnet.IsDel(isDel).String(), "msg", msg, "not actioned because no si for", msg.Ifindex, "in", ns.name)
		}
		return
	}

	// Don't enable bridge feature yet
	// FIXME, REMOVEME if enabling bridge
	if !AllowBridge && si.Kind(v) == vnet.SwBridgeInterface {
		dbgfdb.Neigh.Log("Ignore, for now,  bridge neighbor for ", si.Name(v), "in", ns.name)
		return
	}

	dbgfdb.Neigh.Logf("msg.Dst %v ip %v %v\n", msg.Dst, addr.String(), si.Name(v))
	nbr := ethernet.IpNeighbor{
		Si:       si,
		Ethernet: ethernet.Address(msg.Lladdr),
		Ip:       addr,
	}
	m4 := ip4.GetMain(v)
	em := ethernet.GetMain(v)
	dbgfdb.Neigh.Log(vnet.IsDel(isDel).String(), "nbr", nbr)
	_, err = em.AddDelIpNeighbor(&m4.Main, &nbr, isDel)

	// Ignore delete of unknown neighbor.
	if err == ethernet.ErrDelUnknownNeighbor {
		err = nil
	}
	return
}

// Zero Gw processing covers 2 major sub-cases:
// 1. Interface-address setting
//    If local table entry and is a known interface of vnet i.e. front-panel then
//    install an interface address
// 2. Dummy or any other interface that's not a front panel or vlans of a front panel setting
//    If not a known interface of vnet, we assume it's a dummy and install as a punt
//    adjacency (FIXME - need to filter routes through eth0 and others)
func ProcessZeroGw(msg *xeth.MsgFibentry, v *vnet.Vnet, ns *net_namespace, isDel, isLocal, isMainUc bool) (err error) {
	xethNhs := msg.NextHops()
	pe := vnet.GetPortByIndex(xethNhs[0].Ifindex)
	si, ok := ns.siForIfIndex(uint32(xethNhs[0].Ifindex))
	if pe != nil && !ok {
		// found a port entry but no si for it; not expected
		dbgfdb.Fib.Log("INFO found port entry but no si, pe = ", pe)
	}
	if pe != nil && ok {
		// Adds (local comes first followed by main-uc):
		// If local-local route then stash /32 prefix into Port[] table
		// If main-unicast route then lookup port in Port[] table and marry
		// local prefix and main-unicast prefix-len to install interface-address
		// Dels (main-uc comes first followed by local):
		//
		m := GetMain(v)
		ns := getNsByInode(m, pe.Net)
		if ns == nil {
			dbgfdb.Ns.Log("namespace", pe.Net, "not found")
			dbgfdb.Fib.Log("INFO", vnet.IsDel(isDel).String(), "msg:", msg, "not actioned because namespace", xeth.Netns(pe.Net), "not found")
			return
		}
		dbgfdb.Ns.Log("namespace", pe.Net, "found")
		if ok {
			m4 := ip4.GetMain(v)
			if isLocal {
				dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "local", msg.Prefix(), "ifindex", xethNhs[0].Ifindex, "si", si, si.Name(v), si.Kind(v), si.GetType(v))
				m4.AddDelInterfaceAddressRoute(msg.Prefix(), si, ip4.LOCAL, isDel)
			} else if isMainUc {
				dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "main", msg.Prefix(), "ifindex", xethNhs[0].Ifindex, "si", si, si.Name(v), si.Kind(v), si.GetType(v))
				m4.AddDelInterfaceAddressRoute(msg.Prefix(), si, ip4.GLEAN, isDel)
			} else {
				dbgfdb.Fib.Log(vnet.IsDel(isDel).String(),
					"neither local nor main", msg.Prefix(), si.Name(v))
			}
		}
	} else {
		// punt for any other interface not a front-panel or vlans on a front-panel
		dbgfdb.Fib.Log("Non-front-panel", vnet.IsDel(isDel).String(), "punt for", msg.Prefix(), "ifindex", xethNhs[0].Ifindex)
		m4 := ip4.GetMain(v)
		in := msg.Prefix()
		var addr ip4.Address
		for i := range in.IP {
			addr[i] = in.IP[i]
		}
		// Filter 127.*.*.* routes
		if addr[0] == 127 {
			return
		}
		m4.AddDelRoute(in, ns.fibIndexForNamespace(), ip.AdjPunt, isDel)
	}
	return
}

func addrIsZero(addr net.IP) bool {
	var aiz bool = true
	for _, i := range addr {
		if i != 0 {
			aiz = false
			break
		}
	}
	return aiz
}

// NB:
// Using these tests you could replace interface-address message and just use
// fibentry - use this test for interface address routes
// 	if (msg.Id == xeth.RT_TABLE_LOCAL && msg.Type == xeth.RTN_LOCAL) ||
//		(msg.Id == xeth.RT_TABLE_MAIN && msg.Type == xeth.RTN_UNICAST) {
func ProcessFibEntry(msg *xeth.MsgFibentry, v *vnet.Vnet) (err error) {

	var isLocal bool = msg.Id == xeth.RT_TABLE_LOCAL && msg.Type == xeth.RTN_LOCAL
	var isMainUc bool = msg.Id == xeth.RT_TABLE_MAIN && msg.Type == xeth.RTN_UNICAST

	netns := xeth.Netns(msg.Net)
	rtn := xeth.Rtn(msg.Type)
	rtt := xeth.RtTable(msg.Id)
	dbgfdb.Fib.Log(msg)
	// fwiw netlink handling also filters RTPROT_KERNEL and RTPROT_REDIRECT
	if msg.Type != xeth.RTN_UNICAST || msg.Id != xeth.RT_TABLE_MAIN {
		if isLocal {
			dbgfdb.Fib.Log(rtn, "table", rtt, msg.Prefix(),
				"in", netns)
		} else {
			dbgfdb.Fib.Log(nil, "ignore", rtn, "table", rtt,
				"in", netns)
			return
		}
	} else {
		dbgfdb.Fib.Log(rtn, "table", rtt, msg.Prefix(), "in", netns)
	}

	isDel := msg.Event == xeth.FIB_EVENT_ENTRY_DEL
	isReplace := msg.Event == xeth.FIB_EVENT_ENTRY_REPLACE

	m := GetMain(v)
	ns := getNsByInode(m, msg.Net)
	if ns == nil {
		dbgfdb.Ns.Log("namespace", netns, "not found")
		_, lo, _ := net.ParseCIDR("127.0.0.0/8")
		if !lo.Contains(msg.Prefix().IP) {
			dbgfdb.Fib.Log("INFO", vnet.IsDel(isDel).String(), "msg:", msg, "not actioned because namespace", xeth.Netns(msg.Net), "not found")
		}
		return
	}
	nhs := ns.parseIP4NextHops(msg) // this gets rid of next hops that are not xeth interfaces or interfaces built on xeth
	m4 := ip4.GetMain(v)

	xethNhs := msg.NextHops()
	dbgfdb.Fib.Logf("%v%v nexthops for %v\n%v", msg, len(nhs), netns, ns.ShowMsgNextHops(xethNhs))
	// Check for dummy processing
	if len(xethNhs) == 1 {
		if addrIsZero(xethNhs[0].IP()) {
			ProcessZeroGw(msg, v, ns, isDel, isLocal, isMainUc)
			return
		}
	}

	// handle ipv4 only for now
	if a4 := msg.Prefix().IP.To4(); len(a4) == net.IPv4len && len(nhs) > 0 {
		m4.AddDelRouteNextHops(ns.fibIndexForNamespace(), msg.Prefix(), nhs, isDel, isReplace)
	}
	return
}

func (ns *net_namespace) Ip4IfaddrMsg(m4 *ip4.Main, p *net.IPNet, ifindex uint32, isDel bool) (err error) {
	if si, ok := ns.siForIfIndex(ifindex); ok {
		dbgfdb.Ifa.Log(vnet.IsDel(isDel).String(), "si", si)
		ns.validateFibIndexForSi(si)
		err = m4.AddDelInterfaceAddress(si, p, isDel)
		dbgfdb.Ifa.Log(err)
	} else {
		dbgfdb.Ifa.Log("no si for ifindex:", ifindex)
	}
	return
}

func ProcessInterfaceAddr(msg *xeth.MsgIfa, action vnet.ActionType, v *vnet.Vnet) (err error) {
	if msg == nil {
		sendFdbEventIfAddr(v)
		return
	}
	xethif := xeth.Interface.Indexed(msg.Ifindex)
	if xethif == nil {
		err = fmt.Errorf("can't find %d", msg.Ifindex)
		return
	}
	ifname := xethif.Name
	if len(ifname) == 0 {
		err = fmt.Errorf("interface %d has no name", msg.Ifindex)
		return
	}
	pe, found := vnet.Ports[ifname]
	if !found {
		err = dbgfdb.Ifa.Log("ifname not found, ignored", action, msg.IsAdd(), ifname, msg.IPNet())
		return
	}

	ifaevent := xeth.IfaEvent(msg.Event)
	switch action {
	case vnet.PreVnetd:
		// stash addresses for later use
		dbgfdb.Ifa.Log("PreVnetd", ifaevent, msg.IPNet(), "to", ifname)
		if msg.IsAdd() {
			pe.AddIPNet(msg.IPNet())
		} else if msg.IsDel() {
			pe.DelIPNet(msg.IPNet())
		}
	case vnet.ReadyVnetd:
		// Walk Port map and flush any IFAs we gathered at prevnetd time
		dbgfdb.Ifa.Log("ReadyVnetd", ifaevent)
		sendFdbEventIfAddr(v)

		if false {
			m := GetMain(v)
			for _, pe := range vnet.Ports {
				ns := getNsByInode(m, pe.Net)
				if ns != nil {
					dbgfdb.Ifa.Log("ReadyVnetd namespace",
						pe.Net, pe.Ifname)
					m4 := ip4.GetMain(v)
					for _, peipnet := range pe.IPNets {
						ns.Ip4IfaddrMsg(m4, peipnet, uint32(pe.Ifindex), false)
					}
				} else {
					dbgfdb.Ns.Log("ReadyVnetd namespace",
						pe.Net, "not found")
				}
			}
		}

	case vnet.PostReadyVnetd:
		dbgfdb.Ifa.Log("PostReadyVnetd", ifaevent)
		fallthrough
	case vnet.Dynamic:
		dbgfdb.Ifa.Log("Dynamic", ifaevent, msg)
		// vnetd is up and running and received an event, so call into vnet api
		pe, found := vnet.Ports[ifname]
		if !found {
			err = fmt.Errorf("Dynamic IFA - %q unknown", ifname)
			dbgfdb.Ifa.Log(err)
			return
		}
		if FdbOn {
			if action == vnet.Dynamic {
				dbgfdb.Ifa.Log(ifname, ifaevent, msg.IPNet())
				if msg.IsAdd() {
					pe.AddIPNet(msg.IPNet())
				} else if msg.IsDel() {
					pe.DelIPNet(msg.IPNet())
				}
			}

			m := GetMain(v)
			ns := getNsByInode(m, pe.Net)
			if ns != nil {
				dbgfdb.Ns.Log("namespace", pe.Net, "found")
				m4 := ip4.GetMain(v)
				ns.Ip4IfaddrMsg(m4, msg.IPNet(), uint32(pe.Ifindex), msg.IsDel())
			} else {
				dbgfdb.Ns.Log("namespace", pe.Net, "not found")
				dbgfdb.Fib.Log("INFO msg:", msg, "not actioned because namespace", xeth.Netns(pe.Net), "not found")
			}
		}
	}
	return
}

func makeMsgIfa(xethif *xeth.InterfaceEntry, peipnet *net.IPNet) (buf []byte) {
	buf = xeth.Pool.Get(xeth.SizeofMsgIfa)
	msg := (*xeth.MsgIfa)(unsafe.Pointer(&buf[0]))
	msg.Kind = xeth.XETH_MSG_KIND_IFA
	msg.Ifindex = xethif.Index
	msg.Event = xeth.IFA_ADD
	msg.Address = ipnetToUint(peipnet, true)
	msg.Mask = ipnetToUint(peipnet, false)

	dbgfdb.Ifa.Log(xethif.Name, msg.IPNet())
	return
}

func sendFdbEventIfAddr(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)

	for _, pe := range vnet.Ports {
		xethif := xeth.Interface.Indexed(pe.Ifindex)
		for _, peipnet := range pe.IPNets {
			buf := makeMsgIfa(xethif, peipnet)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				// filled event with messages so send event and start a new one
				fe.Signal()
				fe = fdbm.GetEvent(vnet.PostReadyVnetd)
				ok := fe.EnqueueMsg(buf)
				if !ok {
					panic("sendFdbEventIfAddr: Re-enqueue of msg failed")
				}
			}
		}
	}
	dbgfdb.Ifa.Log("sending", fe.NumMsgs, "messages")
	fe.Signal()
}

func pleaseDoAddNamepace(v *vnet.Vnet, net uint64) {
	// Ignore 1 which is default ns and created at init time
	if net == 1 {
		return
	}
	// First try and see if an existing namespace has this net number.
	// If so, just grab it. Otherwise, create a new one.
	m := GetMain(v)
	nm := &m.net_namespace_main
	if nsFound, ok := nm.namespace_by_inode[net]; ok {
		dbgfdb.Ns.Log(nsFound.name, "found for net", net)
	} else {
		name := strconv.FormatUint(net, 10)
		dbgfdb.Ns.Log("trying to add namespace", name)
		nm.addDelNamespace(name, false)
	}
}

// FIXME - need to add logic to handle a namespace that has been orphaned and needs
// to be cleaned out.
func maybeAddNamespaces(v *vnet.Vnet, net uint64) {
	// If specified find or create the namespace with inode-num "net".
	// Otherwise, we walk the PortEntry table and create namespaces
	// that we don't know about
	if net > 0 {
		dbgfdb.Ns.Log("add single ns for", net)
		pleaseDoAddNamepace(v, net)
	} else {
		// March through all port-entries.
		// If we haven't seen a Net before we need to create a net_namespace
		for _, pe := range vnet.Ports {
			dbgfdb.Ns.Log("ReadyVnetd add", pe.Net, "for", pe.Ifname)
			pleaseDoAddNamepace(v, pe.Net)
		}
	}
}

func getNsByInode(m *Main, netNum uint64) *net_namespace {
	if netNum == 1 {
		return &m.default_namespace
	} else {
		return m.namespace_by_inode[netNum]
	}
}

var eth1, eth2 *net.Interface

func makePortEntry(msg *xeth.MsgIfinfo) (pe *vnet.PortEntry) {
	var err error

	if eth1 == nil || eth2 == nil {
		for _, name := range []string{"eth1", "enp3s0f0"} {
			eth1, err = net.InterfaceByName(name)
			if err == nil {
				break
			}
		}
		if err != nil {
			dbgfdb.XethMsg.Log(err)
			return
		}
		for _, name := range []string{"eth2", "enp3s0f1"} {
			eth2, err = net.InterfaceByName(name)
			if err == nil {
				break
			}
		}
		if err != nil {
			dbgfdb.XethMsg.Log(err)
			return
		}
	}

	ifname := xeth.Ifname(msg.Ifname)

	switch msg.Devtype {
	case xeth.XETH_DEVTYPE_XETH_PORT:
		pe = vnet.SetPort(ifname.String())
		pe.Portindex = msg.Portindex
		// -1 is unspecified - from driver
		if msg.Subportindex >= 0 {
			pe.Subportindex = msg.Subportindex
		}
		pe.PortVid = msg.Id
		// convert eth1/eth2 to meth-0/meth-1
		switch msg.Iflinkindex {
		case int32(eth1.Index):
			pe.PuntIndex = 0
		case int32(eth2.Index):
			pe.PuntIndex = 1
		}

	case xeth.XETH_DEVTYPE_LINUX_VLAN_BRIDGE_PORT:
		fallthrough
	case xeth.XETH_DEVTYPE_LINUX_VLAN:
		xp := vnet.GetPortByIndex(msg.Iflinkindex)
		if xp == nil {
			dbgfdb.XethMsg.Logf("vlan no link %v %v", msg.Ifindex, msg.Iflinkindex)
		} else {
			pe = vnet.SetPort(ifname.String())
			pe.PortVid = xp.PortVid
			pe.Portindex = msg.Portindex
			// -1 is unspecified - from driver
			if msg.Subportindex >= 0 {
				pe.Subportindex = msg.Subportindex
			}
			pe.Ctag = msg.Id
		}
	case xeth.XETH_DEVTYPE_LINUX_BRIDGE:
		if AllowBridge {
			pe = ethernet.SetBridge(msg.Id, ifname.String())
			pe.PuntIndex = uint8(pe.Stag & 1)
		}
	}
	if pe == nil {
		dbgfdb.XethMsg.Logf("%v ignored, type=%v", ifname.String(), msg.Devtype)
		return
	}
	pe.Devtype = msg.Devtype
	pe.Ifname = ifname.String()
	pe.Net = msg.Net
	pe.Ifindex = msg.Ifindex
	pe.Iflinkindex = msg.Iflinkindex
	vnet.SetPortByIndex(msg.Ifindex, pe.Ifname)
	pe.Iff = net.Flags(msg.Flags)
	copy(pe.StationAddr, msg.Addr[:])

	dbgfdb.XethMsg.Logf("make(%v,%v) %v ifindex %v, iflinkindex %v, mac %v, punt %v",
		msg.Devtype, xeth.DevType(msg.Devtype).String(), ifname.String(),
		msg.Ifindex, msg.Iflinkindex, pe.StationAddr, pe.PuntIndex)

	return
}

func ProcessInterfaceInfo(msg *xeth.MsgIfinfo, action vnet.ActionType, v *vnet.Vnet) (err error) {
	if msg == nil {
		sendFdbEventIfInfo(v)
		return
	}

	netAddr := make(net.HardwareAddr, 6)
	copy(netAddr, msg.Addr[:])

	kind := xeth.Kind(msg.Kind)
	ifname := (*xeth.Ifname)(&msg.Ifname).String()
	ifindex := uint32(msg.Ifindex)
	reason := xeth.IfinfoReason(msg.Reason)
	netns := xeth.Netns(msg.Net)

	dbgfdb.Ifinfo.Log(action, ifname, ifindex, msg.Devtype)
	if msg.Devtype == xeth.XETH_DEVTYPE_LINUX_VLAN {
		/* disallow specific VLAN ID configs for vlan interfaces
		 */
		if msg.Id >= UNSUPPORTED_VLAN_CTAG_RANGE_MIN &&
			msg.Id <= UNSUPPORTED_VLAN_CTAG_RANGE_MAX {
			dbgfdb.Ifinfo.Log("%v.%v ignored, vlan range %v-%v is reserved",
				msg.Id, ifname,
				UNSUPPORTED_VLAN_CTAG_RANGE_MIN, UNSUPPORTED_VLAN_CTAG_RANGE_MAX)
			return
		}
	}

	switch action {
	case vnet.PreVnetd:
		makePortEntry(msg)
		dbgfdb.Ifinfo.Log("Prevnetd", kind, "makePortEntry", "Ifindex:", msg.Ifindex, "IfName:", ifname, "DevType:", xeth.DevType(msg.Devtype).String())

	case vnet.ReadyVnetd: // not reached
		// Walk Port map and flush into vnet/fe layers the interface info we gathered
		// at prevnetd time. Both namespace and interface creation messages sent during this processing.
		dbgfdb.Ifinfo.Log("ReadyVnetd add", ifname)
		// Signal that all namespaces are now initialized??
		sendFdbEventIfInfo(v)

	case vnet.PostReadyVnetd:
		fallthrough
	case vnet.Dynamic:
		m := GetMain(v)
		ns := getNsByInode(m, msg.Net)
		if ns == nil {
			dbgfdb.Ns.Log("namespace", netns, "not found")
			dbgfdb.Ifinfo.Log("INFO msg:", msg, "not actioned because namespace", xeth.Netns(msg.Net), "not found")
			return
		}
		dbgfdb.Ifinfo.Log("dynamic", reason.String(), kind, netns, ifname, ns.name, msg.Devtype, netAddr)

		pe := vnet.GetPortByIndex(msg.Ifindex)
		if pe == nil {
			// If a vlan or bridge interface we allow dynamic creation so create a cached entry
			if msg.Devtype >= xeth.XETH_DEVTYPE_LINUX_UNKNOWN {
				pe = makePortEntry(msg)
			}
		}

		if pe == nil {
			dbgfdb.Ifinfo.Log("pe is nil - returning")
			return
		}
		if msg.Net != pe.Net {
			// This ifindex has been set into a new namespace so
			// 1. Remove ifindex from previous namespace
			// 2. Add ifindex to new namespace
			nsOld := getNsByInode(m, pe.Net)
			if nsOld == nil {
				// old namespace already removed
				dbgfdb.Ns.Log("Couldn't find old ns:", pe.Net)
			} else {
				nsOld.addDelMk1Interface(m, true, ifname,
					uint32(msg.Ifindex), netAddr, msg.Devtype, msg.Iflinkindex, msg.Id)
			}

			ns.addDelMk1Interface(m, false, ifname,
				uint32(msg.Ifindex), netAddr, msg.Devtype, msg.Iflinkindex, msg.Id)

			dbgfdb.Ifinfo.Log("moving", ifname, pe.Net, netns)
			pe.Net = msg.Net
		} else if action == vnet.PostReadyVnetd {
			// Goes has restarted with interfaces already in existent namespaces,
			// so create vnet representation of interface in this ns.
			// Or this is a dynamically created vlan interface.
			dbgfdb.Ifinfo.Log(ifname, netns)
			ns.addDelMk1Interface(m, false, ifname,
				uint32(msg.Ifindex), netAddr, msg.Devtype,
				msg.Iflinkindex, msg.Id)
		} else if msg.Devtype >= xeth.XETH_DEVTYPE_LINUX_UNKNOWN {
			// create or delete interfaces based on reg/unreg reason
			dbgfdb.Ifinfo.Log(ifname, reason, msg.Devtype, netns)
			if reason == xeth.XETH_IFINFO_REASON_REG {
				ns.addDelMk1Interface(m, false, ifname,
					uint32(msg.Ifindex), netAddr, msg.Devtype,
					msg.Iflinkindex, msg.Id)
			} else if reason == xeth.XETH_IFINFO_REASON_UNREG {
				ns.addDelMk1Interface(m, true, ifname,
					uint32(msg.Ifindex), netAddr, msg.Devtype,
					msg.Iflinkindex, msg.Id)
				if msg.Devtype == xeth.XETH_DEVTYPE_LINUX_BRIDGE {
					ethernet.UnsetBridge(pe.Stag)
				} else {
					vnet.UnsetPort(ifname)
				}
				return
			}
		}
		if ns.interface_by_index[ifindex] != nil {
			// Process admin-state flags
			if si, ok := ns.siForIfIndex(ifindex); ok {
				ns.validateFibIndexForSi(si)
				flags := net.Flags(msg.Flags)
				isUp := flags&net.FlagUp == net.FlagUp
				err = si.SetAdminUp(v, isUp)
				dbgfdb.Ifinfo.Log("SetAdminUp", si, msg.Devtype, isUp, err)
			} else {
				dbgfdb.Si.Log("can't get si of", ifname)
			}
		} else {
			// NB: This is the dynamic front-panel-port-creation case which our lower layers
			// don't support yet. Driver does not send us these but here as a placeholder.
			dbgfdb.Ifinfo.Log("Attempting dynamic port-creation of", ifname)
			if false {
				if action == vnet.Dynamic {
					_, found := vnet.Ports[ifname]
					if !found {
						pe := vnet.SetPort(ifname)
						dbgfdb.Ifinfo.Log("setting",
							ifname, "in", netns)
						pe.Net = msg.Net
						pe.Ifindex = msg.Ifindex
						pe.Iflinkindex = msg.Iflinkindex
						pe.Ifname = ifname
						vnet.SetPortByIndex(msg.Ifindex, pe.Ifname)
						pe.Iff = net.Flags(msg.Flags)
						pe.PortVid = msg.Id
						copy(pe.StationAddr, msg.Addr[:])
						pe.Portindex = msg.Portindex
						pe.Subportindex = msg.Subportindex
						pe.PuntIndex = 0
					}
				}
				ns.addDelMk1Interface(m, false, ifname,
					uint32(msg.Ifindex), netAddr,
					msg.Devtype, msg.Iflinkindex,
					msg.Id)
			}
		}
	}
	return nil
}

func makeMsgIfinfo(entry *xeth.InterfaceEntry) (buf []byte) {
	dbgfdb.Ifinfo.Log(entry.Name, entry.Index, entry.Link)

	buf = xeth.Pool.Get(xeth.SizeofMsgIfinfo)
	msg := (*xeth.MsgIfinfo)(unsafe.Pointer(&buf[0]))
	msg.Kind = xeth.XETH_MSG_KIND_IFINFO
	copy(msg.Ifname[:], entry.Name)
	msg.Ifindex = entry.Index
	msg.Iflinkindex = entry.Link
	copy(msg.Addr[:], entry.HardwareAddr())
	msg.Net = uint64(entry.Netns)
	msg.Id = entry.Id
	msg.Portindex = entry.Port
	msg.Subportindex = entry.Subport
	msg.Flags = uint32(entry.Flags)
	msg.Devtype = uint8(entry.DevType)
	return
}

func makeMsgChangeUpper(lower, upper int32) (buf []byte) {
	dbgfdb.Ifinfo.Log(lower, upper)

	buf = xeth.Pool.Get(xeth.SizeofMsgChangeUpper)
	msg := (*xeth.MsgChangeUpper)(unsafe.Pointer(&buf[0]))
	msg.Kind = xeth.XETH_MSG_KIND_CHANGE_UPPER
	msg.Lower = lower
	msg.Upper = upper
	msg.Linking = 1
	return
}

// send XETH_PORT first to ensure (ifindex port) enqueued before (ifindex vlan-interface) which refs port via iflinkindex
func sendFdbEventIfInfo(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)

	for _, i := range [2]bool{false, true} {
		xeth.Interface.Iterate(func(entry *xeth.InterfaceEntry) error {
			if qualify := entry.DevType == xeth.XETH_DEVTYPE_XETH_PORT; !i && !qualify || i && qualify {
				return nil
			}
			buf := makeMsgIfinfo(entry)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				// filled event with messages so send event and start a new one
				fe.Signal()
				fe = fdbm.GetEvent(vnet.PostReadyVnetd)
				ok := fe.EnqueueMsg(buf)
				if !ok {
					panic("sendFdbEventIfInfo: Re-enqueue of msg failed")
				}
			}
			return nil
		})
	}

	xeth.Interface.Iterate(func(entry *xeth.InterfaceEntry) error {
		entry.Uppers.ForeachKey(func(upper int32) {
			buf := makeMsgChangeUpper(entry.Index, upper)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				// filled event with messages so send event and start a new one
				fe.Signal()
				fe = fdbm.GetEvent(vnet.PostReadyVnetd)
				ok := fe.EnqueueMsg(buf)
				if !ok {
					panic("sendFdbEventIfInfo: Re-enqueue of msg failed")
				}
			}
		})
		return nil
	})

	fe.Signal()
}

func ipnetToUint(ipnet *net.IPNet, ipNotMask bool) uint32 {
	if ipNotMask {
		return *(*uint32)(unsafe.Pointer(&ipnet.IP[0]))
	} else {
		return *(*uint32)(unsafe.Pointer(&ipnet.Mask[0]))
	}
}

func InitInterfaceEthtool(v *vnet.Vnet) {
	sendFdbEventEthtoolSettings(v)
	sendFdbEventEthtoolFlags(v)
}

func sendFdbEventEthtoolSettings(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)
	for _, pe := range vnet.Ports {
		xethif := xeth.Interface.Indexed(pe.Ifindex)
		ifindex := xethif.Ifinfo.Index
		ifname := xethif.Ifinfo.Name
		if xethif.Ifinfo.DevType != xeth.XETH_DEVTYPE_XETH_PORT {
			continue
		}
		dbgfdb.Ifinfo.Log(ifname, pe)
		buf := xeth.Pool.Get(xeth.SizeofMsgEthtoolSettings)
		msg := (*xeth.MsgEthtoolSettings)(unsafe.Pointer(&buf[0]))
		msg.Kind = xeth.XETH_MSG_KIND_ETHTOOL_SETTINGS
		msg.Ifindex = ifindex
		msg.Speed = uint32(pe.Speed)
		msg.Autoneg = pe.Autoneg
		// xeth layer is cacheing the rest of this message
		// in future can just reference that and send it along here
		ok := fe.EnqueueMsg(buf)
		if !ok {
			// filled event with messages so send event and start a new one
			fe.Signal()
			fe = fdbm.GetEvent(vnet.PostReadyVnetd)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				panic("sendFdbEventEthtoolSettings: Re-enqueue of msg failed")
			}
		}
	}
	fe.Signal()
}

func sendFdbEventEthtoolFlags(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)
	for _, pe := range vnet.Ports {
		xethif := xeth.Interface.Indexed(pe.Ifindex)
		ifindex := xethif.Ifinfo.Index
		ifname := xethif.Ifinfo.Name
		if xethif.Ifinfo.DevType != xeth.XETH_DEVTYPE_XETH_PORT {
			continue
		}
		dbgfdb.Ifinfo.Log(ifname, pe)
		buf := xeth.Pool.Get(xeth.SizeofMsgEthtoolFlags)
		msg := (*xeth.MsgEthtoolFlags)(unsafe.Pointer(&buf[0]))
		msg.Kind = xeth.XETH_MSG_KIND_ETHTOOL_FLAGS
		msg.Ifindex = ifindex
		msg.Flags = uint32(pe.Flags)
		// xeth layer is cacheing the rest of this message
		// in future can just reference that and send it along here
		ok := fe.EnqueueMsg(buf)
		if !ok {
			// filled event with messages so send event and start a new one
			fe.Signal()
			fe = fdbm.GetEvent(vnet.PostReadyVnetd)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				panic("sendFdbEventEthtoolFlags: Re-enqueue of msg failed")
			}
		}
	}
	fe.Signal()
}

func addDelReplace(isDel, isReplace bool) string {
	if isReplace {
		return "replace"
	} else if isDel {
		return "del"
	}
	return "add"
}

func (ns *net_namespace) ShowMsgNextHops(xethNhs []xeth.NextHop) (s string) {
	for _, xnh := range xethNhs {
		intf := ns.interface_by_index[uint32(xnh.Ifindex)]
		intfName := "nil"
		if intf != nil {
			intfName = intf.name
		}
		s += fmt.Sprintf("Intf %v; Weight %v; Flags %v; Gw %v; Scope %v; Pad %v\n",
			intfName, xnh.Weight, xnh.Flags, xnh.IP(), ScopeTranslate(xnh.Scope), xnh.Pad)
	}
	return
}

func ScopeTranslate(scope uint8) string {
	switch scope {
	case 255:
		return "Nowhere"
	case 254:
		return "Host"
	case 253:
		return "Link"
	case 200:
		return "Site" // Ipv6
	case 0:
		return "Universe"
	default:
		return strconv.Itoa(int(scope))
	}
}

type fdbBridgeMember struct {
	stag      uint16
	pipe_port uint16
}

type fdbBridgeIndex struct {
	bridge int32
	member int32
}

// map TH fdb stag/port to ctag/port on linux bridge
// no need to sanity check reverse intf/ctag map since an intf/ctag only has one upper stag
// ctag=0 will be used for untagged member
var fdbBrmToIndex = map[fdbBridgeMember]fdbBridgeIndex{}

func (m *FdbMain) fdbPortShow(c cli.Commander, w cli.Writer, in *cli.Input) (err error) {
	show_linux := false

	for !in.End() {
		switch {
		case in.Parse("l%*inux"):
			show_linux = true
		default:
			err = cli.ParseError
			return
		}
	}

	for _, e := range vnet.Ports {
		if !show_linux || e.Devtype >= xeth.XETH_DEVTYPE_LINUX_UNKNOWN {
			fmt.Fprintf(w, "si:%v %+v\n", vnet.SiByIfindex[e.Ifindex], e)
		}
	}

	fmt.Fprintln(w, "\nPortsByIndex")
	lines := 0
	for i, e := range vnet.PortsByIndex {
		fmt.Fprintf(w, "%v:%v\t", i, e.Ifname)
		lines++
		if lines&7 == 0 {
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w, "\nSiByIfIndex")
	lines = 0
	for i, si := range vnet.SiByIfindex {
		fmt.Fprintf(w, "%v:%v\t", i, si)
		lines++
		if lines&7 == 0 {
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintf(w, "\nmap lengths: name %v, index %v, si %v\n",
		len(vnet.Ports), len(vnet.PortsByIndex), len(vnet.SiByIfindex))

	return
}

const maxMsgHistory = 1000

var msgHistory []string

func Summary(buff []byte, v *vnet.Vnet) (s string) {
	kind := xeth.KindOf(buff)
	ptr := unsafe.Pointer(&buff[0])
	switch kind {
	case xeth.XETH_MSG_KIND_BREAK:
	case xeth.XETH_MSG_KIND_LINK_STAT:
	case xeth.XETH_MSG_KIND_ETHTOOL_STAT:
	case xeth.XETH_MSG_KIND_ETHTOOL_FLAGS:
		msg := (*xeth.MsgEthtoolFlags)(ptr)
		xethif := xeth.Interface.Indexed(msg.Ifindex)
		ifname := xethif.Ifinfo.Name
		s = fmt.Sprintf("%v %v %v", kind, ifname, xeth.EthtoolPrivFlags(msg.Flags))
	case xeth.XETH_MSG_KIND_ETHTOOL_SETTINGS:
		msg := (*xeth.MsgEthtoolSettings)(ptr)
		xethif := xeth.Interface.Indexed(msg.Ifindex)
		ifname := xethif.Ifinfo.Name
		s = fmt.Sprintf("%v %v autoneg %v speed %v", kind, ifname, msg.Autoneg, xeth.Mbps(msg.Speed))
	case xeth.XETH_MSG_KIND_DUMP_IFINFO:
	case xeth.XETH_MSG_KIND_CARRIER:
	case xeth.XETH_MSG_KIND_SPEED:
	case xeth.XETH_MSG_KIND_IFINFO:
		msg := (*xeth.MsgIfinfo)(ptr)
		ifname := (*xeth.Ifname)(&msg.Ifname).String()
		s = fmt.Sprintf("%v %v %v", kind, ifname, xeth.DevType(msg.Devtype))
	case xeth.XETH_MSG_KIND_IFA:
		msg := (*xeth.MsgIfa)(ptr)
		ifname := fmt.Sprintf("unknown ifindex %v", msg.Ifindex)
		if xethif := xeth.Interface.Indexed(msg.Ifindex); xethif != nil {
			ifname = xethif.Ifinfo.Name
		}
		s = fmt.Sprintf("%v %v %v %v", kind, ifname, xeth.IfaEvent(msg.Event), msg.IPNet())
	case xeth.XETH_MSG_KIND_DUMP_FIBINFO:
	case xeth.XETH_MSG_KIND_FIBENTRY:
		msg := (*xeth.MsgFibentry)(ptr)
		netns := xeth.Netns(msg.Net)
		namespace := fmt.Sprintf("unknown namespace %v", netns)
		if ns := getNsByInode(GetMain(v), msg.Net); ns != nil {
			namespace = fmt.Sprintf("namespace %v", ns.name)
		}
		rtn := xeth.Rtn(msg.Type)
		rtt := xeth.RtTable(msg.Id)
		s = fmt.Sprintf("%v %v %v %v %v %v", kind, namespace, rtn, rtt, msg.Prefix(), msg.NextHops())
	case xeth.XETH_MSG_KIND_IFDEL:
	case xeth.XETH_MSG_KIND_NEIGH_UPDATE:
		msg := (*xeth.MsgNeighUpdate)(ptr)
		netns := xeth.Netns(msg.Net)
		addr := msg.CloneIP()
		devName := fmt.Sprintf("unknown si %v", msg.Ifindex)
		namespace := fmt.Sprintf("unknown namespace %v", netns)
		if ns := getNsByInode(GetMain(v), msg.Net); ns != nil {
			if si, ok := ns.siForIfIndex(uint32(msg.Ifindex)); ok {
				devName = si.Name(v)
			}
			namespace = fmt.Sprintf("namespace %v", ns.name)
		}
		s = fmt.Sprintf("%v %v %v dev %v lladdr %v", kind, namespace, addr.String(), devName, ethernet.Address(msg.Lladdr))
	case xeth.XETH_MSG_KIND_IFVID:
	case xeth.XETH_MSG_KIND_CHANGE_UPPER:
		msg := (*xeth.MsgChangeUpper)(ptr)
		s = fmt.Sprintf("%v", msg.Kind)
	default:
		s = fmt.Sprintf("%v", kind)
	}
	return
}

func logMsg(s string) {
	if len(msgHistory) > maxMsgHistory {
		msgHistory = msgHistory[1:]
	}
	s = fmt.Sprintf("%v ", time.Now().Format(time.UnixDate)) + s
	msgHistory = append(msgHistory, s)
}

func (m *FdbMain) showLastFdbMsgs(c cli.Commander, w cli.Writer, in *cli.Input) (err error) {
	for _, line := range msgHistory {
		fmt.Fprintln(w, line)
	}
	return nil
}

func (m *FdbMain) cliInit() (err error) {
	v := m.m.v

	cmds := []cli.Command{
		cli.Command{
			Name:      "show ports",
			ShortHelp: "help",
			Action:    m.fdbPortShow,
		},
	}
	for i := range cmds {
		v.CliAdd(&cmds[i])
	}
	if dbgfdb.XethMsg > 0 {
		lsh := fmt.Sprintf("show last %v received xeth messages", maxMsgHistory)
		cmd := cli.Command{
			Name:      "show last-fdb-msgs",
			ShortHelp: lsh,
			Action:    m.showLastFdbMsgs,
		}
		v.CliAdd(&cmd)
	}
	if dbgxeth.Chan > 0 {
		lsh := fmt.Sprintf("show last %v messages to/from kernel", xeth.MaxEventHistory)
		cmd := cli.Command{
			Name:      "show last-kernel-msgs",
			ShortHelp: lsh,
			Action:    xeth.ShowLastEvents,
		}
		v.CliAdd(&cmd)
	}
	return
}
