// Copyright 2018 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ethernet

import (
	"fmt"

	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/xeth"
)

// bridge member is indexed by portvid and its master's stag
// a port can only appear with one ctag (or untagged) per master
// stored directly in map since it's small struct

type bridgeMember struct {
	Ifindex int32
	Ctag    uint16
}

type Bridge struct {
	port         *vnet.PortEntry         // bridge contains port which is network interface (port has stag and Net/netns)
	members      map[uint16]bridgeMember // bridge config, indexed by portvid
	macToIfindex map[Address]int32       // learned MACs per member: DA maps to ifindex of bridge member
}

func (br *Bridge) String() (dump string) {
	dump = fmt.Sprintf("br[%v] %v stag %v, addr %x\n", vnet.SiByIfindex[br.port.Ifindex], br.port.Ifname, br.port.Stag, br.port.Addr)
	dump += fmt.Sprintf("members: %+v\n", br.members)
	dump += fmt.Sprintf("macToIfindex: %+v\n", br.macToIfindex)
	return
}

// return si for XETH_DEVTYPE_PORT egress to reach da
func (br *Bridge) LookupSiCtag(da Address) (si vnet.Si, ctag uint16) {
	i := br.macToIfindex[da]

	if i == 0 {
		dbgvnet.Bridge.Logf("br dest %+v @unknown", da)
		si = vnet.SiNil
	} else {
		brm := vnet.PortsByIndex[i]
		si = vnet.SiByIfindex[i]
		ctag = brm.Ctag
		dbgvnet.Bridge.Logf("br dest %+v ifindex %v, ctag %v, stag %v, si %v, type %v",
			da, i, brm.Stag, brm.Ctag, si, brm.Devtype)
	}
	return
}

// learned by pipe_port, lookup bridge member via portvid
type PortFdbInfo struct {
	PipePort uint16
	PortVid  uint16
}

var BridgeByStag map[uint16]*Bridge
var PipePortByPortVid map[uint16]uint16 // FIXME remove, not needed for learning lookup

// called from fe1 to init map so vnet can call br api by pipe-port
func (m *Main) SetPortMap(fi []PortFdbInfo) {
	if PipePortByPortVid == nil {
		PipePortByPortVid = make(map[uint16]uint16)
	}
	for _, v := range fi {
		// ignore meth ports
		if v.PortVid != 0 {
			PipePortByPortVid[v.PortVid] = v.PipePort
		}
	}
	dbgvnet.Bridge.Logf("%+v", PipePortByPortVid)
}

type fdbBridgeMember struct {
	stag      uint16
	pipe_port uint16
}

// FIXME ifindex for bridge is not global, must include netns
type fdbBridgeIndex struct {
	bridge int32
	member int32
}

// map TH fdb stag/pipe_port to linux netns/ifindex for bridge and bridge-member
var fdbBrmToIndex = map[fdbBridgeMember]fdbBridgeIndex{}

// indexed by portvid/stag in map
func BridgeMemberAdd(br *Bridge, brm *vnet.PortEntry) {
	entry, found := br.members[brm.PortVid]
	if !found {
		entry = bridgeMember{}
	}
	entry.Ctag = brm.Ctag
	entry.Ifindex = brm.Ifindex
	br.members[brm.PortVid] = entry
	brm.Stag = br.port.Stag
	dbgvnet.Bridge.Logf("stag %v, portvid %v, %+v",
		br.port.Stag, brm.PortVid, br.members)
}

// add/remove port from bridge, no change to netns
// update fdb map of stag/pipeport to ifindex of bridge member
func ProcessChangeUpper(msg *xeth.MsgChangeUpper, action vnet.ActionType, v *vnet.Vnet) (err error) {
	var brm fdbBridgeMember
	var bridx fdbBridgeIndex

	switch action {
	case vnet.PostReadyVnetd:
	case vnet.Dynamic:
	default:
		err = dbgvnet.Bridge.Logf("error: unexpected action: %v", action)
		return
	}

	newBe := vnet.GetPortByIndex(msg.Upper)
	if newBe == nil {
		err = dbgvnet.Bridge.Logf("upper %v, port not found", msg.Upper)
		return
	}
	newBr := BridgeByStag[newBe.Stag]
	if newBr == nil {
		err = dbgvnet.Bridge.Logf("upper %v, br not found", msg.Upper)
		return
	}

	brPort := vnet.GetPortByIndex(msg.Lower)
	if brPort == nil {
		err = dbgvnet.Bridge.Logf("lower %v, not found", msg.Lower)
		return
	}
	if brPort.Devtype != xeth.XETH_DEVTYPE_LINUX_VLAN &&
		brPort.Devtype != xeth.XETH_DEVTYPE_LINUX_VLAN_BRIDGE_PORT {
		dbgvnet.Bridge.Logf("lower[%v] type=%v not vlan, not supported as brm",
			msg.Lower,
			brPort.Devtype)
		return
	}

	if msg.Linking == 0 {
		if brPort.Stag != 0 {
			oldBr := BridgeByStag[brPort.Stag]
			delete(oldBr.members, brPort.PortVid)
			dbgvnet.Bridge.Logf("brm del, stag %v, portvid %v, %+v",
				oldBr.port.Stag, brPort.PortVid, oldBr.members)

			brm.stag = brPort.Stag
			brm.pipe_port = PipePortByPortVid[brPort.PortVid]
			delete(fdbBrmToIndex, brm)
			v.BridgeMemberAddDelHook(vnet.SiByIfindex[msg.Upper], brPort.Stag,
				vnet.SiByIfindex[msg.Lower],
				PipePortByPortVid[brPort.PortVid], brPort.Ctag, false)
		}
	} else {
		brm.stag = newBr.port.Stag
		brm.pipe_port = PipePortByPortVid[brPort.PortVid]
		bridx.bridge = msg.Upper
		bridx.member = msg.Lower
		fdbBrmToIndex[brm] = bridx

		BridgeMemberAdd(newBr, brPort)
		v.BridgeMemberAddDelHook(vnet.SiByIfindex[msg.Upper], newBr.port.Stag,
			vnet.SiByIfindex[msg.Lower],
			PipePortByPortVid[brPort.PortVid], brPort.Ctag, true)
	}
	return
}

func GetBridgeBySi(si vnet.Si) (br *Bridge) {
	for _, b := range BridgeByStag {
		bsi := vnet.SiByIfindex[b.port.Ifindex]
		if bsi == si {
			br = b
			break
		}
	}
	return br
}

// Bridge interface is mapped by name and by stag
// entry is allocated when creating map by ifname
// stag may change, so that map must be refreshed
func SetBridge(stag uint16, ifname string) *vnet.PortEntry {
	dbgvnet.Bridge.Logf("set br %v %v", stag, ifname)
	if BridgeByStag == nil {
		BridgeByStag = make(map[uint16]*Bridge)
	}
	br := BridgeByStag[stag]
	if br == nil {
		br = new(Bridge)
		br.members = make(map[uint16]bridgeMember)
		br.macToIfindex = make(map[Address]int32)
		BridgeByStag[stag] = br
	}
	pe := vnet.SetPort(ifname)
	if pe.Stag != 0 {
		if pe.Stag != stag {
			dbgvnet.Bridge.Logf("br stag changed %v -> %v", pe.Stag, stag) // FIXME update br
		}
	}
	pe.Stag = stag
	pe.Devtype = xeth.XETH_DEVTYPE_LINUX_BRIDGE
	pe.Portindex = -1
	pe.Subportindex = -1

	br.port = pe
	return pe
}

func goSviFromFe() {
	var brm fdbBridgeMember
	var bridx fdbBridgeIndex

	for msg := range vnet.SviFromFeCh {
		dbgvnet.Bridge.Logf("Got message from Fe - %+v", msg)
		switch {
		case msg.MsgId == vnet.MSG_SVI_FDB_ADD:
			brm.stag = msg.Stag
			brm.pipe_port = msg.PipePort
			bridx = fdbBrmToIndex[brm]

			br := BridgeByStag[msg.Stag]
			if br != nil {
				// add entry to fdb so we can lookup L3 interface by bridge/mac
				br.macToIfindex[msg.Addr] = bridx.member
				dbgvnet.Bridge.Logf("br fdb add bridge stag %v, mac %+v -> brm ifindex %v",
					msg.Stag,
					msg.Addr,
					bridx.member)
			}
		case msg.MsgId == vnet.MSG_SVI_FDB_DELETE:
			dbgvnet.Bridge.Logf("br fdb del bridge stag %v, mac %+v",
				msg.Stag,
				msg.Addr)
		}
	}
}

// l2-mod-fifo learning is posted async from fe1 to vnet
func StartFromFeReceivers() {
	if vnet.SviFromFeCh == nil {
		vnet.SviFromFeCh = make(chan vnet.FromFeMsg, 32)
		go goSviFromFe()
	}
}
