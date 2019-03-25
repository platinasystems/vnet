// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ethernet

import (
	"github.com/platinasystems/elib/cpu"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/vnet/ip"

	"errors"
	"fmt"
	"net"
)

type ipNeighborFamily struct {
	m              *ip.Main
	pool           ipNeighborPool
	indexByAddress map[ipNeighborKey]uint
}

type ipNeighborMain struct {
	v *vnet.Vnet
	// Ip4/Ip6 neighbors.
	ipNeighborFamilies [ip.NFamily]ipNeighborFamily
}

func (m *ipNeighborMain) init(v *vnet.Vnet, im4, im6 *ip.Main) {
	m.v = v
	m.ipNeighborFamilies[ip.Ip4].m = im4
	m.ipNeighborFamilies[ip.Ip6].m = im6
	v.RegisterSwIfAddDelHook(m.swIfAddDel)
	v.RegisterSwIfAdminUpDownHook(m.swIfAdminUpDown)
}

type ipNeighborKey struct {
	Ip string // stringer of net.IP
	Si vnet.Si
}

type IpNeighbor struct {
	Ethernet Address
	Ip       net.IP
	Si       vnet.Si
}

type ipNeighbor struct {
	IpNeighbor
	index        uint
	lastTimeUsed cpu.Time
}

//go:generate gentemplate -d Package=ethernet -id ipNeighbor -d PoolType=ipNeighborPool -d Data=neighbors -d Type=ipNeighbor github.com/platinasystems/elib/pool.tmpl

var ErrDelUnknownNeighbor = errors.New("delete unknown neighbor")

func (m *ipNeighborMain) AddDelIpNeighbor(im *ip.Main, n *IpNeighbor, isDel bool) (ai ip.Adj, err error) {
	var rwSi vnet.Si
	var isBridge bool
	var ctag, stag uint16
	var br *bridgeEntry

	ai = ip.AdjNil
	nf := &m.ipNeighborFamilies[im.Family]

	// if bridge, then rwSi is the member port to reach the DA
	if n.Si.Kind(m.v) == vnet.SwBridgeInterface {
		isBridge = true
		// FIXME need to flush fib when L2 entry removed
		br = GetBridgeBySi(n.Si)
		stag = br.port.Stag

		// rewrite si port is bridge member
		// si passed to fe1/fib install_adj() via rewrite is the bridge member to reach DA
		rwSi, ctag = br.LookupSiCtag(n.Ethernet, m.v)
		if rwSi == vnet.SiNil {
			dbgvnet.Adj.Logf("DA %v unresolved for br %v", n.Ethernet, br.port.Stag)
			// if unknown, enqueue for later  FIXME
			return
		}
		dbgvnet.Adj.Logf("rewrite br %v stag %v prefix %v, si %v ctag %v",
			vnet.SiName{V: m.v, Si: n.Si}, br.port.Stag, &n.Ip, rwSi, ctag)
	} else {
		rwSi = n.Si
		dbgvnet.Adj.Logf("rewrite %v prefix %v",
			vnet.SiName{V: m.v, Si: n.Si}, &n.Ip)
	}

	var (
		k  ipNeighborKey
		i  uint
		ok bool
	)
	k.Si, k.Ip = rwSi, n.Ip.String()
	if i, ok = nf.indexByAddress[k]; !ok {
		if isDel {
			dbgvnet.Adj.Logf("INFO delete unknown neighbor %v %v", vnet.SiName{V: m.v, Si: rwSi}, &n.Ip)
			err = ErrDelUnknownNeighbor
			return
		}
		i = nf.pool.GetIndex()
	}
	in := &nf.pool.neighbors[i]

	var (
		as     []ip.Adjacency
		prefix net.IPNet
	)
	prefix.IP = n.Ip
	prefix.Mask = net.CIDRMask(32, 32)
	if im.Family == ip.Ip6 {
		prefix.Mask = net.CIDRMask(128, 128)
	}
	if ok {
		ai, as, ok = im.GetReachable(&prefix, rwSi)

		// Delete from map both of add and delete case.
		// For add case we'll re-add to indexByAddress.
		delete(nf.indexByAddress, k)
	}

	if isDel {
		if len(as) > 0 {
			dbgvnet.Adj.Logf("call AddDelRoute to delete %v adj %v from %v",
				prefix.String(), ai.String(), vnet.SiName{V: m.v, Si: rwSi})
			if _, err = im.AddDelRoute(&prefix, im.FibIndexForSi(rwSi), ai, isDel); err != nil {
				return
			}

			im.DelAdj(ai)
		} else {
			dbgvnet.Adj.Logf("DEBUG delete neighbor %v but did not find an adj, got ai = %v\n", prefix.String(), ai.String())
		}
		ai = ip.AdjNil
		*in = ipNeighbor{}
	} else {
		is_new_adj := len(as) == 0
		if is_new_adj {
			ai, as = im.NewAdj(1)
		}
		rw := &as[0].Rewrite

		sw := m.v.SwIf(rwSi)
		hw := m.v.SupHwIf(sw)
		if hw == nil {
			dbgvnet.Adj.Logf("rewrite got nil for SupHwIf; si %v, %v, kind %v, sup_si %v",
				rwSi, vnet.SiName{V: m.v, Si: rwSi}, rwSi.Kind(m.v).String(), m.v.SupSi(rwSi))
			return
		}
		rw.Stag = stag
		h := m.v.SetRewriteNodeHwIf(rw, hw, im.RewriteNode)
		rw.Si = rwSi

		if isBridge {
			br.SetRewrite(m.v, rw, im.PacketType, n.Ethernet[:], ctag)
		} else {
			h.SetRewrite(m.v, rw, im.PacketType, n.Ethernet[:])
		}
		as[0].LookupNextIndex = ip.LookupNextRewrite

		dbgvnet.Adj.Logf("rewrite: new %v, kind %v, si %v, name %v, prefix %v",
			is_new_adj,
			rwSi.Kind(m.v),
			rw.Si,
			vnet.SiName{V: m.v, Si: rwSi},
			prefix.String(),
		)

		if is_new_adj {
			im.CallAdjAddHooks(ai)
		}
		if _, err = im.AddDelRoute(&prefix, im.FibIndexForSi(rwSi), ai, isDel); err != nil {
			return
		}

		// Update neighbor fields (ethernet address may change).
		in.IpNeighbor = *n
		in.index = i
		in.lastTimeUsed = cpu.TimeNow()

		if nf.indexByAddress == nil {
			nf.indexByAddress = make(map[ipNeighborKey]uint)
		}
		nf.indexByAddress[k] = i
	}
	return
}

func (m *ipNeighborMain) delKey(nf *ipNeighborFamily, k *ipNeighborKey) (err error) {
	ip := net.ParseIP(k.Ip)
	if ip == nil {
		fmt.Printf("DEBUG delKey invalid key %v {%v %v}\n", k, k.Ip, vnet.SiName{V: m.v, Si: k.Si})
		//panic(err)
	}
	n := IpNeighbor{
		Ip: ip,
		Si: k.Si,
	}
	const isDel = true
	dbgvnet.Adj.Logf("INFO delete neighbor %v %v from swIf delete\n", vnet.SiName{V: m.v, Si: n.Si}, &n.Ip)
	_, err = m.AddDelIpNeighbor(nf.m, &n, isDel)
	return
}

func (m *ipNeighborMain) swIfAdminUpDown(v *vnet.Vnet, si vnet.Si, up bool) (err error) {
	return m.swIfAddDel(v, si, !up)
}

func (m *ipNeighborMain) swIfAddDel(v *vnet.Vnet, si vnet.Si, isDel bool) (err error) {
	if isDel {
		for fi := range m.ipNeighborFamilies {
			nf := &m.ipNeighborFamilies[fi]
			for k, _ := range nf.indexByAddress {
				if k.Si == si {
					if err = m.delKey(nf, &k); err != nil {
						return
					}
				}
			}
		}
	}
	return
}
