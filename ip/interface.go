// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip

import (
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"

	"fmt"
	"net"
)

type IfAddr uint32

const IfAddrNil = ^IfAddr(0)

//go:generate gentemplate -d Package=ip -id IfAddr -d VecType=IfAddrVec -d Type=IfAddr github.com/platinasystems/elib/vec.tmpl

type IfAddress struct {
	// ip4/ip6 address and map key plus length.
	Prefix net.IPNet

	// Interface which has this address.
	Si vnet.Si

	NeighborProbeAdj Adj

	// Next and previous pointers in doubly-linked list of interface addresses for this interface.
	next, prev IfAddr
}

func (i IfAddr) String(m *Main) string {
	a := m.GetIfAddr(i)
	return a.Si.Name(m.v)
}

//go:generate gentemplate -d Package=ip -id ifaddress -d PoolType=ifAddressPool -d Type=IfAddress -d Data=ifAddrs github.com/platinasystems/elib/pool.tmpl

type ifAddrMapKey struct {
	a string // stringer of net.IP
	i FibIndex
}

type ifAddressMain struct {
	ifAddressPool

	// Maps ip4/ip6 address to pool index.
	addrMap map[ifAddrMapKey]IfAddr

	// Head of doubly-linked list indexed by software interface.
	headBySwIf IfAddrVec
}

func (m *Main) swIfAddDel(v *vnet.Vnet, si vnet.Si, isDel bool) (err error) {
	if isDel {
		// Remove any remaining addresses when interface is deleted.
		ai := m.headBySwIf[si]
		for ai != IfAddrNil {
			a := m.GetIfAddr(ai)
			k := makeIfAddrMapKey(a.Prefix.IP, m.FibIndexForSi(si))
			delete(m.addrMap, k)
			dbgvnet.Adj.Logf("INFO delete IfAddr %v %v from swIf delete\n", a.Prefix.String(), si.Name(v))
			m.ifAddressPool.PutIndex(uint(ai))
			ai = a.next
		}
		m.headBySwIf[si] = IfAddrNil
	} else {
		m.headBySwIf.ValidateInit(uint(si), IfAddrNil)
	}
	return
}

func (*ifAddressMain) init(m *Main) {
	m.v.RegisterSwIfAddDelHook(m.swIfAddDel)
}

func makeIfAddrMapKey(a net.IP, i FibIndex) (k ifAddrMapKey) {
	//copy(k.a[:], a)
	k.a = a.String()
	k.i = i
	return
}

func (m *ifAddressMain) GetIfAddress(a net.IP, i FibIndex) (ia *IfAddress) {
	k := makeIfAddrMapKey(a, i)
	if i, ok := m.addrMap[k]; ok {
		ia = &m.ifAddrs[i]
	}
	return
}
func (m *ifAddressMain) GetIfAddr(i IfAddr) *IfAddress {
	if int(i) >= len(m.ifAddrs) {
		panic(fmt.Errorf("GetIfAddr index %v out of range", i))
	}
	return &m.ifAddrs[i]
}
func (m *ifAddressMain) IfFirstAddr(i vnet.Si) IfAddr {
	if int(i) >= len(m.headBySwIf) {
		panic(fmt.Errorf("IfFirstAddr Si %v out of range", i))
	}
	return m.headBySwIf[i]
}
func (m *ifAddressMain) IfFirstAddress(i vnet.Si) (ifa *IfAddress) {
	ia := m.IfFirstAddr(i)
	if ia != IfAddrNil {
		ifa = m.GetIfAddr(ia)
	}
	return
}

func (m *ifAddressMain) ForeachIfAddress(si vnet.Si, f func(ia IfAddr, i *IfAddress) error) error {
	i := m.headBySwIf[si]
	for i != IfAddrNil {
		ia := m.GetIfAddr(i)
		if err := f(i, ia); err != nil {
			return err
		}
		i = ia.next
	}
	return nil
}

func (m *Main) IfAddrForPrefix(p *net.IPNet, si vnet.Si) (ai IfAddr, exists bool) {
	k := makeIfAddrMapKey(p.IP, m.FibIndexForSi(si))
	ai, exists = m.addrMap[k]
	return
}

func (m *Main) AddDelInterfaceAddress(si vnet.Si, p *net.IPNet, isDel bool) (ai IfAddr, exists bool, err error) {
	var a *IfAddress
	k := makeIfAddrMapKey(p.IP, m.FibIndexForSi(si))
	if ai, exists = m.addrMap[k]; exists {
		a = m.GetIfAddr(ai)
	}

	if isDel {
		if a == nil {
			err = fmt.Errorf("%s: address %s not found", si.Name(m.v), p.String())
			return
		}
		if a.prev != IfAddrNil {
			prev := m.GetIfAddr(a.prev)
			prev.next = a.next
		} else {
			// Delete list head.
			m.headBySwIf[si] = IfAddrNil
		}
		if a.next != IfAddrNil {
			next := m.GetIfAddr(a.next)
			next.prev = a.prev
		}

		delete(m.addrMap, k)
		m.ifAddressPool.PutIndex(uint(ai))
		ai = IfAddrNil
	} else if a == nil {
		ai = IfAddr(m.ifAddressPool.GetIndex())
		a = m.GetIfAddr(ai)

		if m.addrMap == nil {
			m.addrMap = make(map[ifAddrMapKey]IfAddr)
		}
		m.addrMap[k] = ai
		a.Prefix = *p
		a.Si = si
		a.NeighborProbeAdj = AdjNil

		pi := m.headBySwIf[si]
		a.next = IfAddrNil
		a.prev = pi

		// Make previous head (P) point to added element (A) then added address becomes new head.
		if pi != IfAddrNil {
			p := m.GetIfAddr(pi)
			a.next = pi
			a.prev = IfAddrNil
			p.prev = ai
		}
		m.headBySwIf[si] = ai
	}
	return
}

// deletes ALL interface addresses
func (m *Main) InterfaceAddressReset(v *vnet.Vnet) {
	v.ForeachSwIf(func(si vnet.Si) {
		m.ForeachIfAddress(si, func(ia IfAddr, ifa *IfAddress) (err error) {
			p := ifa.Prefix
			m.AddDelInterfaceAddress(si, &p, true)
			return
		})
	})
}
