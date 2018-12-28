// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip4

import (
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/ip"

	"fmt"
	"net"
)

type Neighbor struct {
	m *Main

	Header Header

	LocalSi  vnet.Si
	FibIndex ip.FibIndex
	Weight   ip.NextHopWeight

	// Header payload (for example, GRE header).
	Payload []byte
}

func (n *Neighbor) NextHopWeight() ip.NextHopWeight     { return n.Weight }
func (n *Neighbor) NextHopFibIndex(m *Main) ip.FibIndex { return n.FibIndex }
func (n *Neighbor) FinalizeAdjacency(a *ip.Adjacency) {
	m := n.m
	if a.IsLocal() {
		ift := n.LocalSi.GetType(m.v)
		a.LookupNextIndex = ip.LookupNextRewrite
		ift.SwInterfaceSetRewrite(&a.Rewrite, n.LocalSi, &m.rewriteNode, vnet.IP4)
	}

	if !a.IsRewrite() {
		panic(fmt.Errorf("adjacency not rewrite %v", a.String(&m.Main)))
	}

	r := &a.Rewrite

	si := r.Si
	h := &n.Header

	// Give tunnel a src address if not specified or zero.
	if len(h.Src) == 0 || h.Src.Equal(net.IPv4zero) || h.Src.Equal(net.IPv6zero) {
		ifa := m.IfFirstAddress(si)
		if ifa != nil {
			h.Src = ifa.Prefix.IP
		}
	}

	// Fill in header length and checksum.
	h.Length = vnet.Uint16(SizeofHeader + len(n.Payload)).FromHost()
	h.Checksum = h.ComputeChecksum()

	b, l := r.Data(), r.Len()

	h.Write(b[l:])
	l += h.Len()

	copy(b[l:], n.Payload)
	l += uint(len(n.Payload))

	r.SetLen(l)
}

func (m *Main) AddDelRouteNeighbor(p *net.IPNet, n *Neighbor, fi ip.FibIndex, isDel bool) (err error) {
	n.m = m
	f := m.fibByIndex(fi, true)
	if adj, _, ok := f.GetReachable(p, n.LocalSi); ok {
		return f.addDelRouteNextHop(m, p, n.Header.Dst, n, adj, isDel)
	} else {
		err = fmt.Errorf("neighbor not reachable")
	}
	return
}
