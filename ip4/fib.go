// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip4

import (
	"fmt"
	"net"
	"sync"

	"github.com/platinasystems/elib"
	"github.com/platinasystems/elib/dep"
	"github.com/platinasystems/elib/parse"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/vnet/ip"
)

type Prefix struct {
	Address
	Len uint32
}

var masks = compute_masks()

func compute_masks() (m [33]Address) {
	for l := uint(0); l < uint(len(m)); l++ {
		mask := vnet.Uint32(0)
		if l > 0 {
			mask = (vnet.Uint32(1)<<l - 1) << (32 - l)
		}
		m[l].FromUint32(mask.FromHost())
	}
	return
}

func (a *Address) MaskLen() (l uint, ok bool) {
	m := ^a.AsUint32().ToHost()
	l = ^uint(0)
	if ok = (m+1)&m == 0; ok {
		l = 32
		if m != 0 {
			l -= 1 + elib.Word(m).MinLog2()
		}
	}
	return
}

func (v *Address) MaskedString(r vnet.MaskedStringer) (s string) {
	m := r.(*Address)
	s = v.String() + "/"
	if l, ok := m.MaskLen(); ok {
		s += fmt.Sprintf("%d", l)
	} else {
		s += fmt.Sprintf("%s", m.HexString())
	}
	return
}

func AddressMaskForLen(l uint) Address { return masks[l] }

func (p *Prefix) SetLen(l uint) { p.Len = uint32(l) }
func (a *Address) toPrefix() (p Prefix) {
	p.Address = *a
	return
}

func (p *Prefix) Matches(q *Prefix) bool {
	return p.Address.AsUint32()&p.Mask() == q.Address.AsUint32()&q.Mask()
}

func (p *Prefix) IsEqual(q *Prefix) bool { return p.Len == q.Len && p.Address.IsEqual(&q.Address) }

func (p *Prefix) LessThan(q *Prefix) bool {
	if cmp := p.Address.Diff(&q.Address); cmp != 0 {
		return cmp < 0
	}
	return p.Len < q.Len
}

// Add adds offset to prefix.  For example, 1.2.3.0/24 + 1 = 1.2.4.0/24.
func (p *Prefix) Add(offset uint) (q Prefix) {
	a := p.Address.AsUint32().ToHost()
	a += uint32(offset << (32 - p.Len))
	q = *p
	q.Address.FromUint32(vnet.Uint32(a).FromHost())
	return
}

// True if given destination matches prefix.
func (dst *Address) MatchesPrefix(p *Prefix) bool {
	return 0 == (dst.AsUint32()^p.Address.AsUint32())&p.Mask()
}

func (p Prefix) ToIPNet() (ipn net.IPNet) {
	mask := AddressMaskForLen(uint(p.Len))
	// an empty ipn has nil for Mask and IP so use append
	ipn.Mask = append(mask[:0:0], mask[:]...)
	ipn.IP = append(p.Address[:0:0], p.Address[:]...)
	return
}
func IPNetToV4Prefix(ipn net.IPNet) (p Prefix) {
	l, _ := ipn.Mask.Size()
	p.Len = uint32(l)
	// p.Address has a length already, so ok to just copy
	copy(p.Address[:], ipn.IP[:])
	return
}
func NetIPToV4Address(a net.IP) (a4 Address) {
	if a == nil {
		return
	}
	copy(a4[:], a.To4()[:])
	return
}
func (a Address) ToNetIP() (ip net.IP) {
	ip = append(a[:0:0], a[:]...)
	return
}

func (p *Prefix) ToIpPrefix() (i ip.Prefix) {
	copy(i.Address[:], p.Address[:])
	i.Len = p.Len
	return
}
func FromIp4Prefix(i *ip.Prefix) (p Prefix) {
	copy(p.Address[:], i.Address[:AddressBytes])
	p.Len = i.Len
	return
}

type RouteType uint8

const (
	// neighbor
	CONN RouteType = iota
	// has via next hop(s)
	VIA
	// glean
	GLEAN
	// interface addr of vnet recognized interface
	LOCAL
	// punts to Linux
	PUNT
)

func (t RouteType) String() string {
	switch t {
	case CONN:
		return "connected"
	case VIA:
		return "via_route"
	case GLEAN:
		return "glean"
	case LOCAL:
		return "local"
	case PUNT:
		return "punt"
	default:
		return "unspecified"

	}
}

type FibResult struct {
	Adj       ip.Adj
	Installed bool
	Prefix    net.IPNet
	Type      RouteType
	Nhs       ip.NextHopVec       // nexthops for Address
	usedBy    mapFibResultNextHop // used to track prefixes that uses Prefix.Address as its nexthop
}
type FibResultVec []FibResult
type MapFib [1 + 32]map[vnet.Uint32]FibResultVec

func (r *FibResult) String(m *Main) (s string) {
	n := " no nexthops\n"
	if len(r.Nhs) > 0 {
		n = " nexthops:\n"
		n += r.Nhs.ListNhs(&m.Main)
	}
	u := "\n"
	if len(r.usedBy) > 0 {
		u = r.usedBy.String(m)
	}
	s = fmt.Sprintf(" Prefix:%v Type:%v Installed:%v Adj:%v\n%v %v",
		r.Prefix.String(), r.Type, r.Installed, r.Adj, n, u)
	return
}

func (rs *FibResultVec) ForeachMatchingNhAddress(nha net.IP, fn func(r *FibResult, nh *ip.NextHop)) {
	for ri, r := range *rs {
		for i, nh := range r.Nhs {
			if nh.Address.Equal(nha) {
				fn(&r, &nh)
				r.Nhs[i] = nh
				(*rs)[ri] = r
			}
		}
	}
}

// returns first match
func (rs FibResultVec) GetByNhs(nhs ip.NextHopVec) (r FibResult, ri int, ok bool) {
	// nhs = nil are match also
	for i, _ := range rs {
		if rs[i].Nhs == nil && nhs == nil {
			r = rs[i]
			ri = i
			ok = true
			return
		}
		if rs[i].Nhs == nil || nhs == nil {
			continue
		}
		if rs[i].Nhs.Match(nhs) {
			r = rs[i]
			ri = i
			ok = true
			return
		}
	}
	return
}

// This returns 1st FibResult with a nh si that match; used to look up local and glean
func (rs FibResultVec) GetBySi(si vnet.Si) (r FibResult, ri int, ok bool) {
	for i, _ := range rs {
		for _, nh := range rs[i].Nhs {
			if nh.Si == si {
				r = rs[i]
				ri = i
				ok = true
				return
			}
		}
	}
	return
}

var cached struct {
	masks struct {
		once sync.Once
		val  interface{}
	}
}

// Cache of prefix length network masks: entry LEN has high LEN bits set.
// So, 10/8 has top 8 bits set.
func netMask(i uint) vnet.Uint32 {
	const nmasks = 33
	cached.masks.once.Do(func() {
		masks := make([]vnet.Uint32, nmasks)
		for i := range masks {
			m := ^vnet.Uint32(0)
			if i < 32 {
				m = vnet.Uint32(1<<uint(i)-1) << uint(32-i)
			}
			masks[i] = vnet.Uint32(m).FromHost()
		}
		cached.masks.val = masks
	})
	if i < nmasks {
		return cached.masks.val.([]vnet.Uint32)[i]
	}
	return 0
}

func (p *Prefix) Mask() vnet.Uint32          { return netMask(uint(p.Len)) }
func (p *Prefix) MaskAsAddress() (a Address) { a.FromUint32(p.Mask()); return }
func (p *Prefix) mapFibKey() vnet.Uint32     { return p.Address.AsUint32() & p.Mask() }
func (p *Prefix) ApplyMask() (q *Prefix) {
	pm := Prefix{}
	pm.Address.FromUint32(p.Address.AsUint32() & p.Mask())
	pm.Len = p.Len
	q = &pm
	return
}
func (a *Address) Mask(l uint) (v Address) {
	v.FromUint32(a.AsUint32() & netMask(l))
	return
}

func (m *MapFib) validateLen(l uint32) {
	if m[l] == nil {
		m[l] = make(map[vnet.Uint32]FibResultVec)
	}
}
func (m *MapFib) Set(p *Prefix, newAdj ip.Adj, nhs ip.NextHopVec, rt RouteType) (oldAdj ip.Adj, result *FibResult, ok bool) {
	l := p.Len
	m.validateLen(l)
	k := p.mapFibKey()
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	oldAdj = ip.AdjNil

	// Allow identical prefix/nhs to be added as new instead of just update adj
	if rs, ok = m[l][k]; ok && false {
		// if a result with nhs already exists, update adj and done
		if r, ri, ok = rs.GetByNhs(nhs); ok {
			oldAdj = r.Adj
			m[l][k][ri].Adj = newAdj
			result = &m[l][k][ri]
			return
		}
	}
	ok = true
	// r is a blank RouterFibResult, fill it in
	r.Adj = newAdj
	r.Prefix = p.ToIPNet()
	r.Nhs = nhs
	r.Type = rt
	// add r to end of RouterFibResultVec
	m[l][k] = append(m[l][k], r)
	result = &m[l][k][len(m[l][k])-1]
	return
}
func (m *MapFib) Unset(p *Prefix, nhs ip.NextHopVec) (oldAdj ip.Adj, ok bool) {
	dbgvnet.Adj.Logf("%v %v\n", p.String(), nhs)
	l := p.Len
	m.validateLen(l)
	k := p.mapFibKey()
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	if rs, ok = m[l][k]; ok {
		dbgvnet.Adj.Log("found rs")
		if r, ri, ok = rs.GetByNhs(nhs); ok {
			dbgvnet.Adj.Log("found nhs")
			oldAdj = r.Adj
			copy(rs[ri:], rs[ri+1:])
			rs[len(rs)-1] = FibResult{}
			rs = rs[:len(rs)-1]
			if len(rs) == 0 {
				delete(m[l], k)
			} else {
				m[l][k] = rs
			}
			dbgvnet.Adj.Log("done")
			return
		}
	}
	oldAdj = ip.AdjNil
	dbgvnet.Adj.Logf("DEBUG %v %v not found", p.String(), nhs)
	return
}
func (m *MapFib) UnsetFirst(p *Prefix) (oldAdj ip.Adj, ok bool) {
	l := p.Len
	m.validateLen(l)
	k := p.mapFibKey()
	var (
		rs FibResultVec
	)
	if rs, ok = m[l][p.mapFibKey()]; ok {
		if len(rs) > 0 {
			oldAdj = rs[0].Adj
			copy(rs[0:], rs[1:])
			rs = rs[:len(rs)-1]
			if len(rs) == 0 {
				delete(m[l], k)
			} else {
				m[l][k] = rs
			}
			return
		} else {
			ok = false
		}
	}
	oldAdj = ip.AdjNil
	return
}

func (m *MapFib) foreach(fn func(p *Prefix, r FibResult)) {
	var p Prefix
	for l := 32; l >= 0; l-- {
		//p.Len = uint32(l)
		for _, rs := range m[l] {
			for _, r := range rs {
				//p.Address.FromUint32(k)
				p = IPNetToV4Prefix(r.Prefix)
				fn(&p, r)
			}
		}
	}
}

func (m *MapFib) reset() {
	for i := range m {
		m[i] = nil
	}
}
func (m *MapFib) clean(fi ip.FibIndex) {
	for i := range m {
		for _, rs := range m[i] {
			for _, r := range rs {
				for dst, dstMap := range r.usedBy {
					for dp := range dstMap {
						if dp.i == fi {
							delete(dstMap, dp)
						}
					}
					if len(dstMap) == 0 {
						delete(r.usedBy, dst)
					}
				}
			}
		}
	}
}

type Fib struct {
	index ip.FibIndex

	// reachable and unreachable IP address from neighbor messages
	// these have 1 entry per prefix
	reachable, unreachable MapFib

	// routes and their nexthops
	// these can have more than 1 entry per prefix
	routeFib           MapFib //i.e. via nexthop
	local, punt, glean MapFib
}

//go:generate gentemplate -d Package=ip4 -id Fib -d VecType=FibVec -d Type=*Fib github.com/platinasystems/elib/vec.tmpl

// Total number of routes in FIB.
func (f *Fib) Len() (n uint) {
	for i := range f.reachable {
		n += uint(len(f.reachable[i]))
	}
	return
}

type IfAddrAddDelHook func(ia ip.IfAddr, isDel bool)

//go:generate gentemplate -id FibAddDelHook -d Package=ip4 -d DepsType=FibAddDelHookVec -d Type=FibAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id IfAddrAddDelHook -d Package=ip4 -d DepsType=IfAddrAddDelHookVec -d Type=IfAddrAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl

func (f *Fib) addFib(m *Main, r *FibResult) (installed bool) {
	if r == nil {
		panic(fmt.Errorf("addFib got nil FibResult pointer for argument"))
	}
	dbgvnet.Adj.Logf("%v\n%v", f.index.Name(&m.Main), r.String(m))
	p := IPNetToV4Prefix(r.Prefix)
	// check if there is already an adj installed with same prefix
	oldr, found := f.GetInstalled(r.Prefix)

	if !found { // install new
		m.callFibAddDelHooks(f.index, &p, r.Adj, false)
		installed = true
		r.Installed = installed
		dbgvnet.Adj.Logf("installed new\n")
		return
	}

	// something else had previously been installed
	switch r.Type {
	case CONN:
		// always install
	case VIA:
		if oldr.Type == CONN {
			// connected route is preferred, don't install
			// FIXME, as is will replace any previous VIA routes with same prefix
			return
		}
	case GLEAN:
		if oldr.Type == CONN || oldr.Type == VIA {
			// connected and via routes are preferred, don't install
			return
		}
	case LOCAL:
		if oldr.Type == CONN || oldr.Type == VIA || oldr.Type == GLEAN {
			return
		}
	case PUNT:
		// least preferred
		return
	default:
		dbgvnet.Adj.Logf("DEBUG unspecifed route type for prefix %v\n", r.Prefix)
		return
	}

	dbgvnet.Adj.Logf("call FibAddDelHook %v adj %v", p.String(), r.Adj)
	// AddDelHook replaced any previous adj with new on
	m.callFibAddDelHooks(f.index, &p, r.Adj, false)
	oldr.Installed = false
	installed = true
	r.Installed = installed
	dbgvnet.Adj.Log("replaced existing")
	return
}
func (f *Fib) delFib(m *Main, r *FibResult) {
	if r == nil {
		panic(fmt.Errorf("delFib got nil FibResult pointer for argument"))
	}
	dbgvnet.Adj.Logf("%v\n%v", f.index.Name(&m.Main), r.String(m))
	if !r.Installed {
		dbgvnet.Adj.Logf("prefix %v of type %v was not installed to begin with\n",
			r.Prefix, r.Type)
		return
	}

	// check if there is another less preferred route that should be installed in after
	// check before mark uninstall so we don't get prefix p back as the next preferred
	p := IPNetToV4Prefix(r.Prefix)
	var (
		newr  *FibResult
		found bool
	)
	checkAdjValid := true
	if newr, found = f.reachable.getFirstUninstalled(p, checkAdjValid); found {
	} else if newr, found = f.routeFib.getFirstUninstalled(p, checkAdjValid); found {
	} else if newr, found = f.glean.getFirstUninstalled(p, checkAdjValid); found {
	} else if newr, found = f.local.getFirstUninstalled(p, checkAdjValid); found {
	} else if newr, found = f.punt.getFirstUninstalled(p, checkAdjValid); found {
	}

	// uninstall old
	dbgvnet.Adj.Logf("call FibAddDelHook %v adj %v", p.String(), r.Adj)
	m.callFibAddDelHooks(f.index, &p, r.Adj, true)
	r.Installed = false
	if found {
		dbgvnet.Adj.Logf("call f.addFib to replace with %v\n", newr.String(m))
		// install replacement
		f.addFib(m, newr)
	}
}

type NextHopper interface {
	ip.AdjacencyFinalizer
	NextHopFibIndex(m *Main) ip.FibIndex
	NextHopWeight() ip.NextHopWeight
}

type nhUsage struct {
	referenceCount uint32
	nhr            NextHopper
}

type idst struct {
	a Address
	i ip.FibIndex
}

type ipre struct {
	p Prefix
	i ip.FibIndex
}

// idst is the destination or nh address and namespace
// ipre is the prefix that has idst as its nh
//type mapFibResultNextHop map[idst]map[ipre]NextHopper
type mapFibResultNextHop map[idst]map[ipre]nhUsage

func (mp mapFibResultNextHop) String(m *Main) string {
	s := ""
	for dst, dstMap := range mp {
		s += fmt.Sprintf("%v %v is used by:", dst.i.Name(&m.Main), dst.a.String())
		for dp, _ := range dstMap {
			s += fmt.Sprintf(" %v %v;", dp.i.Name(&m.Main), dp.p.String())
		}
		s += "\n"
	}
	return s
}

func (r *FibResult) addDelNextHop(m *Main, pf *Fib, p Prefix, a Address, nhr NextHopper, isDel bool) {
	id := idst{a: a, i: nhr.NextHopFibIndex(m)}
	ip := ipre{p: p, i: pf.index}
	nhu, found := r.usedBy[id][ip]

	if isDel {
		if found {
			nhu.referenceCount--
			r.usedBy[id][ip] = nhu
			if nhu.referenceCount == 0 {
				delete(r.usedBy[id], ip)
				if len(r.usedBy[id]) == 0 {
					delete(r.usedBy, id)
				}
			}
		} else {
			dbgvnet.Adj.Logf("delete, but %v is not used by %v\n", p.String(), a.String())
		}
	} else {
		if r.usedBy == nil {
			r.usedBy = make(map[idst]map[ipre]nhUsage)
		}
		if r.usedBy[id] == nil {
			r.usedBy[id] = make(map[ipre]nhUsage)
		}
		if found {
			nhu.referenceCount++
		} else {
			nhu = nhUsage{
				referenceCount: 1,
				nhr:            nhr,
			}
		}
		r.usedBy[id][ip] = nhu
	}
}

// Assume each 1 result per prefix in f.reachable; i.e. result vector has only 1 entry
// Make sense given only 1 rewrite per neighbor
func (f *Fib) setReachable(m *Main, p *Prefix, pf *Fib, via *Prefix, nhr NextHopper, isDel bool) {
	va, vl := via.Address.AsUint32(), via.Len
	a := via.Address
	if rs, ok := f.reachable[vl][va]; ok {
		if len(rs) > 0 {
			r := rs[0]
			r.addDelNextHop(m, pf, *p, a, nhr, isDel)
			f.reachable[vl][va][0] = r
			dbgvnet.Adj.Logf("%v %v prefix %v via %v nha %v adj %v, new result\n%v",
				vnet.IsDel(isDel), f.index.Name(&m.Main), p.String(), via.String(), a, r.Adj, r.String(m))
			return
		}
	}
	dbgvnet.Adj.Logf("DEBUG did not find %v in reachable\n", via.String())
}

// delReachableVia will traverse the map and remove x's address from all the prefixes that uses it as its nexthop address, and add them to unreachable
func (r *FibResult) delReachableVia(m *Main, f *Fib) {
	// x is the mapFibResult from reachable (i.e. x is the reachable MapFib)
	// This is also called from addDelUnreachable (i.e. x is the unreachable MapFib) when doing recursive delete; not sure what the purpose is...
	dbgvnet.Adj.Logf("adj %v IsMpAdj %v mapFibResult before:\n%v\n", r.Adj, m.IsMpAdj(r.Adj), r.String(m))

	for dst, dstMap := range r.usedBy {
		if r.usedBy[dst] == nil {
			continue
		}
		// dstMap is map of prefixes that uses dst as its nh
		// For each of them, remove nh from prefix and add to unreachable
		for dp, nhu := range dstMap {
			g := m.fibByIndex(dp.i, false)
			const isDel = true
			dbgvnet.Adj.Logf("call addDelRouteNextHop prefix %v delete nh %v from delReachableVia\n",
				dp.p.String(), dst.a)
			// use addDelRouteNextHop to update routeFib table now that dst.a is unreachable
			g.addDelRouteNextHop(m, &dp.p, dst.a, nhu.nhr, r.Adj, isDel)
			// Prefix is now unreachable, add to unreachable, no recurse
			f.addDelUnreachable(m, &dp.p, g, dst.a, nhu.nhr, !isDel, false)
		}
		// Verify that r.usedBy[id] is not already delete (should have been from above); and if not, delete it
		if r.usedBy[dst] != nil {
			// don't expect to be here
			dbgvnet.Adj.Logf("DEBUG %v dst addr %v had to do delete leftover %v\n", f.index.Name(&m.Main), dst.a.String(), r.usedBy[dst])
			delete(r.usedBy, dst)
		}
	}

	dbgvnet.Adj.Logf("adj %v IsMpAdj %v mapFibResult after:\n%v\n", r.Adj, m.IsMpAdj(r.Adj), r.String(m))
}

func (ur *FibResult) makeReachable(m *Main, f *Fib, p *Prefix, adj ip.Adj) {
	// ur is a mapFibResult from unreachable that we will move to reachable here
	for dst, dstMap := range ur.usedBy {
		// make reachable only if exact match; let Linux add nhs explicity instead
		if dst.a == p.Address {
			// delete the entry from ur's map
			delete(ur.usedBy, dst)
			// dstMap is map of prefixes that has dst as their nh but was not acctually added to the fib table because nh was unreachable
			// For each that match prefix p, actually add nh (i.e. dst.a) to prefix via addDelRouteNextHop which makes nh reachable
			for dp, nhu := range dstMap {
				g := m.fibByIndex(dp.i, false)
				const isDel = false
				dbgvnet.Adj.Logf("call addDelRouteNextHop prefix %v add nh %v from makeReachable\n",
					dp.p.String(), dst.a)
				g.addDelRouteNextHop(m, &dp.p, dst.a, nhu.nhr, adj, isDel)
			}
		}
	}
}

func (x *FibResult) addUnreachableVia(m *Main, f *Fib, p *Prefix) {
	// don't know how this is used in conjunction with recursive addDelUnreachable
	// seems like if there is a match, it would delete the entry, but then just add it back?
	for dst, dstMap := range x.usedBy {
		if dst.a.MatchesPrefix(p) {
			delete(x.usedBy, dst)
			for dp, nhu := range dstMap {
				g := m.fibByIndex(dp.i, false)
				const isDel = false
				f.addDelUnreachable(m, &dp.p, g, dst.a, nhu.nhr, isDel, false)
			}
		}
	}
}

func (f *Fib) addDelReachable(m *Main, p *Prefix, a ip.Adj, isDel bool) {
	var (
		rs FibResultVec
		r  *FibResult
		ok bool
	)
	f.reachable.validateLen(p.Len)
	// should only ever have 1 entry in rs reachable; a prefix cannot have 2 simultaneous neighbors
	if rs, ok = f.reachable[p.Len][p.mapFibKey()]; ok {
		if len(rs) > 0 {
			r = &f.reachable[p.Len][p.mapFibKey()][0]
		} else {
			ok = false
		}
	}
	if p.Len < 32 || m.IsMpAdj(a) {
		dbgvnet.Adj.Logf("DEBUG expecting /32 mask and neighbor rewrite, got /%v and via nextHop=%v instead\n",
			p.Len, m.IsMpAdj(a))
	}

	if isDel {
		dbgvnet.Adj.Logf("delete: %v %v adj %v delReachableVia\n%v",
			f.index.Name(&m.Main), p.String(), a, r.String(m))
		if !ok {
			dbgvnet.Adj.Logf("DEBUG %v not found in reachable\n", p.String())
		}
		r.delReachableVia(m, f)
	} else {
		//if ur, _, ok := f.unreachable.Lookup(p.Address); ok {
		if ur, ok := f.unreachable.getFirstUninstalled(*p, false); ok {
			dbgvnet.Adj.Logf("add: %v %v adj %v makeReachable\n", f.index.Name(&m.Main), p.String(), a)
			ur.makeReachable(m, f, p, a)
		}
	}
	dbgvnet.Adj.Logf("%v: %v reachable nha %v used by prefix %v new:\n%v", vnet.IsDel(isDel), f.index.Name(&m.Main), a.String(), p.String(), r.String(m))
}

func (f *Fib) addDelUnreachable(m *Main, p *Prefix, pf *Fib, a Address, r NextHopper, isDel bool, recurse bool) (err error) {
	// a is the next hop address for p that cannot be reached
	// pf is the fib that p belongs to; f is the fib that a belongs to
	// in general pf and f are the same fib, i.e. in same namespace
	np := Prefix{Address: a, Len: 32}
	var (
		nr *FibResult
		ok bool
	)
	// check if prefix already in unreachable
	if nr, ok = f.unreachable.getFirstUninstalled(np, false); !ok {
		// if not then Set
		_, nr, ok = f.unreachable.Set(&np, ip.AdjNil, ip.NextHopVec{}, CONN)
		dbgvnet.Adj.Logf("set unreachable\n")
	}
	if !isDel && recurse {
		nr.addUnreachableVia(m, f, p)
	}
	dbgvnet.Adj.Log("call addDelNextHop")
	nr.addDelNextHop(m, pf, *p, a, r, isDel)
	dbgvnet.Adj.Logf("%v: %v unreachable nha %v used by prefix %v new:\n%v", vnet.IsDel(isDel), f.index.Name(&m.Main), a.String(), p.String(), nr.String(m))
	return
}

func (f *Fib) GetInstalled(ipn net.IPNet) (result *FibResult, ok bool) {
	p := IPNetToV4Prefix(ipn)
	// check reachable first
	if result, ok = f.reachable.getInstalled(p); ok {
		return
	}
	// check via Routes
	if result, ok = f.routeFib.getInstalled(p); ok {
		return
	}
	// check glean
	if result, ok = f.glean.getInstalled(p); ok {
		return
	}
	// check local
	if result, ok = f.local.getInstalled(p); ok {
		return
	}
	// check punt
	if result, ok = f.punt.getInstalled(p); ok {
		return
	}
	return
}

func (x *MapFib) getInstalled(p Prefix) (result *FibResult, ok bool) {
	var (
		rs FibResultVec
	)
	x.validateLen(p.Len)
	if rs, ok = x[p.Len][p.mapFibKey()]; ok {
		// only 1 should be installed, and should be the 1st one
		// for debug, check them all
		for i, r := range rs {
			if r.Installed {
				result = &x[p.Len][p.mapFibKey()][i]
				if i != 0 {
					dbgvnet.Adj.Logf("DEBUG installed is the %vth entry in vector instead of 0th\n", i)
				}
				return
			}
		}
	}
	ok = false
	return
}
func (x *MapFib) getFirstUninstalled(p Prefix, checkAdjValid bool) (result *FibResult, ok bool) {
	var (
		rs FibResultVec
	)
	x.validateLen(p.Len)
	if rs, ok = x[p.Len][p.mapFibKey()]; ok {
		// only 1 should be installed, and should be the 1st one
		// for debug, check them all
		for i, r := range rs {
			if !r.Installed && !(checkAdjValid && !(r.Adj != ip.AdjNil && r.Adj != ip.AdjMiss)) {
				result = &x[p.Len][p.mapFibKey()][i]
				return
			}
		}
	}
	ok = false
	return
}

func (f *Fib) GetReachable(p *Prefix, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	f.reachable.validateLen(p.Len)
	if rs, ok = f.reachable[p.Len][p.mapFibKey()]; ok {
		if r, ri, ok = rs.GetBySi(si); ok {
			a = r.Adj
			result = &f.reachable[p.Len][p.mapFibKey()][ri]
		}
	}
	return
}
func (f *Fib) GetUnreachable(p *Prefix) (a ip.Adj, ok bool) {
	// unreachables are never installed
	if r, found := f.unreachable.getFirstUninstalled(*p, false); found {
		ok = true
		a = r.Adj
	}
	return
}
func (f *Fib) GetFib(p *Prefix, nhs ip.NextHopVec) (a ip.Adj, result *FibResult, ok bool) {
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	f.routeFib.validateLen(p.Len)
	if rs, ok = f.routeFib[p.Len][p.mapFibKey()]; ok {
		if r, ri, ok = rs.GetByNhs(nhs); ok {
			a = r.Adj
			result = &f.routeFib[p.Len][p.mapFibKey()][ri]
		}
	}
	return
}
func (f *Fib) GetLocal(p *Prefix, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	f.local.validateLen(p.Len)
	if rs, ok = f.local[p.Len][p.mapFibKey()]; ok {
		if r, ri, ok = rs.GetBySi(si); ok {
			a = r.Adj
			result = &f.local[p.Len][p.mapFibKey()][ri]
		}
	}
	return
}
func (f *Fib) GetGlean(p *Prefix, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	f.glean.validateLen(p.Len)
	if rs, ok = f.glean[p.Len][p.mapFibKey()]; ok {
		dbgvnet.Adj.Log("found rs")
		if r, ri, ok = rs.GetBySi(si); ok {
			a = r.Adj
			dbgvnet.Adj.Log("found result")
			result = &f.glean[p.Len][p.mapFibKey()][ri]
		}
	}
	dbgvnet.Adj.Log("not found ok", ok)
	return
}

// adj is always AdjPunt for punt; just return ok if found
func (f *Fib) GetPunt(p *Prefix) (ok bool) {
	var (
		rs FibResultVec
	)
	if rs, ok = f.punt[p.Len][p.mapFibKey()]; ok {
		if len(rs) > 0 {
			ok = true
		}
	}
	return
}

func (m *Main) setInterfaceAdjacency(a *ip.Adjacency, si vnet.Si) {
	sw := m.Vnet.SwIf(si)
	hw := m.Vnet.SupHwIf(sw)
	var h vnet.HwInterfacer
	if hw != nil {
		h = m.Vnet.HwIfer(hw.Hi())
	}

	next := ip.LookupNextRewrite
	noder := &m.rewriteNode
	packetType := vnet.IP4

	if _, ok := h.(vnet.Arper); h == nil || ok {
		next = ip.LookupNextGlean
		noder = &m.arpNode
		packetType = vnet.ARP
	}

	a.LookupNextIndex = next
	if h != nil {
		m.Vnet.SetRewrite(&a.Rewrite, si, noder, packetType, nil /* dstAdr meaning broadcast */)
	}
}

type fibMain struct {
	fibs FibVec
	// Hooks to call on set/unset.
	fibAddDelHooks      FibAddDelHookVec
	ifRouteAdjIndexBySi map[vnet.Si]ip.Adj
}

type FibAddDelHook func(i ip.FibIndex, p *Prefix, r ip.Adj, isDel bool)

func (m *fibMain) RegisterFibAddDelHook(f FibAddDelHook, dep ...*dep.Dep) {
	m.fibAddDelHooks.Add(f, dep...)
}

func (m *fibMain) callFibAddDelHooks(fi ip.FibIndex, p *Prefix, r ip.Adj, isDel bool) {
	for i := range m.fibAddDelHooks.hooks {
		m.fibAddDelHooks.Get(i)(fi, p, r, isDel)
	}
}

func (m *Main) fibByIndex(i ip.FibIndex, create bool) (f *Fib) {
	m.fibs.Validate(uint(i))
	if create && m.fibs[i] == nil {
		m.fibs[i] = &Fib{index: i}
	}
	f = m.fibs[i]
	return
}

func (m *Main) fibById(id ip.FibId, create bool) *Fib {
	var (
		i  ip.FibIndex
		ok bool
	)
	if i, ok = m.FibIndexForId(id); !ok {
		i = ip.FibIndex(m.fibs.Len())
	}
	return m.fibByIndex(i, create)
}

func (m *Main) fibBySi(si vnet.Si) *Fib {
	i := m.FibIndexForSi(si)
	return m.fibByIndex(i, true)
}

func (m *Main) validateDefaultFibForSi(si vnet.Si) {
	i := m.ValidateFibIndexForSi(si)
	m.fibByIndex(i, true)
}

func (m *Main) getRoute(p *ip.Prefix, si vnet.Si) (ai ip.Adj, as []ip.Adjacency, ok bool) {
	f := m.fibBySi(si)
	q := FromIp4Prefix(p)
	if r, found := f.GetInstalled(q.ToIPNet()); found {
		ok = true
		ai = r.Adj
	}
	if ok {
		as = m.GetAdj(ai)
	}
	return
}

func (m *Main) getReachable(p *ip.Prefix, si vnet.Si) (ai ip.Adj, as []ip.Adjacency, ok bool) {
	f := m.fibBySi(si)
	q := FromIp4Prefix(p)
	ai, _, ok = f.GetReachable(&q, si)
	if ok {
		as = m.GetAdj(ai)
	}
	return
}

func (m *Main) getRouteFibIndex(p *ip.Prefix, fi ip.FibIndex) (ai ip.Adj, ok bool) {
	f := m.fibByIndex(fi, false)
	q := FromIp4Prefix(p)
	if r, found := f.GetInstalled(q.ToIPNet()); found {
		ok = true
		ai = r.Adj
	}
	return
}

// Used by neighbor message to add/del route, e.g. from succesfull arp, or install AdjPunt
// Tied to AddDelRoute() and called directly from ethernet/neighbor.go and a few other places
// The adjacency is created/updated elsewhere and the index passed in
func (m *Main) addDelRoute(p *ip.Prefix, fi ip.FibIndex, adj ip.Adj, isDel bool) (oldAdj ip.Adj, err error) {
	createFib := !isDel
	f := m.fibByIndex(fi, createFib)
	q := FromIp4Prefix(p)
	var (
		r         *FibResult
		ok, found bool
		nhs       ip.NextHopVec
		nh        ip.NextHop
	)

	dbgvnet.Adj.Logf("%v %v adj %v\n", vnet.IsDel(isDel), q.Address.String(), adj)

	if connected, si := adj.IsConnectedRoute(&m.Main); connected { // arped neighbor
		// make a new NextHopVec with 1 next hop
		nh = ip.NextHop{Si: si}
		nhs = append(nhs, nh)
		oldAdj, r, found = f.GetReachable(&q, si)
		if isDel && found {
			f.delFib(m, r)
			f.addDelReachable(m, &q, r.Adj, isDel)
			oldAdj, ok = f.reachable.Unset(&q, nhs)
			// neighbor.go takes care of DelAdj so no need to do so here on delete
		}
		if !isDel {
			if found {
				if oldAdj == adj {
					// re-add the fib to hardware as rewrite likely has been updated
					dbgvnet.Adj.Logf("DEBUG update rewrite of adj %v\n", adj)
					f.addFib(m, r)
					return
				} else {
					// can only have 1 neighbor per prefix/si, so unset any previous
					// should not hit this as ethernet/neighbor.go does a GetReachable first to obtain adj
					dbgvnet.Adj.Logf("DEBUG DEBUG delete previous adj %v before adding new adj %v\n", oldAdj, adj)
					oldAdj, ok = f.reachable.Unset(&q, nhs)
				}
			}
			// create a new reachable entry
			// Set before addFib before addDelReachable in that order
			_, r, _ := f.reachable.Set(&q, adj, nhs, CONN)
			f.addFib(m, r)
			f.addDelReachable(m, &q, adj, isDel)
			ok = true
		}
		if !ok {
			dbgvnet.Adj.Logf("DEBUG %v %v connected route not ok\n", vnet.IsDel(isDel), q.String())
			err = fmt.Errorf("%v %v connected route not ok\n", vnet.IsDel(isDel), q.String())
		}
		return
	}
	if adj == ip.AdjPunt {
		r, found = f.punt.getInstalled(q)
		if isDel && found {
			f.delFib(m, r)
			oldAdj, ok = f.punt.Unset(&q, ip.NextHopVec{})
		}
		if !isDel {
			oldAdj, r, ok = f.punt.Set(&q, adj, ip.NextHopVec{}, PUNT)
			f.addFib(m, r)
		}
		if !ok {
			dbgvnet.Adj.Logf("DEBUG %v %v punt not ok\n", vnet.IsDel(isDel), q.String())
			err = fmt.Errorf("%v %v punt not ok\n", vnet.IsDel(isDel), q.String())
		}
		return
	}

	if adj.IsGlean(&m.Main) {
		dbgvnet.Adj.Logf("DEBUG should not be used for glean adj %v\n", adj)
	}
	if adj.IsLocal(&m.Main) {
		dbgvnet.Adj.Logf("DEBUG should not be used for local adj %v\n", adj)
	}
	if adj.IsViaRoute(&m.Main) {
		dbgvnet.Adj.Logf("DEBUG should not be used for nexthop adj %v\n", adj)
	}

	err = fmt.Errorf("%v %v adj %v not connected route or punt\n", vnet.IsDel(isDel), q.String(), adj)
	return
}

type NextHop struct {
	Address Address
	Si      vnet.Si
	Weight  ip.NextHopWeight
}

func (n *NextHop) NextHopWeight() ip.NextHopWeight     { return n.Weight }
func (n *NextHop) NextHopFibIndex(m *Main) ip.FibIndex { return m.FibIndexForSi(n.Si) }
func (n *NextHop) FinalizeAdjacency(a *ip.Adjacency)   {}

func (x *NextHop) ParseWithArgs(in *parse.Input, args *parse.Args) {
	v := args.Get().(*vnet.Vnet)
	switch {
	case in.Parse("%v %v", &x.Si, v, &x.Address):
	default:
		panic(fmt.Errorf("expecting INTERFACE ADDRESS; got %s", in))
	}
	x.Weight = 1
	in.Parse("weight %d", &x.Weight)
}

type prefixError struct {
	s string
	p Prefix
}

func (e *prefixError) Error() string { return e.s + ": " + e.p.String() }

func (m *Main) updateAdjAndUsedBy(f *Fib, p *Prefix, nhs *ip.NextHopVec, isDel bool) {
	dbgvnet.Adj.Logf("%v %v %v", f.index.Name(&m.Main), p.String(), vnet.IsDel(isDel))
	for nhi, nh := range *nhs {
		var (
			adj   ip.Adj
			found bool
		)
		nhp := Prefix{
			Address: NetIPToV4Address(nh.Address),
			Len:     32,
		}
		nhr := NextHop{
			Address: NetIPToV4Address(nh.Address),
			Si:      nh.Si,
			Weight:  nh.Weight,
		}
		nhf := m.fibByIndex(nh.NextHopFibIndex(&m.Main), true) // fib/namesapce that nh.Si belongs to

		adj, _, found = nhf.GetReachable(&nhp, nh.Si) // adj = 0(AdjMiss) if not found

		// if add, need to update the adj as it will not have been filled in yet
		if !isDel {
			(*nhs)[nhi].Adj = adj
		}

		if found {
			// if nh is reachable
			// update reachable map by adding p to nhp's usedBy map
			nhf.setReachable(m, p, f, &nhp, &nhr, isDel)
		} else {
			// if nh is not reachable
			// update unreachable map, don't recurse, adding p to nhp's usedBy map
			f.addDelUnreachable(m, p, f, nhp.Address, &nhr, isDel, false)
		}
	}
}

// NextHops comes as a vector
func (m *Main) AddDelRouteNextHops(fibIndex ip.FibIndex, p *Prefix, nhs ip.NextHopVec, isDel bool, isReplace bool) (err error) {
	f := m.fibByIndex(fibIndex, true)
	dbgvnet.Adj.Logf("%v %v %v isReplace %v, nhs: \n%v\n",
		vnet.IsDel(isDel), fibIndex.Name(&m.Main), p.String(), isReplace, nhs.ListNhs(&m.Main))
	var (
		r      *FibResult
		ok     bool
		oldAdj ip.Adj
	)
	if isDel {
		if oldAdj, r, ok = f.GetFib(p, nhs); ok {
			f.delFib(m, r) // remove from fib
		} else {
			dbgvnet.Adj.Logf("DEBUG delete, cannot find %v %v\n", f.index.Name(&m.Main), p.String())
			err = fmt.Errorf("AddDelRouteNextHops delete, cannot find %v %v\n", f.index.Name(&m.Main), p.String())
		}
	}
	if isReplace {
		if r, ok = f.routeFib.getInstalled(*p); ok {
			f.delFib(m, r)
		} else if r, ok = f.routeFib.getFirstUninstalled(*p, false); ok {
			// no need to remove from fib since not installed
		}
	}
	if (isDel || isReplace) && ok {
		// make a copy of contents of r.Nhs
		nhs_old := r.Nhs
		// update nhs_old to update usesBy map of nexthops that used p
		m.updateAdjAndUsedBy(f, p, &nhs_old, true)
		oldAdj, ok = f.routeFib.Unset(p, r.Nhs)
		m.DelNextHopsAdj(oldAdj)
	}
	if !isDel {
		// update the adj and usedBy map for nhs
		m.updateAdjAndUsedBy(f, p, &nhs, isDel)
		if len(nhs) == 0 {
			dbgvnet.Adj.Logf("DEBUG ignore add via route %v with no next hops\n", p.String())
		}
		if newAdj, ok := m.AddNextHopsAdj(nhs); ok {
			oldAdj, r, ok = f.routeFib.Set(p, newAdj, nhs, VIA)
			f.routeFib.validateLen(p.Len)
			if len(f.routeFib[p.Len][p.mapFibKey()]) == 1 && r.Adj != ip.AdjNil {
				// first via route for prefix p; try installing it
				f.addFib(m, r) // add
			}
		}
	}
	return
}

// modified for legacy netlink and ip/cli use, where nexthop were added 1 at a time instead of a vector at at time
func (m *Main) AddDelRouteNextHop(p *Prefix, nh *NextHop, isDel bool, isReplace bool) (err error) {
	var nhs ip.NextHopVec
	new_nh := ip.NextHop{
		Address: nh.Address.ToNetIP(),
		Si:      nh.Si,
	}
	new_nh.Weight = nh.Weight
	f := m.fibBySi(nh.Si)
	nhs = append(nhs, new_nh)
	return m.AddDelRouteNextHops(f.index, p, nhs, isDel, isReplace)
}

// Mark a nha as reachable(add) or unreachable(del) for ALL routeFibResults in p that has nha as a nexthop
// Update each matching routeFibResult with a newAdj
// Note this doesn't actually remove the nexthop from Prefix; that's done via AddDelRouteNextHops when Linux explicitly deletes or replaces a via route
func (f *Fib) addDelRouteNextHop(m *Main, p *Prefix, nha Address, nhr NextHopper, nhAdj ip.Adj, isDel bool) (err error) {
	var (
		oldAdj, newAdj ip.Adj
		nhp            Prefix
		ok             bool
		rs             FibResultVec
	)
	var nhIP net.IP
	nhIP = nha.ToNetIP()
	nhp = Prefix{Address: nha, Len: 32}

	nhf := m.fibByIndex(nhr.NextHopFibIndex(m), true)

	f.routeFib.validateLen(p.Len)
	if rs, ok = f.routeFib[p.Len][p.mapFibKey()]; !ok {
		dbgvnet.Adj.Logf("DEBUG %v %v not found\n", f.index.Name(&m.Main), p.String())
	}
	newAdj = ip.AdjNil

	// update rs with nhAdj; either a valid nhAdj or 0(AdjMiss) depending on add or delete
	rs.ForeachMatchingNhAddress(nhIP, func(r *FibResult, nh *ip.NextHop) {
		if isDel {
			nh.Adj = ip.AdjMiss
		} else {
			nh.Adj = nhAdj
		}
	})
	rs.ForeachMatchingNhAddress(nhIP, func(r *FibResult, nh *ip.NextHop) {
		oldAdj = r.Adj
		if newAdj, ok = m.AddDelNextHop(oldAdj, nhAdj, nhr.NextHopWeight(), nhr, isDel); !ok {
			dbgvnet.Adj.Logf("DEBUG AddDelNextHop %v failed oldAdj %v nhAdj %v\n",
				vnet.IsDel(isDel), oldAdj, newAdj)
			return
		}
		if newAdj == ip.AdjNil {
			f.delFib(m, r)
			r.Adj = newAdj
		} else if oldAdj != newAdj {
			r.Adj = newAdj
			f.addFib(m, r)
		}
		nhf.setReachable(m, p, f, &nhp, nhr, isDel) // updates map of what prefix uses nha
	})
	return
}

func (m *Main) addDelInterfaceAddressRoutes(ia ip.IfAddr, isDel bool) {
	ifa := m.GetIfAddr(ia)
	si := ifa.Si
	sw := m.Vnet.SwIf(si)
	hw := m.Vnet.SupHwIf(sw)
	f := m.fibBySi(si)
	p := FromIp4Prefix(&ifa.Prefix)

	var (
		nhs    ip.NextHopVec
		r      *FibResult
		ok     bool
		oldAdj ip.Adj
	)
	// make a NextHopVec with 1 nh with Si=si and empty everthing else for local and glean
	nh := ip.NextHop{Si: si}
	nhs = append(nhs, nh)

	// Add interface's prefix as route tied to glean adjacency (arp for Ethernet).
	// Suppose interface has address 1.1.1.1/8; here we add 1.0.0.0/8 tied to glean adjacency.
	if p.Len < 32 {
		addDelAdj := ip.AdjNil
		q := p.ApplyMask()
		if !isDel {
			ai, as := m.NewAdj(1)
			m.setInterfaceAdjacency(&as[0], si)
			m.CallAdjAddHooks(ai)
			addDelAdj = ai
			if _, r, ok = f.glean.Set(q, ai, nhs, GLEAN); ok {
				f.addFib(m, r)
				dbgvnet.Adj.Logf("set glean %v adj %v done\n", q.String(), ai)
			} else {
				dbgvnet.Adj.Logf("DEBUG set glean %v adj %v failed\n", q.String(), ai)
			}
		}
		if isDel {
			if _, r, ok = f.GetGlean(q, si); ok {
				f.delFib(m, r)
			}
			if oldAdj, ok = f.glean.Unset(q, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset glean %v done\n", q.String())
			} else {
				dbgvnet.Adj.Logf("DEBUG unset glean %v failed\n", q.String())
			}
		}
		ifa.NeighborProbeAdj = addDelAdj
	}

	// Add 1.1.1.1/32 as a local address.
	{
		qq := Prefix{Address: p.Address, Len: 32}
		q := &qq
		if !isDel {
			ai, as := m.NewAdj(1)
			as[0].LookupNextIndex = ip.LookupNextLocal
			as[0].Index = uint32(si)
			as[0].Si = si
			if hw != nil {
				as[0].SetMaxPacketSize(hw)
			}
			dbgvnet.Adj.Logf("%v local made new adj %v\n", q.String(), ai)
			m.CallAdjAddHooks(ai)
			dbgvnet.Adj.Logf("%v local added adj %v\n", q.String(), ai)
			if _, r, ok = f.local.Set(q, ai, nhs, LOCAL); ok {
				f.addFib(m, r)
				dbgvnet.Adj.Logf("set local %v adj %v done\n", q.String(), ai)
			} else {
				dbgvnet.Adj.Logf("DEBUG set local %v adj %v failed\n", q.String(), ai)
			}
		}
		if isDel {
			if _, r, ok = f.GetLocal(q, si); ok {
				f.delFib(m, r)
			}
			if oldAdj, ok = f.local.Unset(q, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset local %v done\n", q.String())
			} else {
				dbgvnet.Adj.Logf("DEBUG unset local %v failed\n", q.String())
			}
		}
	}
}

// In Linux, local route is added to table local when an address is assigned to interface.
// It stays there regardless of whether interface is admin up or down
// Glean route, on the other hand, is added to table main when an interface is admin up, and removed when admin down
// There will be explicit fdb messages to add or delete these routes, so no need to maintain state in vnet
// You can also have multiple local and glean per interface
func (m *Main) AddDelInterfaceAddressRoute(ipn net.IPNet, si vnet.Si, rt RouteType, isDel bool) {
	var (
		nhs        ip.NextHopVec
		r          *FibResult
		ok, exists bool
		oldAdj     ip.Adj
		ia         ip.IfAddr
		q          *Prefix
		qq         ip.Prefix
	)
	sw := m.Vnet.SwIf(si)
	hw := m.Vnet.SupHwIf(sw)
	f := m.fibBySi(si)
	p := IPNetToV4Prefix(ipn)
	q = &p
	dbgvnet.Adj.Logf("%v %v %v %v\n", vnet.IsDel(isDel), rt, q.String(), si.Name(m.v))
	if rt == GLEAN {
		// For glean, need to find the IfAddress based on si and ipn
		m.Main.ForeachIfAddress(si, func(iadd ip.IfAddr, i *ip.IfAddress) (err error) {
			ipp := i.Prefix
			pp := FromIp4Prefix(&ipp)
			pp.Len = q.Len
			p := pp.ApplyMask()
			if q.Address.IsEqual(&p.Address) {
				qq = ipp
				ia = iadd
				exists = true
			}
			return
		})
	} else {
		// For local, IfAddress is just p
		qq = q.ToIpPrefix()
		ia, exists = m.Main.IfAddrForPrefix(&qq, si)
	}

	dbgvnet.Adj.Log("exists = ", exists)
	// make a NextHopVec with 1 nh with Si=si and empty everthing else for local and glean
	nh := ip.NextHop{Si: si}
	nhs = append(nhs, nh)

	if rt == GLEAN {
		addDelAdj := ip.AdjNil
		if !isDel {
			ai, as := m.NewAdj(1)
			dbgvnet.Adj.Log("set adjacency")
			m.setInterfaceAdjacency(&as[0], si)
			dbgvnet.Adj.Logf("call CallAdjAddHooks(%v)", ai)
			m.CallAdjAddHooks(ai)
			addDelAdj = ai
			dbgvnet.Adj.Log("call Set")
			if oldAdj, r, ok = f.glean.Set(q, ai, nhs, GLEAN); ok {
				dbgvnet.Adj.Log("call addFib")
				f.addFib(m, r)
				dbgvnet.Adj.Logf("set %v glean %v adj %v done\n", f.index.Name(&m.Main), q.String(), ai)
				if oldAdj != ip.AdjNil {
					dbgvnet.Adj.Logf("DEBUG previous %v glean %v adj %v exist and replace with new adj %v\n",
						f.index.Name(&m.Main), q.String(), oldAdj, ai)
					if !m.IsAdjFree(oldAdj) {
						m.DelAdj(oldAdj)
					}
				}
			} else {
				dbgvnet.Adj.Logf("DEBUG %v set glean %v adj %v failed\n", f.index.Name(&m.Main), q.String(), ai)
			}
		}
		if exists {
			ifa := m.GetIfAddr(ia)
			ifa.NeighborProbeAdj = addDelAdj
		} else {
			// set at IfAddress creation
		}
		if isDel {
			dbgvnet.Adj.Log("get Glean")
			if _, r, ok = f.GetGlean(q, si); !ok {
				dbgvnet.Adj.Logf("DEBUG unset %v glean %v not found\n", f.index.Name(&m.Main), q.String())
				return
			}
			dbgvnet.Adj.Log("call delFib")
			f.delFib(m, r)
			if oldAdj, ok = f.glean.Unset(q, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v glean %v done\n", f.index.Name(&m.Main), q.String())
			}
		}
	}

	if rt == LOCAL {
		if !isDel {
			ai, as := m.NewAdj(1)
			as[0].LookupNextIndex = ip.LookupNextLocal
			as[0].Si = si
			if hw != nil {
				as[0].SetMaxPacketSize(hw)
			}
			dbgvnet.Adj.Logf("%v local made new adj %v\n", q.String(), ai)
			m.CallAdjAddHooks(ai)
			dbgvnet.Adj.Logf("%v local added adj %v\n", q.String(), ai)
			if _, r, ok = f.local.Set(q, ai, nhs, LOCAL); ok {
				f.addFib(m, r)
				dbgvnet.Adj.Logf("set %v local %v adj %v done\n", f.index.Name(&m.Main), q.String(), ai)
			} else {
				dbgvnet.Adj.Logf("DEBUG set %v local %v adj %v failed\n", f.index.Name(&m.Main), q.String(), ai)
			}
		}
		if isDel {
			if _, r, ok = f.GetLocal(q, si); !ok {
				dbgvnet.Adj.Logf("DEBUG unset %v local %v failed\n", f.index.Name(&m.Main), q.String())
				return
			}
			f.delFib(m, r)
			if oldAdj, ok = f.local.Unset(q, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v local %v done\n", f.index.Name(&m.Main), q.String())
			}
		}
	}
}

func (m *Main) AddDelInterfaceAddress(si vnet.Si, addr *Prefix, isDel bool) (err error) {
	if !isDel {
		err = m.ForeachIfAddress(si, func(ia ip.IfAddr, ifa *ip.IfAddress) (err error) {
			p := FromIp4Prefix(&ifa.Prefix)
			if !p.IsEqual(addr) && (addr.Address.MatchesPrefix(&p) || p.Address.MatchesPrefix(addr)) {
				err = fmt.Errorf("%s: add %s conflicts with existing address %s", si.Name(m.Vnet), addr, &p)
				dbgvnet.Adj.Logf("DEBUG %s: add %s conflicts with existing address %s", si.Name(m.Vnet), addr, &p)
			}
			return
		})
		if err != nil {
			return
		}
	}

	var (
		ia     ip.IfAddr
		exists bool
	)

	pa := addr.ToIpPrefix()

	// Fib remove messages should have came from Linux and fdb before InterfaceAddress remove
	// Check and flag just in case, as Local/Glean adjacencies contains index to IfAddress so
	// could be a problem is IfAddress is freed, but index is still used
	if isDel {
		ia, exists = m.Main.IfAddrForPrefix(&pa, si)
		f := m.fibBySi(si)
		p := Prefix{Address: addr.Address, Len: 32}
		if adj, _, found := f.GetLocal(&p, si); found {
			dbgvnet.Adj.Logf("DEBUG deleting IfAddr %v, but it is still used by local route %v adj %v\n",
				addr.String(), p.String(), adj)
		}
		q := addr.ApplyMask()
		if adj, _, found := f.GetGlean(q, si); found {
			dbgvnet.Adj.Logf("DEBUG deleting IfAddr %v, but it is still used by glean route %v adj %v\n",
				addr.String(), q.String(), adj)
		}
	}

	// Add/Delete interface address.  Return error if deleting non-existent address.
	if ia, exists, err = m.Main.AddDelInterfaceAddress(si, &pa, isDel); err != nil {
		return
	}

	if !isDel {
		f := m.fibBySi(si)
		q := addr.ApplyMask()
		if adj, _, found := f.GetGlean(q, si); found {
			ifa := m.GetIfAddr(ia)
			ifa.NeighborProbeAdj = adj
		} else {
			// will be set when glean is created
		}
	}

	// Do callbacks when new address is created or old one is deleted.
	if isDel || !exists {
		for i := range m.ifAddrAddDelHooks.hooks {
			m.ifAddrAddDelHooks.Get(i)(ia, isDel)
		}
	}

	return
}

// function registered in ip4/package.go as a SwIfAdminUpDownHook
func (m *Main) swIfAdminUpDown(v *vnet.Vnet, si vnet.Si, isUp bool) (err error) {
	m.validateDefaultFibForSi(si)
	f := m.fibBySi(si)
	m.ForeachIfAddress(si, func(ia ip.IfAddr, ifa *ip.IfAddress) (err error) {
		// Do not need to do anything for glean
		// Linux and fdb will send explicit message to add/del glean routes on admin up/down

		// Do need to install/uninstall local adjacency; but not add/del the local route itself
		p := FromIp4Prefix(&ifa.Prefix)
		if _, r, ok := f.GetLocal(&p, si); ok {
			if isUp {
				f.addFib(m, r)
			} else {
				f.delFib(m, r)
			}
		}
		return
	})
	return
}

func (f *Fib) Reset() {
	dbgvnet.Adj.Logf("clear out all fibs in %v\n", f.index)
	f.reachable.reset()
	f.unreachable.reset()
	f.routeFib.reset()
	f.local.reset()
	f.glean.reset()
	f.punt.reset()
}

func (m *Main) FibReset(fi ip.FibIndex) {
	for i := range m.fibs {
		if i != int(fi) && m.fibs[i] != nil {
			m.fibs[i].reachable.clean(fi)
			m.fibs[i].unreachable.clean(fi)
		}
	}

	f := m.fibByIndex(fi, true)
	f.Reset()
}
