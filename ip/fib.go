// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip

import (
	"github.com/platinasystems/elib"
	"github.com/platinasystems/vnet"

	"fmt"
)

// Dense index into fib vector.
type FibIndex uint32

type FibName struct {
	M *Main
	I FibIndex
}

//go:generate gentemplate -d Package=ip -id FibIndex -d VecType=FibIndexVec -d Type=FibIndex github.com/platinasystems/elib/vec.tmpl

// Sparse 32 bit id for route table.
type FibId uint32

type fibMain struct {
	// Table index indexed by software interface.
	fibIndexBySi FibIndexVec

	nameByIndex elib.StringVec

	// Hash table mapping table id to fib index.
	// ID space is not necessarily dense; index space is dense.
	fibIndexById map[FibId]FibIndex

	// Hash table mapping interface route rewrite adjacency index by sw if index.
	ifRouteAdjBySi map[vnet.Si]FibIndex
}

func (f *fibMain) fibIndexForSi(si vnet.Si, validate bool) FibIndex {
	if validate {
		f.fibIndexBySi.Validate(uint(si))
	}
	return f.fibIndexBySi[si]
}
func (f *fibMain) FibIndexForSi(si vnet.Si) FibIndex {
	return f.fibIndexForSi(si, false)
}
func (f *fibMain) ValidateFibIndexForSi(si vnet.Si) FibIndex {
	return f.fibIndexForSi(si, true)
}

func (m *Main) SetFibIndexForSi(si vnet.Si, fi FibIndex) {
	f := &m.fibMain
	f.fibIndexBySi.Validate(uint(si))
	f.fibIndexBySi[si] = fi
	return
}
func (f *fibMain) FibIndexForId(id FibId) (i FibIndex, ok bool) { i, ok = f.fibIndexById[id]; return }
func (f *fibMain) SetFibIndexForId(id FibId, i FibIndex) {
	if f.fibIndexById == nil {
		f.fibIndexById = make(map[FibId]FibIndex)
	}
	f.fibIndexById[id] = i
}

func (f *fibMain) SetFibNameForIndex(name string, i FibIndex) {
	f.nameByIndex.Validate(uint(i))
	f.nameByIndex[i] = name
}
func (i FibIndex) Name(m *Main) string {
	f := &m.fibMain
	if uint(i) < f.nameByIndex.Len() {
		return f.nameByIndex[i]
	} else {
		return fmt.Sprintf("%d", i)
	}
}
func (n FibName) String() (s string) {
	f := &n.M.fibMain
	s = fmt.Sprintf("%d", n.I)
	if f == nil {
		return
	}
	if uint(n.I) < f.nameByIndex.Len() {
		s = f.nameByIndex[n.I]
	}
	return
}
