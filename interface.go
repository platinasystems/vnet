// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vnet

import (
	"github.com/platinasystems/elib/cli"
	"github.com/platinasystems/elib/elog"
	"github.com/platinasystems/elib/loop"
	"github.com/platinasystems/elib/parse"
	"github.com/platinasystems/vnet/internal/dbgvnet"

	"errors"
	"fmt"
	"strconv"
	"time"
)

type HwIf struct {
	vnet *Vnet

	name     string
	elogName elog.StringRef

	hi Hi
	si Si

	// Hardware link state: up or down
	linkUp bool

	// Transmit is enabled when both link and admin state are up.
	txUp bool

	// Hardware is unprovisioned.
	// Interfaces with 4 SERDES lanes will be represented as 4 interfaces.
	// Lanes may all be a single interface (1 provisioned 4 lane interface +
	// 3 unprovisioned 0 lane interfaces).
	unprovisioned bool

	speed Bandwidth

	media string

	// Mask of SERDES lanes for this interface.
	laneMask LaneMask

	// Max size of packet in bytes (MTU)
	maxPacketSize uint

	defaultId IfId
	subSiById map[IfId]Si

	n []outputInterfaceNoder
}

//go:generate gentemplate -d Package=vnet -id HwIf -d PoolType=hwIferPool -d Type=HwInterfacer -d Data=elts github.com/platinasystems/elib/pool.tmpl

type IfIndex uint32
type LaneMask uint32

type HwInterfacer interface {
	Devicer
	HwIfClasser
	GetHwIf() *HwIf
}

func (h *HwIf) GetHwIf() *HwIf           { return h }
func (h *HwIf) Name() string             { return h.name }
func (h *HwIf) ElogName() elog.StringRef { return h.elogName }
func (h *HwIf) Si() Si                   { return h.si }
func (h *HwIf) Hi() Hi                   { return h.hi }
func (h *HwIf) GetVnet() *Vnet           { return h.vnet }
func (h *HwIf) IsUnix() bool             { return false }

func (h *HwIf) SetName(v *Vnet, name string) {
	h.name = name
	h.elogName = elog.SetString(name)
	v.hwIfIndexByName.Set(name, uint(h.hi))
}
func (v *Vnet) HwIfByName(name string) (Hi, bool) {
	hi, ok := v.hwIfIndexByName[name]
	return Hi(hi), ok
}

func (h *HwIf) LinkString() (s string) {
	s = "down"
	if h.linkUp {
		s = "up"
	}
	return
}

// Software and hardware interface index.
// Alias for commonly used types.
type Si IfIndex
type Hi IfIndex

const (
	SiNil Si = ^Si(0)
	HiNil Hi = ^Hi(0)
)

type SwIfKind uint16

const (
	SwIfKindInvalid SwIfKind = iota
	// Hardware interface.
	SwIfKindHardware
	// Sub interface (e.g. vlan) of hardware interface.
	SwIfKindSubInterface
	// Sw interface for a bridge
	SwBridgeInterface

	nBuiltinSwIfKind

	// User defined kinds follow.
)

type SwInterfaceType struct {
	SwIfKind SwIfKind
}

func (k SwIfKind) String() string {
	switch k {
	case SwIfKindInvalid:
		return "SwIfKindInvalid"
	case SwIfKindHardware:
		return "SwIfKindHardware"
	case SwIfKindSubInterface:
		return "SwIfKindSubInterface"
	case SwBridgeInterface:
		return "SwBridgeInterface"
	case nBuiltinSwIfKind:
		return "nBuiltinSwIfKind"
	default:
		return strconv.Itoa(int(k))

	}
}

func (t *SwInterfaceType) GetSwInterfaceType() *SwInterfaceType                                  { return t }
func (t *SwInterfaceType) SwInterfaceName(v *Vnet, s *SwIf) string                               { return s.name }
func (t *SwInterfaceType) SwInterfaceSetRewrite(rw *Rewrite, si Si, noder Noder, typ PacketType) {}
func (t *SwInterfaceType) SwInterfaceRewriteString(v *Vnet, r *Rewrite) []string {
	hi := v.SupHi(r.Si)
	h := v.HwIfer(hi)
	return h.FormatRewrite(r)
}
func (t *SwInterfaceType) SwInterfaceLessThan(v *Vnet, a, b *SwIf) bool { return v.SwLessThan(a, b) }

type swInterfaceTyper interface {
	GetSwInterfaceType() *SwInterfaceType
	SwInterfaceName(v *Vnet, s *SwIf) string
	SwInterfaceSetRewrite(rw *Rewrite, si Si, noder Noder, typ PacketType)
	SwInterfaceRewriteString(v *Vnet, rw *Rewrite) []string
	SwInterfaceLessThan(v *Vnet, a, b *SwIf) bool
}

func (i *interfaceMain) registerBuiltinSwInterfaceTypes() {
	if len(i.swInterfaceTypes) >= int(nBuiltinSwIfKind) {
		return
	}
	i.swInterfaceTypes = make([]swInterfaceTyper, nBuiltinSwIfKind)
	for k := range i.swInterfaceTypes {
		i.swInterfaceTypes[k] = &SwInterfaceType{SwIfKind: SwIfKind(k)}
	}
}

func (i *interfaceMain) RegisterSwInterfaceType(r swInterfaceTyper) {
	i.registerBuiltinSwInterfaceTypes()
	t := r.GetSwInterfaceType()
	t.SwIfKind = SwIfKind(len(i.swInterfaceTypes))
	i.swInterfaceTypes = append(i.swInterfaceTypes, r)
	return
}

func (si Si) Kind(v *Vnet) SwIfKind {
	return v.SwIf(si).kind
}
func (s *SwIf) GetType(v *Vnet) swInterfaceTyper {
	return v.interfaceMain.swInterfaceTypes[s.kind]
}
func (si Si) GetType(v *Vnet) swInterfaceTyper {
	return v.SwIf(si).GetType(v)
}
func (si Si) SupSi(v *Vnet) Si {
	return v.SwIf(si).supSi
}

type swIfFlag uint16

const (
	swIfAdminUpIndex, swIfAdminUp swIfFlag = iota, 1 << iota
	swIfPuntIndex, swIfPunt
)

func (f swIfFlag) String() (s string) {
	s = "down"
	if f&swIfAdminUp != 0 {
		s = "up"
	}
	extra := ""
	if f&swIfPunt != 0 {
		if extra != "" {
			extra += ", "
		}
		extra += "punt"
	}
	if extra != "" {
		s += "(" + extra + ")"
	}
	return
}

type IfId IfIndex

type SwIf struct {
	kind SwIfKind

	name string //if SwIfKindHardware, then name should same as HwIf.name

	flags swIfFlag

	// Pool index for this interface.
	si Si

	// Software interface index of super-interface.
	// Equal to index if this interface is not a sub-interface.
	supSi Si

	// For hardware interface: HwIfIndex
	// For sub interface: sub interface id (e.g. vlan/vc number).
	id IfId
}

//go:generate gentemplate -d Package=vnet -id SwIf -d PoolType=swIfPool -d Type=SwIf -d Data=elts github.com/platinasystems/elib/pool.tmpl

func (m *Vnet) addDelSwInterface(siʹ, supSi Si, kind SwIfKind, id IfId, ifname string, isDel bool) (si Si) {
	si = siʹ

	if isDel {
		if err := si.SetAdminUp(m, false); err != nil {
			panic(err) // how to recover?
		}
	}

	if !isDel {
		si = Si(m.swInterfaces.GetIndex())
		if supSi == SiNil {
			supSi = si
		}
		s := m.SwIf(si)
		s.kind = kind
		s.si = si
		s.supSi = supSi
		s.id = id
		s.name = ifname
		m.counterValidateSw(si)
	}

	for i := range m.swIfAddDelHooks.hooks {
		err := m.swIfAddDelHooks.Get(i)(m, si, isDel)
		if err != nil {
			panic(err) // how to recover?
		}
	}

	if isDel {
		s := m.SwIf(si)
		if s.kind == SwIfKindHardware {
			panic(fmt.Sprintf("%v %v is a supSi kind %v, cannot delete\n", si, si.Name(m), s.kind))
		}
		if s := m.SwIf(si); s.kind == SwIfKindSubInterface {
			h := m.SupHwIf(s)
			delete(h.subSiById, s.id)
		}
		m.swInterfaces.PutIndex(uint(si))
		si = SiNil
	}

	dbgvnet.Adj.Logf("si %v.%v %v %v %v, del %v", si, supSi, kind, id, ifname, isDel)
	return
}

// remove ifaddr, neighbor via hooks and admin down (removes glean and local fib), but does not delete the SwIf
func (m *Vnet) CleanAndDownSwInterface(si Si) {
	dbgvnet.Adj.Logf("%v", si.Name(m))
	if err := si.SetAdminUp(m, false); err != nil {
		dbgvnet.Adj.Logf("SetAdminDown %v and got error %v", si.Name(m), err)
	}

	for i := range m.swIfAddDelHooks.hooks {
		err := m.swIfAddDelHooks.Get(i)(m, si, true)
		if err != nil {
			dbgvnet.Adj.Logf("call swIfAddDelHooks %v and got error %v", si.Name(m), err)
		}
	}

}

func (m *Vnet) NewSwIf(kind SwIfKind, id IfId, ifname string) Si {
	return m.addDelSwInterface(SiNil, SiNil, kind, id, ifname, false)
}
func (m *Vnet) DelSwIf(si Si) {
	m.addDelSwInterface(si, si, 0, 0, "", true)
}

func (m *Vnet) NewSwSubInterface(supSi Si, id IfId, ifname string) (si Si) {
	si = m.addDelSwInterface(SiNil, supSi, SwIfKindSubInterface, id, ifname, false)
	s := m.SwIf(si)
	h := m.SupHwIf(s)
	if h.subSiById == nil {
		h.subSiById = make(map[IfId]Si)
	}
	h.subSiById[id] = si
	return
}
func (si Si) IsSwSubInterface(v *Vnet) bool { return v.SwIf(si).kind == SwIfKindSubInterface }

func (m *interfaceMain) SwIfValid(i Si) bool {
	x := int(i)
	if x >= 0 && x < len(m.swInterfaces.elts) {
		return true
	}
	return false
}
func (m *interfaceMain) SwIf(i Si) *SwIf { return &m.swInterfaces.elts[i] }
func (m *interfaceMain) SupSi(i Si) Si   { return m.SwIf(i).supSi }
func (m *interfaceMain) SupSwIf(s *SwIf) (sup *SwIf) {
	sup = s
	if s.supSi != s.si {
		sup = m.SwIf(s.supSi)
	}
	return
}
func (m *interfaceMain) HwIfer(i Hi) HwInterfacer { return m.hwIferPool.elts[i] }
func (m *interfaceMain) HwIf(i Hi) *HwIf          { return m.HwIfer(i).GetHwIf() }
func (hi Hi) Si(m *Vnet) Si                       { return m.HwIf(hi).si }
func (m *interfaceMain) SupHwIf(s *SwIf) (h *HwIf) {
	sup := m.SupSwIf(s)
	if sup.kind == SwIfKindHardware {
		h = m.HwIf(Hi(sup.id))
	} else if sup.kind == SwIfKindSubInterface {
		h = m.HwIf(Hi(sup.supSi))
	}
	return
}
func (m *interfaceMain) SupHi(si Si) Hi {
	sw := m.SwIf(si)
	hw := m.SupHwIf(sw)
	return hw.hi
}

func (m *interfaceMain) HwIferForSupSi(si Si) (h HwInterfacer) {
	hw := m.SupHwIf(m.SwIf(si))
	if hw != nil {
		h = m.HwIfer(hw.hi)
	}
	return
}

func (s *SwIf) builtinSwIfName(vn *Vnet) (v string) {
	hw := vn.SupHwIf(s)
	if hw != nil {
		v = hw.name
	}
	if s.kind != SwIfKindHardware {
		if s.kind == SwBridgeInterface {
			v = "xethbr"
			v += fmt.Sprintf(".%d", s.id)
		} else {
			h := vn.HwIfer(hw.hi)
			v += h.FormatId(s.id)
		}
	}
	return
}
func (i Si) Name(v *Vnet) string {
	if v.SwIfValid(i) {
		s := v.SwIf(i)
		return s.name
	} else if i == SiNil {
		return "SiNil"
	} else {
		return fmt.Sprintf("si %v ???", i)
	}
	/*
		t := v.swInterfaceTypes[s.kind]
		return t.SwInterfaceName(v, s)
	*/
}
func (i Hi) Name(v *Vnet) string { return v.HwIf(i).name }

func (i *SwIf) GetId() IfId { return i.id }
func (i *SwIf) Id(v *Vnet) (id IfId) {
	id = i.id
	if i.kind == SwIfKindHardware {
		h := v.HwIf(Hi(id))
		id = h.defaultId
	}
	return
}
func (si Si) Id(v *Vnet) (id IfId) { return v.SwIf(si).Id(v) }
func (si Si) SetId(v *Vnet, id IfId) {
	swi := v.SwIf(si)
	swi.id = id
}

func (i *SwIf) IsAdminUp() bool      { return i.flags&swIfAdminUp != 0 }
func (si Si) IsAdminUp(v *Vnet) bool { return v.SwIf(si).IsAdminUp() }

func (sw *SwIf) SetAdminUp(v *Vnet, wantUp bool) (err error) {
	isUp := sw.flags&swIfAdminUp != 0
	if isUp == wantUp {
		return
	}
	sw.flags ^= swIfAdminUp
	for i := range v.swIfAdminUpDownHooks.hooks {
		err = v.swIfAdminUpDownHooks.Get(i)(v, sw.si, wantUp)
		if err != nil {
			return
		}
	}
	return
}

func (si Si) SetAdminUp(v *Vnet, isUp bool) (err error) {
	s := v.SwIf(si)
	return s.SetAdminUp(v, isUp)
}

func (h *HwIf) SetAdminUp(isUp bool) (err error) {
	if h.unprovisioned {
		err = errors.New("hardware interface is unprovisioned")
		return
	}

	s := h.vnet.SwIf(h.si)
	err = s.SetAdminUp(h.vnet, isUp)
	h.txUpDown()
	return
}

func (hi Hi) SetAdminUp(v *Vnet, isUp bool) (err error) {
	h := v.HwIf(hi)
	return h.SetAdminUp(isUp)
}

func (h *HwIf) IsProvisioned() bool      { return !h.unprovisioned }
func (hi Hi) IsProvisioned(v *Vnet) bool { return !v.HwIf(hi).unprovisioned }

func (h *HwIf) SetProvisioned(v bool) (err error) {
	if !h.unprovisioned == v {
		return
	}
	vn := h.vnet
	for i := range vn.hwIfProvisionHooks.hooks {
		err = vn.hwIfProvisionHooks.Get(i)(vn, h.hi, v)
		if err != nil {
			break
		}
	}
	// Toggle provisioning hooks show no error.
	if err == nil {
		h.unprovisioned = !v
	}
	return
}

func (h *HwIf) IsLinkUp() bool      { return h.linkUp }
func (hi Hi) IsLinkUp(v *Vnet) bool { return v.HwIf(hi).IsLinkUp() }

func (h *HwIf) SetLinkUp(v bool) (err error) {
	if h.linkUp == v {
		return
	}
	h.linkUp = v
	vn := h.vnet
	for i := range vn.hwIfLinkUpDownHooks.hooks {
		err = vn.hwIfLinkUpDownHooks.Get(i)(vn, h.hi, v)
		if err != nil {
			return
		}
	}
	h.txUpDown()
	return
}

func (h *HwIf) txUpDown() {
	s := h.vnet.SwIf(h.si)
	up := s.IsAdminUp() && h.IsLinkUp()
	if h.txUp != up {
		h.txNodeUpDown(up)
	}
	h.txUp = up
}

type LinkStateEvent struct {
	Event
	Hi   Hi
	IsUp bool
}

func (e *LinkStateEvent) EventAction() {
	h := e.Vnet().HwIf(e.Hi)
	if err := h.SetLinkUp(e.IsUp); err != nil {
		panic(err)
	}
}

func (e *LinkStateEvent) String() string {
	return fmt.Sprintf("link-state %s %v", e.Hi.Name(e.Vnet()), e.IsUp)
}

func (i Hi) GetAddress(v *Vnet) []byte { return v.HwIfer(i).GetAddress() }

func (h *HwIf) MaxPacketSize() uint { return h.maxPacketSize }

func (h *HwIf) SetMaxPacketSize(v uint) (err error) {
	h.maxPacketSize = v
	// fixme call hooks
	return
}

func (h *HwIf) Speed() Bandwidth   { return h.speed }
func (h *HwIf) Media() string      { return h.media }
func (h *HwIf) LaneMask() LaneMask { return h.laneMask }

func (hw *HwIf) SetSpeed(v Bandwidth) (err error) {
	vn := hw.vnet
	h := vn.HwIfer(hw.hi)
	err = h.ValidateSpeed(v)
	if err == nil {
		hw.speed = v
	}
	return
}
func (hw *HwIf) SetMedia(pi string) (err error) {
	vn := hw.vnet
	h := vn.HwIfer(hw.hi)
	err = h.ValidateMedia(pi)
	if err == nil {
		hw.media = pi

		// In case media is set after speed do a speed change with
		// speed on record
		err = hw.SetSpeed(hw.speed)
	}
	return
}

func (hi Hi) SetSpeed(v *Vnet, s Bandwidth) error { return v.HwIf(hi).SetSpeed(s) }
func (hi Hi) SetMedia(v *Vnet, pi string) error   { return v.HwIf(hi).SetMedia(pi) }

var ErrNotSupported = errors.New("not supported")

// Default versions.
func (h *HwIf) ValidateSpeed(v Bandwidth) (err error) { return }
func (h *HwIf) ValidateMedia(pi string) (err error)   { return }
func (h *HwIf) SetLoopback(v IfLoopbackType) (err error) {
	switch v {
	case IfLoopbackNone:
	default:
		err = ErrNotSupported
	}
	return
}
func (h *HwIf) GetSwInterfaceCounterNames() (nm InterfaceCounterNames) { return }

func (h *HwIf) DefaultId() IfId                       { return 0 }
func (h *HwIf) LessThanId(a, b IfId) bool             { return IfIndex(a) < IfIndex(b) }
func (h *HwIf) ParseId(a *IfId, in *parse.Input) bool { return in.Parse(".%d", a) }
func (h *HwIf) FormatId(a IfId) string                { return fmt.Sprintf(".%d", a) }
func (a *HwIf) LessThan(b HwInterfacer) bool          { return a.hi < b.GetHwIf().hi }

type interfaceMain struct {
	hwIferPool       hwIferPool
	hwIfIndexByName  parse.StringMap
	swInterfaceTypes []swInterfaceTyper
	swInterfaces     swIfPool
	ifThreads        ifThreadVec

	// Counters
	swIfCounterNames     InterfaceCounterNames
	swIfCounterSyncHooks SwIfCounterSyncHookVec

	swIfAddDelHooks      SwIfAddDelHookVec
	swIfAdminUpDownHooks SwIfAdminUpDownHookVec
	hwIfAddDelHooks      HwIfAddDelHookVec
	hwIfLinkUpDownHooks  HwIfLinkUpDownHookVec
	hwIfProvisionHooks   HwIfProvisionHookVec

	timeLastClear time.Time
}

func (m *interfaceMain) init() {
	m.registerBuiltinSwInterfaceTypes()

	// Give clear counters time an initial value.
	m.timeLastClear = time.Now()
}

//go:generate gentemplate -d Package=vnet -id ifThread -d VecType=ifThreadVec -d Type=*InterfaceThread github.com/platinasystems/elib/vec.tmpl

func (v *Vnet) RegisterAndProvisionHwInterface(h HwInterfacer, provision bool, format string, args ...interface{}) (err error) {
	hi := Hi(v.hwIferPool.GetIndex())
	v.hwIferPool.elts[hi] = h
	hw := h.GetHwIf()
	hw.hi = hi
	hw.SetName(v, fmt.Sprintf(format, args...))
	hw.vnet = v
	hw.defaultId = h.DefaultId()
	hw.unprovisioned = !provision
	hw.si = v.NewSwIf(SwIfKindHardware, IfId(hw.hi), hw.name)

	isDel := false
	m := &v.interfaceMain
	for i := range m.hwIfAddDelHooks.hooks {
		err := m.hwIfAddDelHooks.Get(i)(v, hi, isDel)
		if err != nil {
			panic(err) // how to recover?
		}
	}
	return
}

func (v *Vnet) RegisterHwInterface(h HwInterfacer, format string, args ...interface{}) (err error) {
	return v.RegisterAndProvisionHwInterface(h, true, format, args...)
}

func (m *interfaceMain) newInterfaceThread() (t *InterfaceThread) {
	t = &InterfaceThread{}
	m.counterInit(t)
	return
}

func (m *interfaceMain) GetIfThread(id uint) (t *InterfaceThread) {
	m.ifThreads.Validate(id)
	if t = m.ifThreads[id]; t == nil {
		t = m.newInterfaceThread()
		m.ifThreads[id] = t
	}
	return
}
func (n *Node) GetIfThread() *InterfaceThread { return n.Vnet.GetIfThread(n.ThreadId()) }

func (v *Vnet) ForeachSwIf(f func(si Si)) {
	v.swInterfaces.ForeachIndex(func(i uint) {
		si := Si(i)
		f(si)
	})
}

func (v *Vnet) ForeachHwIf(unixOnly bool, f func(hi Hi)) {
	for i := range v.hwIferPool.elts {
		if v.hwIferPool.IsFree(uint(i)) {
			continue
		}
		hwifer := v.hwIferPool.elts[i]
		if unixOnly && !hwifer.IsUnix() {
			continue
		}
		h := hwifer.GetHwIf()
		if h.unprovisioned {
			continue
		}
		f(h.hi)
	}
}

// Interface ordering for output.
func (v *Vnet) HwLessThan(a, b *HwIf) bool {
	ha, hb := v.HwIfer(a.hi), v.HwIfer(b.hi)
	da, db := ha.DriverName(), hb.DriverName()
	if da != db {
		return da < db
	}
	return ha.LessThan(hb)
}

func (v *Vnet) SwLessThan(a, b *SwIf) bool {
	hwa, hwb := v.SupHwIf(a), v.SupHwIf(b)
	if hwa != nil && hwb != nil {
		if hwa != hwb {
			return v.HwLessThan(hwa, hwb)
		}
		ha := v.HwIfer(hwa.hi)
		return ha.LessThanId(a.id, b.id)
	}
	// Different kind?  Sort by increasing kind.
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	// Same kind.
	return a.name < b.name
}

// Interface can loopback at MAC or PHY.
type IfLoopbackType int

const (
	IfLoopbackNone IfLoopbackType = iota
	IfLoopbackMac
	IfLoopbackPhy
)

func (x *IfLoopbackType) Parse(in *parse.Input) {
	switch text := in.Token(); text {
	case "none":
		*x = IfLoopbackNone
	case "mac":
		*x = IfLoopbackMac
	case "phy":
		*x = IfLoopbackPhy
	default:
		in.ParseError()
	}
	return
}

// To clarify units: 1e9 * vnet.Bps
const (
	Bps    = 1e0
	Kbps   = 1e3
	Mbps   = 1e6
	Gbps   = 1e9
	Tbps   = 1e12
	Bytes  = 1
	Kbytes = 1 << 10
	Mbytes = 1 << 20
	Gbytes = 1 << 30
)

type Bandwidth float64

func (b Bandwidth) String() string {
	if b == 0 {
		return "autoneg"
	}
	unit := Bandwidth(1)
	prefix := ""
	switch {
	case b < Kbps:
		break
	case b <= Mbps:
		unit = Kbps
		prefix = "k"
	case b <= Gbps:
		unit = Mbps
		prefix = "m"
	case b <= Tbps:
		unit = Gbps
		prefix = "g"
	default:
		unit = Tbps
		prefix = "t"
	}
	b /= unit
	return fmt.Sprintf("%g%s", b, prefix)
}

func (b *Bandwidth) Parse(in *parse.Input) {
	var f float64

	// Special speed code "autoneg" means auto-negotiate speed.
	// b = 0 imply autoneg for Bandwidth
	if in.Parse("au%*toneg") {
		*b = 0
		return
	}

	ok := in.Parse("%f", &f)
	if !ok {
		//panic is gracefully handled by in.Parse as parse error; will not crash code
		//default way to return error back to in.Parse that parse failed
		panic(fmt.Errorf("%v not valid speed", in))
	}

	unit := Bps
	switch {
	case in.AtOneof("Kk") < 2:
		unit = Kbps
	case in.AtOneof("Mm") < 2:
		unit = Mbps
	case in.AtOneof("Gg") < 2:
		unit = Gbps
	case in.AtOneof("Tt") < 2:
		unit = Tbps
	}
	*b = Bandwidth(float64(f) * unit)
}

// Class of hardware interfaces, for example, ethernet, sonet, srp, docsis, etc.
type HwIfClasser interface {
	// Get/set/format interface address (e.g. mac address for ethernet).
	GetAddress() []byte
	SetAddress(a []byte)
	FormatAddress() string
	// Encapsulation rewrite string for this interface class.
	SetRewrite(v *Vnet, r *Rewrite, t PacketType, dstAddr []byte)
	FormatRewrite(r *Rewrite) []string
	ParseRewrite(r *Rewrite, in *parse.Input)
	// ID: for example VLAN tag(s) for ethernet.  32 bit number uniquely identifies sub-interface.
	DefaultId() IfId
	LessThanId(a, b IfId) bool
	ParseId(a *IfId, in *parse.Input) bool
	FormatId(a IfId) string
	ConfigureHwIf(in *cli.Input) (ok bool, err error)
}

type Devicer interface {
	Noder
	loop.OutputLooper
	DriverName() string // name of device driver
	LessThan(b HwInterfacer) bool
	IsUnix() bool
	ValidateSpeed(speed Bandwidth) error
	ValidateMedia(pi string) error
	SetLoopback(v IfLoopbackType) error
	GetHwInterfaceCounterNames() InterfaceCounterNames
	GetSwInterfaceCounterNames() InterfaceCounterNames
	GetHwInterfaceCounterValues(t *InterfaceThread)
	GetHwInterfaceFinalSpeed() (s Bandwidth)
}

type SwIfAddDelHook func(v *Vnet, si Si, isDel bool) error
type SwIfAdminUpDownHook func(v *Vnet, si Si, isUp bool) error
type SwIfCounterSyncHook func(v *Vnet)
type HwIfAddDelHook func(v *Vnet, hi Hi, isDel bool) error
type HwIfLinkUpDownHook func(v *Vnet, hi Hi, isUp bool) error
type HwIfProvisionHook func(v *Vnet, hi Hi, isProvisioned bool) error

//go:generate gentemplate -id SwIfAddDelHook -d Package=vnet -d DepsType=SwIfAddDelHookVec -d Type=SwIfAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id SwIfAdminUpDownHook -d Package=vnet -d DepsType=SwIfAdminUpDownHookVec -d Type=SwIfAdminUpDownHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id HwIfAddDelHook -d Package=vnet -d DepsType=HwIfAddDelHookVec -d Type=HwIfAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id HwIfLinkUpDownHook -d Package=vnet -d DepsType=HwIfLinkUpDownHookVec -d Type=HwIfLinkUpDownHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id HwIfProvisionHook -d Package=vnet -d DepsType=HwIfProvisionHookVec -d Type=HwIfProvisionHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id SwIfCounterSyncHookVec -d Package=vnet -d DepsType=SwIfCounterSyncHookVec -d Type=SwIfCounterSyncHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl

func (m *interfaceMain) RegisterSwIfAddDelHook(h SwIfAddDelHook) {
	m.swIfAddDelHooks.Add(h)
}
func (m *interfaceMain) RegisterSwIfAdminUpDownHook(h SwIfAdminUpDownHook) {
	m.swIfAdminUpDownHooks.Add(h)
}
func (m *interfaceMain) RegisterSwIfCounterSyncHook(h SwIfCounterSyncHook) {
	m.swIfCounterSyncHooks.Add(h)
}
func (m *interfaceMain) RegisterHwIfAddDelHook(h HwIfAddDelHook) {
	m.hwIfAddDelHooks.Add(h)
}
func (m *interfaceMain) RegisterHwIfLinkUpDownHook(h HwIfLinkUpDownHook) {
	m.hwIfLinkUpDownHooks.Add(h)
}
func (m *interfaceMain) RegisterHwIfProvisionHook(h HwIfProvisionHook) {
	m.hwIfProvisionHooks.Add(h)
}
