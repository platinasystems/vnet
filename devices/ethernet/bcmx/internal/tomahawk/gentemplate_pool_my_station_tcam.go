// autogenerated: do not edit!
// generated from gentemplate [gentemplate -d Package=tomahawk -id my_station_tcam -d PoolType=my_station_tcam_pool -d Type=my_station_tcam_entry -d Data=entries github.com/platinasystems/go/elib/pool.tmpl]

package tomahawk

import (
	"github.com/platinasystems/go/elib"
)

type my_station_tcam_pool struct {
	elib.Pool
	entries []my_station_tcam_entry
}

func (p *my_station_tcam_pool) GetIndex() (i uint) {
	l := uint(len(p.entries))
	i = p.Pool.GetIndex(l)
	if i >= l {
		p.Validate(i)
	}
	return i
}

func (p *my_station_tcam_pool) PutIndex(i uint) (ok bool) {
	return p.Pool.PutIndex(i)
}

func (p *my_station_tcam_pool) IsFree(i uint) (v bool) {
	v = i >= uint(len(p.entries))
	if !v {
		v = p.Pool.IsFree(i)
	}
	return
}

func (p *my_station_tcam_pool) Resize(n uint) {
	c := elib.Index(cap(p.entries))
	l := elib.Index(len(p.entries) + int(n))
	if l > c {
		c = elib.NextResizeCap(l)
		q := make([]my_station_tcam_entry, l, c)
		copy(q, p.entries)
		p.entries = q
	}
	p.entries = p.entries[:l]
}

func (p *my_station_tcam_pool) Validate(i uint) {
	c := elib.Index(cap(p.entries))
	l := elib.Index(i) + 1
	if l > c {
		c = elib.NextResizeCap(l)
		q := make([]my_station_tcam_entry, l, c)
		copy(q, p.entries)
		p.entries = q
	}
	if l > elib.Index(len(p.entries)) {
		p.entries = p.entries[:l]
	}
}

func (p *my_station_tcam_pool) Elts() uint {
	return uint(len(p.entries)) - p.FreeLen()
}

func (p *my_station_tcam_pool) Len() uint {
	return uint(len(p.entries))
}

func (p *my_station_tcam_pool) Foreach(f func(x my_station_tcam_entry)) {
	for i := range p.entries {
		if !p.Pool.IsFree(uint(i)) {
			f(p.entries[i])
		}
	}
}
