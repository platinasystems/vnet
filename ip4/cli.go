// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip4

import (
	"github.com/platinasystems/elib/cli"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/ip"

	"bytes"
	"fmt"
	"net"
	"sort"
)

type fibShowUsageHook func(w cli.Writer)

//go:generate gentemplate -id FibShowUsageHook -d Package=ip4 -d DepsType=fibShowUsageHookVec -d Type=fibShowUsageHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl

type showFibConfig struct {
	detail      bool
	summary     bool
	unreachable bool
	showTable   string
}

func (m *Main) showIpFib(c cli.Commander, w cli.Writer, in *cli.Input) (err error) {
	cf := showFibConfig{}
	for !in.End() {
		switch {
		case in.Parse("d%*etail"):
			cf.detail = true
		case in.Parse("s%*ummary"):
			cf.summary = true
		case in.Parse("t%*able %s", &cf.showTable):
		default:
			err = cli.ParseError
			return
		}
	}

	if cf.summary {
		m.showSummary(w)
		return
	}

	// Sync adjacency stats with hardware.
	m.CallAdjSyncCounterHooks()

	type route struct {
		prefixFibIndex ip.FibIndex
		prefix         net.IPNet
		r              FibResult
	}
	rs := []route{}
	for fi := range m.fibs {
		fib := m.fibs[fi]
		if fib == nil {
			continue
		}
		t := ip.FibIndex(fi).Name(&m.Main)
		if cf.showTable != "" && t != cf.showTable {
			rt := route{prefixFibIndex: ip.FibIndex(fi)}
			rs = append(rs, rt)
			continue
		}
		fib.reachable.foreach(func(p net.IPNet, r FibResult) {
			rt := route{prefixFibIndex: ip.FibIndex(fi), prefix: p, r: r}
			rs = append(rs, rt)
		})
		fib.routeFib.foreach(func(p net.IPNet, r FibResult) {
			rt := route{prefixFibIndex: ip.FibIndex(fi), prefix: p, r: r}
			rs = append(rs, rt)
		})
		fib.glean.foreach(func(p net.IPNet, r FibResult) {
			rt := route{prefixFibIndex: ip.FibIndex(fi), prefix: p, r: r}
			rs = append(rs, rt)
		})
		fib.local.foreach(func(p net.IPNet, r FibResult) {
			rt := route{prefixFibIndex: ip.FibIndex(fi), prefix: p, r: r}
			rs = append(rs, rt)
		})
		fib.punt.foreach(func(p net.IPNet, r FibResult) {
			rt := route{prefixFibIndex: ip.FibIndex(fi), prefix: p, r: r}
			rs = append(rs, rt)
		})
	}
	sort.Slice(rs, func(i, j int) bool {
		if cmp := int(rs[i].prefixFibIndex) - int(rs[j].prefixFibIndex); cmp != 0 {
			return cmp < 0
		}
		if cmp := bytes.Compare(rs[i].prefix.IP, rs[j].prefix.IP); cmp != 0 {
			return cmp < 0
		}
		return bytes.Compare(rs[i].prefix.Mask, rs[j].prefix.Mask) < 0
	})
	fmt.Fprintf(w, "%6s%30s%40s\n", "Table", "Destination", "Adjacency")
	for ri := range rs {
		r := &rs[ri]
		var lines []string
		if r.r.Adj != ip.AdjNil && r.r.Adj != ip.AdjMiss {
			lines = m.adjLines(r.r.Adj, cf.detail, r.r.Installed)
		}
		in := "---------"
		if r.r.Installed {
			in = "Installed"
		}
		//header := fmt.Sprintf("%12s%25s%15v", r.prefixFibIndex.Name(&m.Main), &r.prefix, in)
		header := fmt.Sprintf("%12s%25s%15v", r.prefixFibIndex.Name(&m.Main), r.prefix.String(), in)
		indent := fmt.Sprintf("%12s%25s%15v", "", "", "")
		if r.r.Type == VIA {
			for i, nh := range r.r.Nhs {
				reach := ""
				if nh.Adj == ip.AdjNil || nh.Adj == ip.AdjMiss || nh.Adj == ip.AdjPunt {
					reach = "unresolved"
				}
				line := fmt.Sprintf("%6svia %20v dev %10v weight %3v  %v",
					"", nh.Address, nh.Si.Name(m.v), nh.Weight, reach)
				if i == 0 {
					fmt.Fprintf(w, "%v%v\n", header, line)
				} else {
					fmt.Fprintf(w, "%v%v\n", indent, line)
				}
			}
		}
		for i := range lines {
			if i == 0 && (r.r.Type != VIA || len(r.r.Nhs) == 0) {
				fmt.Fprintf(w, "%v%s\n", header, lines[i])
			} else {
				fmt.Fprintf(w, "%v%s\n", indent, lines[i])
			}
		}
	}

	return
}

func (m *Main) clearIpFib(c cli.Commander, w cli.Writer, in *cli.Input) (err error) {
	// Sync adjacency stats with hardware.
	m.CallAdjSyncCounterHooks()
	m.Main.ClearAdjCounters()
	return
}

func (m *Main) adjLines(baseAdj ip.Adj, detail bool, installed bool) (lines []string) {
	const initialSpace = "  "
	nhs := m.NextHopsForAdj(baseAdj)
	adjs := m.GetAdj(baseAdj)
	if len(adjs) == 0 || adjs == nil {
		lines = append(lines, fmt.Sprintf("%s%6d: empty adjacency", initialSpace, baseAdj))
		return
	}
	ai := ip.Adj(0)
	for ni := range nhs {
		nh := &nhs[ni]
		adj := baseAdj + ai
		line := fmt.Sprintf("%s%6d: ", initialSpace, adj)
		ss := []string{}
		if int(ai) >= len(adjs) {
			lines = append(lines, fmt.Sprintf("adj %v out of range", ai))
			return
		}
		adj_lines := adjs[ai].String(&m.Main) // problem here if no hwif and no hwif.name
		if nh.Weight != 1 || nh.Adj != baseAdj {
			// adj_lines[0] += fmt.Sprintf(" %d-%d, %d x %d", adj, adj+ip.Adj(nh.Weight)-1, nh.Weight, nh.Adj)
			adj_lines[0] += fmt.Sprintf(" adj-range %d-%d, weight %d nh-adj %d", adj, adj+ip.Adj(nh.Weight)-1, nh.Weight, nh.Adj)
		}
		// Indent subsequent lines like first line if more than 1 lines.
		for i := 1; i < len(adj_lines); i++ {
			adj_lines[i] = fmt.Sprintf("%*s%s", len(line), "", adj_lines[i])
		}
		ss = append(ss, adj_lines...)

		counterAdj := nh.Adj
		if !m.EqualAdj(adj, nh.Adj) {
			counterAdj = adj
		}
		if installed && detail {
			m.Main.ForeachAdjCounter(counterAdj, func(tag string, v vnet.CombinedCounter) {
				if v.Packets != 0 {
					ss = append(ss, fmt.Sprintf("%s%spackets %16d", initialSpace, tag, v.Packets))
					ss = append(ss, fmt.Sprintf("%s%sbytes   %16d", initialSpace, tag, v.Bytes))
				}
			})
		}

		for _, s := range ss {
			lines = append(lines, line+s)
			line = initialSpace
		}

		ai += ip.Adj(nh.Weight)
	}

	return
}

func (m *Main) showSummary(w cli.Writer) {
	fmt.Fprintf(w, "%6s%12s\n", "Table", "Routes")
	for fi := range m.fibs {
		fib := m.fibs[fi]
		if fib != nil {
			fmt.Fprintf(w, "%12s%12d\n", ip.FibIndex(fi).Name(&m.Main), fib.Len())
		}
	}
	u := m.GetAdjacencyUsage()
	fmt.Fprintf(w, "Adjacencies: heap %d used, %d free\n", u.Used, u.Free)
	for i := range m.FibShowUsageHooks.hooks {
		m.FibShowUsageHooks.Get(i)(w)
	}
}

func (m *Main) showIfa(c cli.Commander, w cli.Writer, in *cli.Input) (err error) {
	intf := vnet.SiNil
	v := m.Vnet
	in.Parse("%v", &intf, v)
	v.ForeachSwIf(func(si vnet.Si) {
		if si != intf && intf != vnet.SiNil {
			return
		}
		var lines []string
		n := 0
		m.ForeachIfAddress(si, func(ia ip.IfAddr, ifa *ip.IfAddress) (err error) {
			lines = append(lines, fmt.Sprintf("%10v%v\n", "", ifa.Prefix.String()))
			n++
			return
		})
		for i, line := range lines {
			if i == 0 {
				fmt.Fprintf(w, "%10v%v", si.Name(v)+":", line)
			} else {
				fmt.Fprintf(w, "%10v%v", "", line)
			}
		}
		return
	})
	return
}

func (m *Main) cliInit(v *vnet.Vnet) {
	cmds := [...]cli.Command{
		cli.Command{
			Name:      "show ip fib",
			ShortHelp: "show ip4 forwarding table",
			Action:    m.showIpFib,
		},
		cli.Command{
			Name:      "clear ip fib",
			ShortHelp: "clear ip4 forwarding table statistics",
			Action:    m.clearIpFib,
		},
		cli.Command{
			Name:      "show ip addr",
			ShortHelp: "show interface addresses",
			Action:    m.showIfa,
		},
	}
	for i := range cmds {
		v.CliAdd(&cmds[i])
	}
}
