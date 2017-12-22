// +build !go1.8

package main

import (
	"sort"
	"reflect"

	"github.com/subgraph/fw-daemon/sgfw"
)

// Copied from golang 1.8 sources
// START sort.SliceStable
type lessSwap struct {
	Less func(i, j int) bool
	Swap func(i, j int)
}

func SliceStable(slice interface{}, less func(i, j int) bool) {
	rv := reflect.ValueOf(slice)
	swap := reflect.Swapper(slice)
	stable_func(lessSwap{less, swap}, rv.Len())
}

func symMerge_func(data lessSwap, a, m, b int) {
	if m-a == 1 {
		i := m
		j := b
		for i < j {
			h := int(uint(i+j) >> 1)
			if data.Less(h, a) {
				i = h + 1
			} else {
				j = h
			}
		}
		for k := a; k < i-1; k++ {
			data.Swap(k, k+1)
		}
		return
	}
	if b-m == 1 {
		i := a
		j := m
		for i < j {
			h := int(uint(i+j) >> 1)
			if !data.Less(m, h) {
				i = h + 1
			} else {
				j = h
			}
		}
		for k := m; k > i; k-- {
			data.Swap(k, k-1)
		}
		return
	}
	mid := int(uint(a+b) >> 1)
	n := mid + m
	var start, r int
	if m > mid {
		start = n - b
		r = mid
	} else {
		start = a
		r = m
	}
	p := n - 1
	for start < r {
		c := int(uint(start+r) >> 1)
		if !data.Less(p-c, c) {
			start = c + 1
		} else {
			r = c
		}
	}
	end := n - start
	if start < m && m < end {
		rotate_func(data, start, m, end)
	}
	if a < start && start < mid {
		symMerge_func(data, a, start, mid)
	}
	if mid < end && end < b {
		symMerge_func(data, mid, end, b)
	}
}

func swapRange_func(data lessSwap, a, b, n int) {
	for i := 0; i < n; i++ {
		data.Swap(a+i, b+i)
	}
}

func rotate_func(data lessSwap, a, m, b int) {
	i := m - a
	j := b - m
	for i != j {
		if i > j {
			swapRange_func(data, m-i, m, j)
			i -= j
		} else {
			swapRange_func(data, m-i, m+j-i, i)
			j -= i
		}
	}
	swapRange_func(data, m-i, m, i)
}

func insertionSort_func(data lessSwap, a, b int) {
	for i := a + 1; i < b; i++ {
		for j := i; j > a && data.Less(j, j-1); j-- {
			data.Swap(j, j-1)
		}
	}
}

// Auto-generated variant of sort.go:stable
func stable_func(data lessSwap, n int) {
	blockSize := 20
	a, b := 0, blockSize
	for b <= n {
		insertionSort_func(data, a, b)
		a = b
		b += blockSize
	}
	insertionSort_func(data, a, n)
	for blockSize < n {
		a, b = 0, 2*blockSize
		for b <= n {
			symMerge_func(data, a, a+blockSize, b)
			a = b
			b += 2 * blockSize
		}
		if m := a + blockSize; m < n {
			symMerge_func(data, a, m, n)
		}
		blockSize *= 2
	}
}
// END sort.SliceStable


func (rl *ruleList) sortRules(rules []sgfw.DbusRule) []sgfw.DbusRule {
	SliceStable(rules, func(i, j int) bool {
		in := rules[i].Sandbox + rules[i].App + rules[i].Target
		jn := rules[j].Sandbox + rules[j].App + rules[j].Target
		order := []string{in,jn}
		sort.Strings(order)
		if rules[i].App == rules[j].App && rules[i].Sandbox == rules[j].Sandbox {
			if sgfw.RuleAction(rules[i].Verb) == sgfw.RULE_ACTION_DENY || sgfw.RuleAction(rules[j].Verb) == sgfw.RULE_ACTION_DENY {
				if rules[i].Verb != rules[j].Verb {
					return (sgfw.RuleAction(rules[i].Verb) == sgfw.RULE_ACTION_DENY)
				}
			}
		}
		return (order[0] == in)
	})
	return rules
}
