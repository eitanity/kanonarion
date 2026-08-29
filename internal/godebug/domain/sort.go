package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// SettingLess is the canonical ordering for Setting slices: where the setting
// was read from, then what it says.
//
// It was keyed on source, line, name and value. Those do not identify a
// setting: the module it belongs to, whether it applies to this build and the
// tier it was classified at were all invisible to the comparator, and two
// settings agreeing on the first four keys were left to the sort. Every field
// the type carries is keyed here, so two distinct settings always have a
// defined order.
func SettingLess(a, b Setting) bool {
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Value != b.Value {
		return a.Value < b.Value
	}
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Applied != b.Applied {
		return !a.Applied
	}
	if a.Tier != b.Tier {
		return a.Tier < b.Tier
	}
	if a.PolicyOutcome != b.PolicyOutcome {
		return a.PolicyOutcome < b.PolicyOutcome
	}
	if a.PolicyBlocking != b.PolicyBlocking {
		return !a.PolicyBlocking
	}
	return false
}

// Sort orders settings by SettingLess. Output must be in a canonical order
// before hashing or serialising, and the comparator is a total order, so the
// result is a function of the set and not of the order the files were read in.
func Sort(ss []Setting) {
	sort.Slice(ss, func(i, j int) bool { return SettingLess(ss[i], ss[j]) })
}

// Hash returns a deterministic content hash of the sorted setting set. The
// caller must Sort first; Hash does not re-sort so the hash reflects exactly
// what is serialised.
func Hash(ss []Setting) string {
	var b strings.Builder
	for _, s := range ss {
		fmt.Fprintf(&b, "%s|%s|%s|%d|%s|%t|%s\n",
			s.Name, s.Value, s.Source, s.Line, s.Module,
			s.Applied, s.Tier)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
