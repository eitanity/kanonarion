package versionorder_test

import (
	"sort"
	"testing"

	"github.com/eitanity/kanonarion/internal/versionorder"
)

// Every trap the text idiom falls into. Each pair is one where "a < b" as a
// string says the opposite of what the numbers say, or where the input is not a
// number at all.
func TestComparePipelineVersions(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b string
		want int
	}{
		{"v9 is older than v10", "v9", "v10", -1},
		{"v9 is older than v19", "v9", "v19", -1},
		{"v19 is newer than v2", "v19", "v2", 1},
		{"v99 is older than v100", "v99", "v100", -1},
		{"v22 is newer than v9", "v22", "v9", 1},
		{"equal", "v19", "v19", 0},
		{"dotted minor inverts too", "0.9.0", "0.10.0", -1},
		{"dotted patch", "0.4.1", "0.4.0", 1},
		{"absent components are zero", "0.4", "0.4.0", 0},
		{"leading zeros are not width", "v007", "v7", 0},
		{"the shapes are read as the numbers they state", "v4", "0.4.0", 1},
		{"malformed ranks below valid", "", "v1", -1},
		{"valid ranks above malformed", "v1", "", 1},
		{"two malformed compare equal", "draft", "wip", 0},
		{"a bare v states no number", "v", "v0", -1},
		{"an empty component is not a number", "0..1", "0.0.1", -1},
		{"a non-digit component is not a number", "v1.x", "v1.0", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionorder.ComparePipelineVersions(tc.a, tc.b); got != tc.want {
				t.Errorf("ComparePipelineVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			// The comparison is antisymmetric, or a sort using it is undefined.
			if got := versionorder.ComparePipelineVersions(tc.b, tc.a); got != -tc.want {
				t.Errorf("ComparePipelineVersions(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

// A malformed version never wins a newest-wins selection: a value that cannot
// state its generation must not be served as the newest one.
func TestComparePipelineVersions_MalformedNeverWinsNewest(t *testing.T) {
	versions := []string{"v9", "", "v24", "not-a-version", "v19"}
	newest := versions[0]
	for _, v := range versions[1:] {
		if versionorder.ComparePipelineVersions(v, newest) > 0 {
			newest = v
		}
	}
	if newest != "v24" {
		t.Errorf("newest = %q, want v24", newest)
	}
}

func TestCompareModuleVersions(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b string
		want int
	}{
		{"v9 before v10", "v9.0.0", "v10.0.0", -1},
		{"patch", "v1.2.10", "v1.2.9", 1},
		{"prerelease sorts before its release", "v1.0.0-rc.1", "v1.0.0", -1},
		{"build metadata does not order", "v1.0.0+incompatible", "v1.0.0+incompatible", 0},
		{"a pseudo-version is semver", "v0.0.0-20211217152057-87afa9aa2ca8", "v0.1.0", -1},
		{"equal", "v1.0.0", "v1.0.0", 0},
		{"invalid ranks below valid", "main", "v0.0.1", -1},
		{"two invalid fall back to text", "aaa", "bbb", -1},
		{"two invalid that are equal", "@local", "@local", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionorder.CompareModuleVersions(tc.a, tc.b); got != tc.want {
				t.Errorf("CompareModuleVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if got := versionorder.CompareModuleVersions(tc.b, tc.a); got != -tc.want {
				t.Errorf("CompareModuleVersions(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

// The headline symptom, as a listing: several versions of one module present in
// semantic order, not in text order.
func TestCompareModuleVersions_ListingOrder(t *testing.T) {
	got := []string{"v10.0.0", "v9.0.0", "v2.0.0", "v10.0.1", "v1.0.0"}
	sort.SliceStable(got, func(i, j int) bool {
		return versionorder.CompareModuleVersions(got[i], got[j]) < 0
	})
	want := []string{"v1.0.0", "v2.0.0", "v9.0.0", "v10.0.0", "v10.0.1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted = %v, want %v", got, want)
		}
	}
}
