package domain

import (
	"slices"
	"strings"
)

// TinyGoSupply is which standard packages of a TinyGo build TinyGo supplies.
// The zero value is a build with no TinyGo frame.
type TinyGoSupply struct {
	TinyGo []string
}

// NoPackageNote is the reason a stdlib advisory naming no package is not
// established under a TinyGo frame.
const NoPackageNote = "the advisory names no package, so it cannot be told whether Go or TinyGo supplies the code"

// PartitionTinyGoFindings judges a TinyGo build's stdlib findings by who
// supplies the affected packages. Go's affected range describes Go's code, so a
// finding wholly about TinyGo's packages, or naming none, is not established; a
// mixed one is judged on Go's and names TinyGo's. Findings are copied, never
// written through.
func PartitionTinyGoFindings(findings []VulnerabilityFinding, s TinyGoSupply) []VulnerabilityFinding {
	if findings == nil {
		return nil
	}
	out := make([]VulnerabilityFinding, len(findings))
	for i, f := range findings {
		var tinygo, other []string
		for _, p := range f.AffectedPackages {
			if slices.Contains(s.TinyGo, p) {
				tinygo = append(tinygo, p)
			} else {
				other = append(other, p)
			}
		}
		switch {
		case len(f.AffectedPackages) == 0:
			notEstablished(&f, NoPackageNote)
		case len(other) == 0:
			notEstablished(&f, "TinyGo supplies "+strings.Join(tinygo, ", ")+"; Go's affected range describes Go's code")
		case len(tinygo) > 0:
			f.TinyGoNote = "judged on " + strings.Join(other, ", ") + ", which TinyGo does not supply; TinyGo supplies " +
				strings.Join(tinygo, ", ") + ", which Go's affected range does not describe"
		}
		out[i] = f
	}
	return out
}

// notEstablished withdraws a finding's reachability verdict, keeping its routes,
// as WithdrawSymbolLevelClaim does: an answer about code the build does not
// compile is no answer about the build.
func notEstablished(f *VulnerabilityFinding, note string) {
	f.NotEstablished = true
	f.TinyGoNote = note
	if f.Reachable == nil {
		return
	}
	r := *f.Reachable
	r.IsReachable = false
	r.Confidence = ConfidenceUnknown
	f.Reachable = &r
}
