package domain

import (
	"regexp"
	"slices"
	"strings"
)

// TinyGoLibcAbsence is clang refusing a TinyGo cgo preamble while TinyGo had
// not built the target's libc on this host: the include directory TinyGo's
// flags name did not exist. The host limited the run, so the cause is the
// environment's.
type TinyGoLibcAbsence struct {
	// Libc and Target are TinyGo's names; Dir is the missing include directory.
	Libc, Target, Dir string
	// Packages are those whose preamble clang refused for it.
	Packages []string
}

// tinyGoLibcAbsenceClause is the loader's spelling of the refusal.
var tinyGoLibcAbsenceClause = regexp.MustCompile(`TinyGo has not built (\S+) for target (\S+) on this host: ` +
	`(.+?) does not exist, so clang could not read the preamble of (\S+) \(`)

// ReadTinyGoLibcAbsence reads the refusal out of a record's failure detail.
func ReadTinyGoLibcAbsence(detail string) (TinyGoLibcAbsence, bool) {
	var a TinyGoLibcAbsence
	for _, m := range tinyGoLibcAbsenceClause.FindAllStringSubmatch(detail, -1) {
		a.Libc, a.Target, a.Dir = m[1], m[2], m[3]
		if !slices.Contains(a.Packages, m[4]) {
			a.Packages = append(a.Packages, m[4])
		}
	}
	return a, len(a.Packages) > 0
}

// Statement says what this host lacked and that the source is not at fault.
func (a TinyGoLibcAbsence) Statement() string {
	return "TinyGo has not built " + a.Libc + " for target " + a.Target + " on this host, so clang read the preamble\n" +
		"  without its headers: " + a.Dir + " does not exist. The gap is in the environment, not in the source."
}

// Remedy is the build that makes TinyGo build the libc.
func (a TinyGoLibcAbsence) Remedy() string {
	return "Build any program for the target, which builds that libc, then re-analyse:\n" +
		"  tinygo build -target " + a.Target + " <any main package>"
}

// DroppedBy reports whether pkg's preamble was refused for the absence.
func (a TinyGoLibcAbsence) DroppedBy(pkg string) bool {
	return slices.Contains(a.Packages, pkg)
}

// DroppedReason says why a package's edges are missing.
func (a TinyGoLibcAbsence) DroppedReason() string {
	return "was not analysed: TinyGo has not built " + a.Libc + " for target " + a.Target + " on this host (" + a.Dir + " does not exist)"
}

// legacyPreambleRejection is clang's refusal as a 0.16.0 record written before
// the libc headers were passed spells it. Later records say which headers the
// preamble was read with, so this spelling marks a record to re-measure.
const legacyPreambleRejection = "clang rejected the preamble: "

// IsLegacyPreambleRejection reports whether detail quotes a preamble refusal
// made without TinyGo's libc headers.
func IsLegacyPreambleRejection(detail string) bool {
	return strings.Contains(detail, legacyPreambleRejection)
}
