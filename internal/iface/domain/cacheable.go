package domain

import "github.com/eitanity/kanonarion/internal/gotoolchain"

// RecordIsCacheable reports whether a stored record may answer a later
// extraction without measuring again. A record carrying the analyser limit is
// never served, and nor is one with parse failures an older Go may have
// recorded: earlier builds filed a refusal of newer syntax as the module's own.
func RecordIsCacheable(r InterfaceRecord) bool {
	if r.AnalyserLimit != nil {
		return false
	}
	for _, p := range r.Packages {
		if len(p.ParseFailures) > 0 {
			return !gotoolchain.MayPredateThisGo(r.Toolchain)
		}
	}
	return true
}
