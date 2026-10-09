package domain

import "github.com/eitanity/kanonarion/internal/gotoolchain"

// RecordIsCacheable reports whether a stored record may answer a later
// extraction without measuring again, given the module's go directive ("" when
// unknown). A record carrying the analyser limit is never served. Nor is one
// with parse failures the oldest build that writes this record could have met
// as a limit: earlier builds filed a refusal of newer syntax as the module's
// own, and the record names no toolchain to rule that out.
func RecordIsCacheable(r ExampleRecord, goDirective, oldestWriterGo string) bool {
	if r.AnalyserLimit != nil {
		return false
	}
	return len(r.ParseFailures) == 0 || !gotoolchain.DirectiveNewerThan(goDirective, oldestWriterGo)
}
