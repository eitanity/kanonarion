package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
)

// answerWithLatest builds a staleness answer whose latest version shipped
// publishedDaysAgo days ago.
func answerWithLatest(latest string, publishedDaysAgo int) staleapp.Answer {
	return staleapp.Answer{Record: staledomain.Record{
		LatestVersion:     latest,
		LatestPublishedAt: time.Now().Add(-time.Duration(publishedDaysAgo) * 24 * time.Hour),
	}}
}

// TestLatestJSON_NamesTheAgeOfTheLatestRelease is the correction. The number is
// the age of the newest release; under the old `days_behind` key an
// eighteen-month-old pin on an actively released module reported a SMALLER
// figure than a current pin on a quiet one, which inverts the order a reader
// sorting by it expects.
func TestLatestJSON_NamesTheAgeOfTheLatestRelease(t *testing.T) {
	// An old pin on an active module: the pin is far behind, but the latest
	// release is two days old, and two is what the field means.
	var res latestResult
	res.Module = "google.golang.org/grpc"
	res.Pinned = "v1.61.1"
	res.IsLatest = measuredIsLatest(false)
	res.applyStaleness(answerWithLatest("v1.83.0", 2))

	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling: %v", uerr)
	}

	if _, present := decoded["days_behind"]; present {
		t.Error("days_behind is still emitted; the value is not the distance from the pin, and no ledger records the pin's publication date")
	}
	age, present := decoded["latest_release_age_days"]
	if !present {
		t.Fatal("latest_release_age_days is absent for a module whose latest release has a publication date")
	}
	if got := int(age.(float64)); got != 2 {
		t.Errorf("latest_release_age_days = %d, want 2 (the age of v1.83.0, not the distance from v1.61.1)", got)
	}
}

// TestLatestJSON_ReportsTheReleaseAgeForACurrentPin pins the field's meaning
// against the other reading. A module AT its latest still has a latest release
// with an age; suppressing it would make one key mean two different things
// depending on the row.
func TestLatestJSON_ReportsTheReleaseAgeForACurrentPin(t *testing.T) {
	var res latestResult
	res.Module = "github.com/joho/godotenv"
	res.Pinned = "v1.5.1"
	res.IsLatest = measuredIsLatest(true)
	res.applyStaleness(answerWithLatest("v1.5.1", 1272))

	if res.LatestReleaseAgeDays == nil {
		t.Fatal("latest_release_age_days is null for a latest release that has a publication date")
	}
	if *res.LatestReleaseAgeDays != 1272 {
		t.Errorf("latest_release_age_days = %d, want 1272: a current pin on a quiet project still has an old latest release",
			*res.LatestReleaseAgeDays)
	}
}

// TestLatestJSON_NullsTheAgeWithoutAPublicationDate keeps the field from
// answering a question the proxy never answered. A zero date reported as "0
// days" would read as "released today", which is the fabricated-date failure the
// omitzero on LatestDate already exists to prevent.
//
// The key is PRESENT and null rather than absent: null is the answer "no date
// was supplied", and it has to be distinguishable from the 0 that a release
// shipped today genuinely produces. See the zero-age test below, which is the
// pair to this one.
func TestLatestJSON_NullsTheAgeWithoutAPublicationDate(t *testing.T) {
	var res latestResult
	res.Module = "example.com/mod"
	res.Pinned = "v1.0.0"
	res.applyStaleness(staleapp.Answer{Record: staledomain.Record{LatestVersion: "v1.1.0"}})

	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling: %v", uerr)
	}
	age, present := decoded["latest_release_age_days"]
	if !present {
		t.Fatal("latest_release_age_days is absent; a consumer cannot tell an unknown date from a build that does not derive the field")
	}
	if age != nil {
		t.Errorf("latest_release_age_days = %v for a latest version with no publication date, want null", age)
	}
	if _, present := decoded["latest_date"]; present {
		t.Error("latest_date was emitted for a latest version with no publication date")
	}
}

// TestLatestJSON_KeepsAZeroAgeForAReleaseShippedToday is the pair to the test
// above, and the hole this file used to have: every fixture here had a non-zero
// age, so `omitempty` erasing the zero went unmeasured.
//
// A release that shipped today is nought days old. That is the field's most
// meaningful value on a row that IS behind and IS offering a target — "the fix
// landed today" — and it was silently dropped, leaving it indistinguishable
// from a release whose publication date is unknown.
func TestLatestJSON_KeepsAZeroAgeForAReleaseShippedToday(t *testing.T) {
	var res latestResult
	res.Module = "golang.org/x/mod"
	res.Pinned = "v0.37.0"
	res.IsLatest = measuredIsLatest(false)
	res.PinAheadOfLatest = measuredIsLatest(false)
	// Published a few hours ago: under a day, so the age is genuinely 0.
	res.applyStaleness(staleapp.Answer{Record: staledomain.Record{
		LatestVersion:     "v0.40.0",
		LatestPublishedAt: time.Now().Add(-5 * time.Hour),
	}})

	if res.LatestReleaseAgeDays == nil {
		t.Fatal("latest_release_age_days is null for a release published five hours ago")
	}
	if *res.LatestReleaseAgeDays != 0 {
		t.Fatalf("fixture is not exercising the zero: age = %d", *res.LatestReleaseAgeDays)
	}

	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling: %v", uerr)
	}
	age, present := decoded["latest_release_age_days"]
	if !present {
		t.Fatal("latest_release_age_days is absent for a release shipped today")
	}
	if age == nil {
		t.Fatal("latest_release_age_days is null for a release shipped today; null means the date is unknown")
	}
	if got := int(age.(float64)); got != 0 {
		t.Errorf("latest_release_age_days = %d, want 0", got)
	}

	// The text surface says the same thing rather than falling through to the
	// no-date rendering.
	var out bytes.Buffer
	if perr := printLatestTable(&out, []latestResult{res}); perr != nil {
		t.Fatalf("printLatestTable: %v", perr)
	}
	if !strings.Contains(out.String(), "latest: v0.40.0 (released today)") {
		t.Errorf("text does not state the release shipped today:\n%s", out.String())
	}
}

// TestAuditJSON_NamesTheAgeOfTheLatestRelease pins the same rename on the other
// surface. `audit --json` is the one an unattended agent consumes.
func TestAuditJSON_NamesTheAgeOfTheLatestRelease(t *testing.T) {
	res := auditModuleResult{
		Coordinate:           "google.golang.org/grpc@v1.61.1",
		LatestVersion:        "v1.83.0",
		LatestReleaseAgeDays: measuredAgeDays(2),
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling: %v", uerr)
	}
	if _, present := decoded["days_behind"]; present {
		t.Error("audit --json still emits days_behind")
	}
	if got, present := decoded["latest_release_age_days"]; !present {
		t.Error("audit --json does not emit latest_release_age_days")
	} else if int(got.(float64)) != 2 {
		t.Errorf("latest_release_age_days = %v, want 2", got)
	}
}

// TestStalenessJSON_NoOmitemptyWhereZeroIsAnAnswer is a structural guard, not a
// behavioural one.
//
// `omitempty` erases a zero, and for these fields zero is a real answer: a
// release that shipped today is nought days old, and "not ahead of the latest
// tag" is a measurement. Both were erased, which made a meaningful value
// indistinguishable from a field the build does not derive at all — twice, in
// this batch, in the same shape. This test fails the moment the tag comes back,
// which a behavioural test cannot do: reverting these fields to their old
// declaration does not compile against the rest of the suite, so the assertion
// that would catch the regression has to be about the declaration itself.
func TestStalenessJSON_NoOmitemptyWhereZeroIsAnAnswer(t *testing.T) {
	guarded := map[reflect.Type][]string{
		reflect.TypeOf(latestResult{}):      {"LatestReleaseAgeDays", "PinAheadOfLatest", "IsLatest"},
		reflect.TypeOf(auditModuleResult{}): {"LatestReleaseAgeDays", "PinAheadOfLatest", "IsLatest"},
		reflect.TypeOf(stalenessInfo{}):     {"DaysSince", "PinAheadOfLatest", "IsLatest"},
	}
	for typ, names := range guarded {
		for _, name := range names {
			field, ok := typ.FieldByName(name)
			if !ok {
				t.Errorf("%s has no field %s", typ.Name(), name)
				continue
			}
			tag := field.Tag.Get("json")
			if strings.Contains(tag, "omitempty") {
				t.Errorf("%s.%s carries omitempty (%q); its zero is an answer and would be erased",
					typ.Name(), name, tag)
			}
			// A pointer is what lets "no answer" be said without borrowing the
			// zero to say it.
			if field.Type.Kind() != reflect.Pointer {
				t.Errorf("%s.%s is %s, not a pointer; there is no way to distinguish an unanswered row from a zero",
					typ.Name(), name, field.Type)
			}
		}
	}
}
