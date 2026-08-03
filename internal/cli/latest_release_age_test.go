package cli

import (
	"encoding/json"
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

	if res.LatestReleaseAgeDays != 1272 {
		t.Errorf("latest_release_age_days = %d, want 1272: a current pin on a quiet project still has an old latest release",
			res.LatestReleaseAgeDays)
	}
}

// TestLatestJSON_OmitsTheAgeWithoutAPublicationDate keeps the field from
// answering a question the proxy never answered. A zero date reported as "0
// days" would read as "released today", which is the fabricated-date failure the
// omitzero on LatestDate already exists to prevent.
func TestLatestJSON_OmitsTheAgeWithoutAPublicationDate(t *testing.T) {
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
	if _, present := decoded["latest_release_age_days"]; present {
		t.Error("latest_release_age_days was emitted for a latest version with no publication date")
	}
	if _, present := decoded["latest_date"]; present {
		t.Error("latest_date was emitted for a latest version with no publication date")
	}
}

// TestAuditJSON_NamesTheAgeOfTheLatestRelease pins the same rename on the other
// surface. `audit --json` is the one an unattended agent consumes.
func TestAuditJSON_NamesTheAgeOfTheLatestRelease(t *testing.T) {
	res := auditModuleResult{
		Coordinate:           "google.golang.org/grpc@v1.61.1",
		LatestVersion:        "v1.83.0",
		LatestReleaseAgeDays: 2,
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
