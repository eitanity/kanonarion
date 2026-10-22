package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// Each module row says which repository directory its VCS leg hashed: the
// directory, "." for the root, or null where the record names none, as a
// record written before the field does. --detail prints the first two.
func TestGraphVerificationRows_CarryGitSubdir(t *testing.T) {
	nested := coordinatetest.MustNew("go.etcd.io/etcd/client/v3", "v3.6.14")
	root := coordinatetest.MustNew("github.com/google/uuid", "v1.6.0")
	preField := coordinatetest.MustNew("modernc.org/gc/v3", "v3.1.4")
	rec := func(subdir fetchdomain.RepoSubdir) fetchdomain.CompositeRecord {
		return fetchdomain.CompositeRecord{FactRecord: fetchdomain.FactRecord{
			VerificationStatus: string(fetchdomain.Verified), GitSubdir: subdir}}
	}
	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{
		nested:   rec("client/v3"),
		root:     rec(fetchdomain.RepoRoot),
		preField: rec(""),
	}}
	rows := graphVerificationRows(context.Background(), []walkdomain.GraphNode{
		{Coordinate: nested, ResolutionSource: walkdomain.ResolutionMVS},
		{Coordinate: root, ResolutionSource: walkdomain.ResolutionMVS},
		{Coordinate: preField, ResolutionSource: walkdomain.ResolutionMVS},
	}, records)

	var out bytes.Buffer
	if err := writeVerificationDetail(&out, rows); err != nil {
		t.Fatalf("writeVerificationDetail: %v", err)
	}
	text := out.String()
	if strings.Count(text, "git subdirectory:") != 2 ||
		!strings.Contains(text, "git subdirectory: client/v3") ||
		!strings.Contains(text, "git subdirectory: (repository root)") {
		t.Errorf("detail lines wrong:\n%s", text)
	}

	for i, want := range []string{`"git_subdir":"client/v3"`, `"git_subdir":"."`, `"git_subdir":null`} {
		data, err := json.Marshal(rows[i])
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("row %s JSON lacks %s: %s", rows[i].Coordinate, want, data)
		}
	}
}
