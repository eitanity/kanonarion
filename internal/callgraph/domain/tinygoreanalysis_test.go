package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// The TinyGo re-run is the plain re-run with --tinygo, for each coordinate kind.
func TestTinyGoReanalysisInstruction(t *testing.T) {
	t.Parallel()
	local, err := coordinate.NewLocalCoordinate("example.com/blinky")
	if err != nil {
		t.Fatal(err)
	}
	published, err := coordinate.NewModuleCoordinate("example.com/drivers", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		coord coordinate.ModuleCoordinate
		dir   string
		want  string
	}{
		{local, "/work/tree", "kanonarion local /work/tree --tinygo <target>"},
		{local, "", domain.UnnamedWorkingTreeLead + ", so run kanonarion local --tinygo <target> from inside it"},
		{published, "", "kanonarion fetch example.com/drivers@v1.0.0 && kanonarion callgraph example.com/drivers@v1.0.0 --tinygo <target>"},
	} {
		if got := domain.TinyGoReanalysisInstruction(tc.coord, tc.dir); got != tc.want {
			t.Errorf("TinyGoReanalysisInstruction(%s, %q) = %q, want %q", tc.coord, tc.dir, got, tc.want)
		}
	}
}
