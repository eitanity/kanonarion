//go:build unix

package childproc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
)

// A child killed mid-run cannot remove what it wrote, so the parent does: the
// child's temp root is the parent's, and it goes once the child has exited —
// read-only module-cache trees included.
func TestRunBounded_KilledChildLeavesNoTempDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// A failing run leaves a read-only tree that TempDir's own removal cannot.
	t.Cleanup(func() {
		if err := modcache.Remove(tmp); err != nil {
			t.Errorf("removing %s: %v", tmp, err)
		}
	})
	report := filepath.Join(t.TempDir(), "report")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := RunBounded(ctx, Bounds{}, "/bin/sh", "-c",
			`d=$(mktemp -d "$TMPDIR/kanonarion-cg-XXXXXX") && mkdir "$d/m" && touch "$d/m/f" && `+
				`chmod 444 "$d/m/f" && chmod 555 "$d/m" && echo "$TMPDIR $d" > `+report+`.part && `+
				`mv `+report+`.part `+report+` && sleep 30`)
		done <- err
	}()

	var fields []string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(report); err == nil { // #nosec G304 -- this test's own temp file
			fields = strings.Fields(string(b))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(fields) != 2 {
		cancel()
		<-done
		t.Fatalf("the child never reported its temp dir")
	}
	childTmp, childDir := fields[0], fields[1]
	if filepath.Dir(childTmp) != tmp || !strings.HasPrefix(filepath.Base(childTmp), ScratchPrefix) {
		t.Errorf("the child's TMPDIR is %s, want a %s* directory under %s", childTmp, ScratchPrefix, tmp)
	}

	cancel()
	if err := <-done; err == nil {
		t.Fatal("the child was not killed")
	}
	for _, p := range []string{childDir, childTmp} {
		if _, err := os.Stat(p); !os.IsNotExist(err) { // #nosec G703 -- paths the test's own child reported under its temp dir
			t.Errorf("%s survived its killed child (stat: %v)", p, err)
		}
	}
	if entries, err := os.ReadDir(tmp); err != nil || len(entries) != 0 {
		t.Errorf("the temp dir holds %d entries after the child was killed (read error: %v); want none", len(entries), err)
	}
}
