package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	proxyadapter "code.eitanity.com/kanonarion/internal/adapters/proxy/direct"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	vulnports "code.eitanity.com/kanonarion/internal/vuln/ports"
)

// An adapter's refusal names no flag; the command adds the flag only when it
// defines it, and leaves every other error alone.
func TestWithFlagRemedy_NamesTheFlagOnlyWhereTheCommandDefinesIt(t *testing.T) {
	t.Cleanup(func() { invokedCmd = nil })
	for _, tc := range []struct {
		name    string
		cmd     []string
		err     error
		want    string
		mustNot string
	}{
		{"plain HTTP on fetch", []string{"fetch"}, proxyadapter.ErrPlainHTTP, "pass --insecure", ""},
		{"plain HTTP on a command without --insecure", []string{"walk"}, proxyadapter.ErrPlainHTTP, "", "--insecure"},
		{"no git on walk", []string{"walk"}, fetchports.ErrVCSToolMissing, "pass --skip-vcs-verify", ""},
		{"no git on local", []string{"local"}, fetchports.ErrVCSToolMissing, "", "--skip-vcs-verify"},
		{"empty snapshot on vuln-scan", []string{"vuln-scan"}, vulnports.ErrSnapshotEmpty, "--fresh", ""},
		{"empty snapshot on the re-scan", []string{"vuln-scan-rescan"}, vulnports.ErrSnapshotEmpty, "", "--fresh"},
		{"an unrelated error", []string{"fetch"}, errors.New("unrelated"), "", "--"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, _, err := newRootCmd(io.Discard, io.Discard).Find(tc.cmd)
			if err != nil {
				t.Fatal(err)
			}
			invokedCmd = cmd
			wrapped := fmt.Errorf("context: %w", tc.err)
			got := withFlagRemedy(wrapped)
			if !errors.Is(got, tc.err) {
				t.Errorf("the refusal left the chain: %v", got)
			}
			if tc.want != "" && !strings.Contains(got.Error(), tc.want) {
				t.Errorf("got %q, want it to name %q", got, tc.want)
			}
			if tc.mustNot != "" && strings.Contains(got.Error(), tc.mustNot) {
				t.Errorf("got %q, which names %q the command does not define", got, tc.mustNot)
			}
		})
	}
	invokedCmd = nil
	if got := withFlagRemedy(proxyadapter.ErrPlainHTTP); got.Error() != proxyadapter.ErrPlainHTTP.Error() {
		t.Errorf("with no command resolved the refusal was changed: %v", got)
	}
}
