package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// vulndb.url takes only an https URL with a host. `config set` and the file
// refuse anything else at exit 20 in the same words, and a misspelt key is
// refused from both.
func TestVulnDBURL_Refusals(t *testing.T) {
	const want = `vulndb.url requires an https:// URL with a host (the base of a mirror of https://vuln.go.dev), got %q`
	for _, bad := range []string{"http://mirror.example.com", "ftp://mirror.example.com", "https://"} {
		root := t.TempDir()
		_, refusal, code := runCLIErr(t, "config", "set", "vulndb.url", bad, "--store-root", root)
		msg := strings.Replace(want, "%q", `"`+bad+`"`, 1)
		if code != ExitConfig || !strings.Contains(refusal, msg) {
			t.Errorf("config set vulndb.url %s: exit %d, refusal %s", bad, code, refusal)
		}
		root = writeStoreConfig(t, "version: \"3\"\nvulndb:\n  url: "+bad+"\n")
		_, refusal, code = runCLIErr(t, "vuln-snapshot-list", "--store-root", root)
		if code != ExitConfig || !strings.Contains(refusal, "config file "+filepath.Join(root, "config.yaml")+" was rejected: "+msg) {
			t.Errorf("file vulndb.url %s: exit %d, refusal %s", bad, code, refusal)
		}
	}

	root := t.TempDir()
	if _, refusal, code := runCLIErr(t, "config", "set", "vulndb.ulr", "https://mirror.example.com", "--store-root", root); code != ExitConfig || !strings.Contains(refusal, `unknown config key "vulndb.ulr"`) {
		t.Errorf("config set vulndb.ulr: exit %d, refusal %s", code, refusal)
	}
	misspelt := writeStoreConfig(t, "version: \"3\"\nvulndb:\n  ulr: https://mirror.example.com\n")
	if _, refusal, code := runCLIErr(t, "vuln-snapshot-list", "--store-root", misspelt); code != ExitConfig || !strings.Contains(refusal, `unknown key "vulndb.ulr" (did you mean "url"?)`) {
		t.Errorf("file vulndb.ulr: exit %d, refusal %s", code, refusal)
	}

}

// config show names the default, and config set, get and show --json carry a
// mirror once one is set.
func TestVulnDBURL_SetAndShow(t *testing.T) {
	root := t.TempDir()
	out, _, _ := runCLI(t, "config", "show", "--store-root", root)
	if !strings.Contains(out, "vulndb.url") || !strings.Contains(out, "(unset: https://vuln.go.dev)  (default)") {
		t.Errorf("config show does not name the default:\n%s", out)
	}
	if _, refusal, code := runCLIErr(t, "config", "set", "vulndb.url", "https://mirror.example.com/go", "--store-root", root); code != ExitOK {
		t.Fatalf("config set a valid mirror: exit %d, %s", code, refusal)
	}
	out, _, _ = runCLI(t, "config", "get", "vulndb.url", "--store-root", root)
	if strings.TrimSpace(out) != "https://mirror.example.com/go" {
		t.Errorf("config get vulndb.url = %q", out)
	}
	out, _, _ = runCLI(t, "config", "show", "--json", "--store-root", root)
	if !strings.Contains(out, `"vulndb": {`) || !strings.Contains(out, `"url": "https://mirror.example.com/go"`) {
		t.Errorf("config show --json does not carry the mirror:\n%s", out)
	}
}
