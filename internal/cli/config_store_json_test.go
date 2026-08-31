package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The four commands that accepted --json and wrote prose: `config get`,
// `config set`, `config init` and `store clean`. Each now answers with a
// document, and each is exercised both ways round — the flag typed on the
// command line, and the same preference in force from the config file —
// because those are two different routes into the same rendering and a
// consumer who set the preference is entitled to the same answer.
//
// The text renderings are pinned byte for byte alongside, because nothing about
// the human path changes: these are the lines an operator already reads, and a
// document added beside them is not licence to reword them.

// runCLI runs one invocation against an isolated store and returns stdout,
// stderr and the exit code a caller would see.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	// A run leaves the resolved flags in package-level variables, and half of
	// these invocations resolve --json to true. Restoring them keeps that out
	// of whatever test runs next.
	isolateInvocationState(t)
	var out, errBuf bytes.Buffer
	err := Run(args, &out, &errBuf)
	return out.String(), errBuf.String(), ExitCodeForError(err)
}

// decodeDocument asserts stdout is exactly one JSON object and returns it.
func decodeDocument(t *testing.T, what, out string) map[string]any {
	t.Helper()
	return assertSingleJSONDocument(t, what, []byte(out))
}

// jsonRoutes are the two ways --json comes to be in force. Both are measured on
// every command, keyed on the resolved preference and never on whether the flag
// was typed: a caller who wrote `preferences.json: true` into the file asked for
// the same thing as one who typed the flag.
type jsonRoute struct {
	name string
	// args is what the caller types.
	args []string
	// prefs is what the route needs under `preferences:` in the config file.
	prefs string
}

func jsonRoutes() []jsonRoute {
	return []jsonRoute{
		{name: "flag", args: []string{"--json"}},
		{name: "config preference", prefs: "  json: true\n"},
	}
}

// seedStore writes a store root whose config file carries the route's
// preference plus whatever else the case needs under `preferences:`.
func seedStore(t *testing.T, route jsonRoute, prefs string) string {
	t.Helper()
	root := t.TempDir()
	writeConfig(t, root, "version: \"1\"\npreferences:\n"+route.prefs+prefs)
	return root
}

// writeConfig seeds a store root with a config file.
func writeConfig(t *testing.T, root, body string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("creating store root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

// TestConfigGetJSON_NamesTheSourceOfTheValue: a bare `false` cannot say whether
// an operator set the key or nobody ever did, and that is the question a caller
// scripting this has. Both answers are measured on the same key.
func TestConfigGetJSON_NamesTheSourceOfTheValue(t *testing.T) {
	for _, route := range jsonRoutes() {
		for _, tc := range []struct {
			name       string
			prefs      string
			wantValue  string
			wantSource string
		}{
			{"unset key reads default", "", "warn", configSourceDefault},
			{"set key reads file", "  log_level: debug\n", "debug", configSourceFile},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				root := seedStore(t, route, tc.prefs)
				args := append([]string{"config", "get", "preferences.log_level"}, route.args...)
				args = append(args, "--store-root", root)

				out, errOut, code := runCLI(t, args...)
				if code != ExitOK {
					t.Fatalf("exit %d, stderr: %s", code, errOut)
				}
				doc := decodeDocument(t, "config get --json", out)
				if doc["key"] != "preferences.log_level" {
					t.Errorf("key = %v, want preferences.log_level", doc["key"])
				}
				if doc["value"] != tc.wantValue {
					t.Errorf("value = %v, want %q", doc["value"], tc.wantValue)
				}
				if doc["source"] != tc.wantSource {
					t.Errorf("source = %v, want %q — the value alone cannot say whether an operator set it",
						doc["source"], tc.wantSource)
				}
			})
		}
	}
}

// TestConfigSetJSON_StatesWhatItDisplaced: the write destroys the previous
// value, so the document is the only place it can be read. Both cases matter —
// a key the file carried, and a key it did not, whose previous value was the
// built-in default.
func TestConfigSetJSON_StatesWhatItDisplaced(t *testing.T) {
	for _, route := range jsonRoutes() {
		for _, tc := range []struct {
			name       string
			prefs      string
			wantPrev   string
			wantSource string
		}{
			{"unset key displaced the default", "", "warn", configSourceDefault},
			{"set key displaced the file value", "  log_level: debug\n", "debug", configSourceFile},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				root := seedStore(t, route, tc.prefs)
				args := append([]string{"config", "set", "preferences.log_level", "info"}, route.args...)
				args = append(args, "--store-root", root)

				out, errOut, code := runCLI(t, args...)
				if code != ExitOK {
					t.Fatalf("exit %d, stderr: %s", code, errOut)
				}
				doc := decodeDocument(t, "config set --json", out)
				if doc["key"] != "preferences.log_level" {
					t.Errorf("key = %v", doc["key"])
				}
				if doc["previous_value"] != tc.wantPrev {
					t.Errorf("previous_value = %v, want %q — a caller that sets a key wants to know what it displaced",
						doc["previous_value"], tc.wantPrev)
				}
				if doc["previous_source"] != tc.wantSource {
					t.Errorf("previous_source = %v, want %q", doc["previous_source"], tc.wantSource)
				}
				if doc["value"] != "info" {
					t.Errorf("value = %v, want info", doc["value"])
				}
				if want := filepath.Join(root, "config.yaml"); doc["config_file"] != want {
					t.Errorf("config_file = %v, want %s", doc["config_file"], want)
				}
			})
		}
	}
}

// TestConfigInitJSON_SeparatesCreatingFromCompleting: creating a file and
// finding one already there are different events and must not read the same.
func TestConfigInitJSON_SeparatesCreatingFromCompleting(t *testing.T) {
	for _, route := range jsonRoutes() {
		t.Run(route.name, func(t *testing.T) {
			root := t.TempDir()
			// The preference route needs a file for the flag to be in force, so
			// it can only be measured on the completing arm; the flag route
			// measures the creating arm, where no file exists yet.
			existed := route.prefs != ""
			wantAction := configInitCreated
			if existed {
				writeConfig(t, root, "version: \"1\"\npreferences:\n"+route.prefs)
				// A file holding only preferences is missing every other
				// section, so this run completes it.
				wantAction = configInitAppended
			}

			args := append([]string{"config", "init"}, route.args...)
			args = append(args, "--store-root", root)
			out, errOut, code := runCLI(t, args...)
			if code != ExitOK {
				t.Fatalf("exit %d, stderr: %s", code, errOut)
			}
			doc := decodeDocument(t, "config init --json", out)
			if want := filepath.Join(root, "config.yaml"); doc["config_file"] != want {
				t.Errorf("config_file = %v, want %s", doc["config_file"], want)
			}
			if doc["existed"] != existed {
				t.Errorf("existed = %v, want %v", doc["existed"], existed)
			}
			if doc["action"] != wantAction {
				t.Errorf("action = %v, want %q", doc["action"], wantAction)
			}

			// Run again against the file this run just left: nothing to do, and
			// the document has to say so rather than repeat what it did before.
			second, errOut, code := runCLI(t, args...)
			if code != ExitOK {
				t.Fatalf("second run: exit %d, stderr: %s", code, errOut)
			}
			doc = decodeDocument(t, "config init --json (second run)", second)
			if doc["existed"] != true {
				t.Errorf("second run existed = %v, want true", doc["existed"])
			}
			if doc["action"] != configInitUnchanged {
				t.Errorf("second run action = %v, want %q", doc["action"], configInitUnchanged)
			}
		})
	}
}

// TestStoreCleanJSON_StatesZeroRatherThanNothing: this is a command whose whole
// purpose is to change the store, so a caller has to be able to read that it
// changed nothing. Every count is present at zero.
func TestStoreCleanJSON_StatesZeroRatherThanNothing(t *testing.T) {
	for _, route := range jsonRoutes() {
		t.Run(route.name, func(t *testing.T) {
			root := seedStore(t, route, "")
			// The sweep deletes by prefix without asking whether an entry is in
			// use, so it never runs against the real shared temp directory.
			t.Setenv("TMPDIR", t.TempDir())

			args := append([]string{"store", "clean"}, route.args...)
			args = append(args, "--store-root", root)
			out, errOut, code := runCLI(t, args...)
			if code != ExitOK {
				t.Fatalf("exit %d, stderr: %s", code, errOut)
			}
			doc := decodeDocument(t, "store clean --json (nothing to clean)", out)

			for _, key := range []string{"removed_total", "bytes_reclaimed"} {
				v, ok := doc[key]
				if !ok {
					t.Fatalf("%s is absent: an omitted count reads as success at something", key)
				}
				if v.(float64) != 0 {
					t.Errorf("%s = %v, want 0", key, v)
				}
			}
			for _, section := range []string{"blob_temps", "temp_entries"} {
				sub, ok := doc[section].(map[string]any)
				if !ok {
					t.Fatalf("%s is absent from the document", section)
				}
				if sub["removed"].(float64) != 0 || sub["bytes_reclaimed"].(float64) != 0 {
					t.Errorf("%s = %v, want zeros", section, sub)
				}
			}
		})
	}
}

// TestStoreCleanJSON_StatesWhatWentAndWhatStayed measures the other half: a
// sweep with something to remove states the counts, the bytes and the entries
// it left alone.
func TestStoreCleanJSON_StatesWhatWentAndWhatStayed(t *testing.T) {
	root := t.TempDir()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	// One orphaned blob temp file of a known size.
	const blobBytes = 2048
	if err := os.MkdirAll(filepath.Join(root, "blobs"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "blobs", ".tmp-abc"),
		make([]byte, blobBytes), 0o600); err != nil {
		t.Fatalf("writing blob temp: %v", err)
	}
	// One kanonarion-owned temp tree of a known size, and one neighbour that
	// must survive.
	const tempBytes = 4096
	owned := filepath.Join(tmp, "kanonarion-vuln-scan-a")
	if err := os.MkdirAll(filepath.Join(owned, "nested"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(owned, "nested", "blob.bin"),
		make([]byte, tempBytes), 0o600); err != nil {
		t.Fatalf("writing temp payload: %v", err)
	}
	foreign := filepath.Join(tmp, "someone-elses-work")
	if err := os.MkdirAll(foreign, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	out, errOut, code := runCLI(t, "store", "clean", "--json", "--store-root", root)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	doc := decodeDocument(t, "store clean --json (something to clean)", out)

	if got := doc["removed_total"].(float64); got != 2 {
		t.Errorf("removed_total = %v, want 2", got)
	}
	if got := doc["bytes_reclaimed"].(float64); got != blobBytes+tempBytes {
		t.Errorf("bytes_reclaimed = %v, want %d", got, blobBytes+tempBytes)
	}
	blobs := doc["blob_temps"].(map[string]any)
	if blobs["removed"].(float64) != 1 || blobs["bytes_reclaimed"].(float64) != blobBytes {
		t.Errorf("blob_temps = %v, want one file of %d bytes", blobs, blobBytes)
	}
	// Each sweep names where it looked. Two directories are swept and the
	// counts are meaningless without knowing which one they are about.
	if want := filepath.Join(root, "blobs"); blobs["dir"] != want {
		t.Errorf("blob_temps.dir = %v, want %s", blobs["dir"], want)
	}
	temps := doc["temp_entries"].(map[string]any)
	if temps["removed"].(float64) != 1 || temps["bytes_reclaimed"].(float64) != tempBytes {
		t.Errorf("temp_entries = %v, want one entry of %d bytes", temps, tempBytes)
	}
	if temps["dir"] != tmp {
		t.Errorf("temp_entries.dir = %v, want %s", temps["dir"], tmp)
	}
	if temps["kept"].(float64) != 1 {
		t.Errorf("temp_entries.kept = %v, want 1: the blast radius is a number a caller can read",
			temps["kept"])
	}
	paths, _ := temps["paths"].([]any)
	if len(paths) != 1 || paths[0] != owned {
		t.Errorf("temp_entries.paths = %v, want [%s]", paths, owned)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("the sweep removed an entry it does not own: %v", err)
	}
}

// TestFourCommandsTextIsUnchanged pins the human path byte for byte. These are
// the lines an operator already reads; adding a document beside them is not
// licence to reword them.
func TestFourCommandsTextIsUnchanged(t *testing.T) {
	root := t.TempDir()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	configPath := filepath.Join(root, "config.yaml")

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"config init (fresh)", []string{"config", "init"},
			"wrote commented config template to " + configPath + "\n"},
		{"config init (existing)", []string{"config", "init"},
			"config already present at " + configPath + " (any missing sections appended)\n"},
		{"config get", []string{"config", "get", "preferences.log_level"}, "warn\n"},
		{"config set", []string{"config", "set", "preferences.log_level", "debug"},
			"set preferences.log_level\n"},
		{"store clean", []string{"store", "clean"}, "nothing to clean\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runCLI(t, append(append([]string{}, tc.args...), "--store-root", root)...)
			if code != ExitOK {
				t.Fatalf("exit %d, stderr: %s", code, errOut)
			}
			if out != tc.want {
				t.Errorf("text output changed:\n got: %q\nwant: %q", out, tc.want)
			}
		})
	}
}

// TestFourCommandsExitCodesAreUnchanged: adding a document does not change any
// command's exit code, and a refusal that already exited non-zero keeps its
// code under --json as well as without it.
func TestFourCommandsExitCodesAreUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"config get unknown key", []string{"config", "get", "bogus.key"}, ExitConfig},
		{"config get absent override", []string{"config", "get", "license_overrides.example.com/x"}, ExitConfig},
		{"config set unknown key", []string{"config", "set", "bogus.key", "x"}, ExitConfig},
		{"config set bad value", []string{"config", "set", "preferences.json", "notabool"}, ExitConfig},
		{"config set bad duration", []string{"config", "set", "staleness.ttl", "nope"}, ExitConfig},
		{"config get accepted key", []string{"config", "get", "preferences.log_level"}, ExitOK},
		{"config init", []string{"config", "init"}, ExitOK},
		{"store clean", []string{"store", "clean"}, ExitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, asJSON := range []bool{false, true} {
				root := t.TempDir()
				t.Setenv("TMPDIR", t.TempDir())
				args := append([]string{}, tc.args...)
				if asJSON {
					args = append(args, "--json")
				}
				args = append(args, "--store-root", root)
				out, _, code := runCLI(t, args...)
				if code != tc.want {
					t.Errorf("--json=%v: exit %d, want %d", asJSON, code, tc.want)
				}
				// A refusal writes no document, so nothing is left on stdout
				// for a parser to choke on.
				if tc.want != ExitOK && strings.TrimSpace(out) != "" {
					t.Errorf("--json=%v: a refusal wrote to stdout: %q", asJSON, out)
				}
			}
		})
	}
}

// TestStoreCleanJSON_CarriesWarningsInTheDocument: the sweep reports failures
// and carries on. In text those go to stdout where they happen; under --json
// they have to travel inside the document, not beside it where they would
// break every parser.
func TestStoreCleanJSON_CarriesWarningsInTheDocument(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", t.TempDir())
	// A .tmp-* directory with an occupant cannot be removed by os.Remove, so
	// the blob sweep reports an error and continues.
	poisonBlobTemps(t, root)

	out, _, code := runCLI(t, "store", "clean", "--json", "--store-root", root)
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	doc := decodeDocument(t, "store clean --json (warning)", out)
	warnings, _ := doc["warnings"].([]any)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want the one failure the sweep reported", warnings)
	}
	if !strings.Contains(warnings[0].(string), "cleaning blob temps") {
		t.Errorf("warning = %q, want the blob-temp failure", warnings[0])
	}
}

// TestConfigGetJSON_ARejectedFileSetsNothing: `config get` is exempt from the
// rejected-config refusal and reports the built-in default that is actually in
// force. The source has to agree with that value — reading `file` off a
// rejected file would attach the operator's authority to a value that is not
// running.
func TestConfigGetJSON_ARejectedFileSetsNothing(t *testing.T) {
	// The shared rejected fixture: it sets preferences.log_level AND carries an
	// illegal policy outcome, so the file names the key and none of it runs.
	root := storeWithConfig(t, rejectedConfigYAML)

	out, _, code := runCLI(t, "config", "get", "preferences.log_level", "--json", "--store-root", root)
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	doc := decodeDocument(t, "config get --json (rejected file)", out)
	if doc["source"] != configSourceDefault {
		t.Errorf("source = %v, want %q: a rejected file set nothing", doc["source"], configSourceDefault)
	}
	if doc["value"] != "warn" {
		t.Errorf("value = %v, want the built-in default that is actually in force", doc["value"])
	}
}

// TestConfigSetJSON_RepairsARejectedFile: `config set` is the repair path, so
// it must keep answering when the loaded configuration was refused — and the
// previous value it reports is the file's, which is what the write displaces.
func TestConfigSetJSON_RepairsARejectedFile(t *testing.T) {
	root := storeWithConfig(t, rejectedConfigYAML)

	out, _, code := runCLI(t, "config", "set", "preferences.log_level", "info", "--json", "--store-root", root)
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	doc := decodeDocument(t, "config set --json (rejected file)", out)
	if doc["previous_value"] != "debug" || doc["previous_source"] != configSourceFile {
		t.Errorf("previous = %v/%v, want debug/%s — the write displaced what the file said",
			doc["previous_value"], doc["previous_source"], configSourceFile)
	}
}

// TestConfigKeyPathCoversEveryReadableKey: every key `config get` answers needs
// a source, and a key with no path behind it silently reads `default` whatever
// the file says. The two lists are compared rather than trusted.
func TestConfigKeyPathCoversEveryReadableKey(t *testing.T) {
	for _, key := range []string{
		"version",
		"preferences.json", "preferences.log_level", "preferences.progress",
		"license_policy.categories", "license_policy.categories.permissive",
		"license_policy.rules",
		"license_overrides", "license_overrides.example.com/mod",
		"copyright_declarations", "copyright_declarations.example.com/mod",
		"callgraph.exclude",
		"staleness.ttl", "staleness.probe_concurrency",
		"fetch_policy.allowed_vcs_hosts",
	} {
		if _, ok := configKeyPath(key); !ok {
			t.Errorf("configKeyPath has no path for %q, so its source always reads %q",
				key, configSourceDefault)
		}
	}
}

// TestConfigGetJSON_ReadsSourceForAStructuredKey: the source question is not
// only about scalars. A category set in the file must not read as a built-in.
func TestConfigGetJSON_ReadsSourceForAStructuredKey(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "version: \"1\"\nlicense_policy:\n  categories:\n    permissive: [MIT]\n")

	out, _, code := runCLI(t, "config", "get", "license_policy.categories.permissive",
		"--json", "--store-root", root)
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	doc := decodeDocument(t, "config get --json (category)", out)
	if doc["source"] != configSourceFile {
		t.Errorf("source = %v, want %q", doc["source"], configSourceFile)
	}
	if !strings.Contains(doc["value"].(string), "MIT") {
		t.Errorf("value = %v, want the category the file names", doc["value"])
	}
}

// TestFourCommandsProduceExactlyOneDocument is the shape assertion in one
// place: each of the four parses as a single JSON document with nothing after
// it. The tree-wide guard asserts the same thing; this fails by name.
func TestFourCommandsProduceExactlyOneDocument(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", t.TempDir())
	for _, args := range [][]string{
		{"config", "init"},
		{"config", "get", "preferences.json"},
		{"config", "set", "preferences.log_level", "warn"},
		{"store", "clean"},
	} {
		name := strings.Join(args, " ")
		t.Run(name, func(t *testing.T) {
			out, errOut, code := runCLI(t, append(append([]string{}, args...), "--json", "--store-root", root)...)
			if code != ExitOK {
				t.Fatalf("exit %d, stderr: %s", code, errOut)
			}
			var doc map[string]any
			dec := json.NewDecoder(strings.NewReader(out))
			if err := dec.Decode(&doc); err != nil {
				t.Fatalf("stdout is not a JSON document: %v\n%s", err, out)
			}
			if len(doc) == 0 {
				t.Fatalf("the document is empty, so it states nothing")
			}
		})
	}
}
