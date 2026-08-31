package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config file that is valid YAML but that the typed load refuses is the case
// these tests pin. It used to be discarded in silence: every command ran on the
// built-in defaults, and `config show` printed the file's values as though they
// were in force. The licence policy is one of the things such a file sets, so
// the tool answered compliance questions under a policy the operator had not
// written and confirmed the wrong one when asked.
//
// The rule now: a file the operator wrote and the loader rejected is a refusal
// at ExitConfig, except for the commands that exist to see or repair the file.

// rejectedConfigYAML is valid YAML with one illegal value: "block" is not a
// policy outcome for a rule's default (allow, notify and warn are). It also
// sets preferences.log_level, so a reader can check which of the two values —
// the file's or the built-in — a command reports.
const rejectedConfigYAML = `version: "2"
preferences:
  log_level: debug
license_policy:
  rules:
    - scope: production
      allow: [permissive]
      default: block
`

// validConfigYAML is the control: the same document with a legal outcome.
const validConfigYAML = `version: "2"
preferences:
  log_level: debug
license_policy:
  rules:
    - scope: production
      allow: [permissive]
      default: warn
`

// storeWithConfig writes body to <tmp>/config.yaml and returns the store root.
func storeWithConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

// isolateInvocationState restores the process-wide state a Run leaves behind,
// so a test here cannot change what an unrelated test sees. Two of these tests
// resolve a config that sets preferences.json, and jsonOut survives the Run
// that set it — a sibling test reading the global then renders JSON where it
// expected text.
func isolateInvocationState(t *testing.T) {
	t.Helper()
	cfg, cfgErr, jsonWas, levelWas, rootWas := activeConfig, activeConfigErr, jsonOut, logLevel, storeRoot
	t.Cleanup(func() {
		activeConfig, activeConfigErr, jsonOut, logLevel, storeRoot = cfg, cfgErr, jsonWas, levelWas, rootWas
	})
}

// TestRejectedConfig_OrdinaryCommandRefusesAtExitConfig is the defect itself:
// an ordinary command must not run on built-in defaults while the operator
// believes their file is in force.
func TestRejectedConfig_OrdinaryCommandRefusesAtExitConfig(t *testing.T) {
	isolateInvocationState(t)
	root := storeWithConfig(t, rejectedConfigYAML)

	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk-list", "--store-root", root}, &stdout, &stderr)
	if err == nil {
		t.Fatal("a rejected config file was discarded in silence: the command exited 0")
	}
	if got := ExitCodeForError(err); got != ExitConfig {
		t.Errorf("exit code = %d, want ExitConfig(%d): %v", got, ExitConfig, err)
	}
	// The operator's next action is to edit one line, so the message has to
	// name both the file and the line the loader objected to.
	msg := err.Error()
	if !strings.Contains(msg, filepath.Join(root, "config.yaml")) {
		t.Errorf("refusal does not name the config file: %s", msg)
	}
	for _, want := range []string{`unknown policy outcome "block"`, `scope "production"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not carry %q: %s", want, msg)
		}
	}
}

// TestRejectedConfig_AbsentFileIsNotARejection is the constraint the refusal
// must not break: a store with no config.yaml runs the full built-in policy at
// exit 0. Most stores are in that state.
func TestRejectedConfig_AbsentFileIsNotARejection(t *testing.T) {
	isolateInvocationState(t)
	root := t.TempDir()

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"walk-list", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("a store with no config file must run: %v", err)
	}
	if activeConfigErr != nil {
		t.Errorf("absent config file recorded as a rejection: %v", activeConfigErr)
	}
	if strings.Contains(stderr.String(), "rejected") {
		t.Errorf("absent config file produced a rejection notice: %q", stderr.String())
	}
}

// TestRejectedConfig_ValidFileIsUnaffected is the second control: a file that
// loads keeps working, and its values are in force.
func TestRejectedConfig_ValidFileIsUnaffected(t *testing.T) {
	isolateInvocationState(t)
	root := storeWithConfig(t, validConfigYAML)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"config", "get", "preferences.log_level", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("valid config file refused: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "debug" {
		t.Errorf("log_level = %q, want the file's debug", got)
	}
	if strings.Contains(stderr.String(), "rejected") {
		t.Errorf("valid config file produced a rejection notice: %q", stderr.String())
	}
}

// TestRejectedConfig_RepairPathStaysUsable pins the exemption. Every command an
// operator needs in order to see the problem or fix it must still run against
// the rejected file — a refusal that makes a bad file unfixable by the tool
// that wrote it is a worse defect than the one being fixed.
func TestRejectedConfig_RepairPathStaysUsable(t *testing.T) {
	exempt := [][]string{
		{"config", "show"},
		{"config", "get", "preferences.log_level"},
		{"config", "init"},
		{"config", "set", "preferences.log_level", "info"},
		{"store", "config", "show"},
	}
	for _, args := range exempt {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			isolateInvocationState(t)
			root := storeWithConfig(t, rejectedConfigYAML)
			var stdout, stderr bytes.Buffer
			if err := Run(append(args, "--store-root", root), &stdout, &stderr); err != nil {
				t.Fatalf("refused, leaving the operator no way to see or fix the file: %v", err)
			}
			// Still usable is not the same as still honest: each of these says
			// on stderr that the file is not running.
			if !strings.Contains(stderr.String(), "was rejected") {
				t.Errorf("ran without stating the rejection; stderr = %q", stderr.String())
			}
		})
	}
}

// TestRejectedConfig_HelpAndVersionAnswer records that cobra resolves both
// before any PersistentPreRunE, so neither is gated on the config file and
// neither needs the exemption annotation.
func TestRejectedConfig_HelpAndVersionAnswer(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--version"}, {"walk-list", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			isolateInvocationState(t)
			root := storeWithConfig(t, rejectedConfigYAML)
			var stdout, stderr bytes.Buffer
			if err := Run(append([]string{"--store-root", root}, args...), &stdout, &stderr); err != nil {
				t.Fatalf("refused: %v", err)
			}
			if stdout.Len() == 0 {
				t.Error("no output")
			}
		})
	}
}

// TestRejectedConfig_ConfigShowStatesItIsNotInForce is the command whose whole
// job is answering "what is in force", and the one that used to lie: it printed
// the file's log_level: debug with no marker while warn was running.
func TestRejectedConfig_ConfigShowStatesItIsNotInForce(t *testing.T) {
	isolateInvocationState(t)
	root := storeWithConfig(t, rejectedConfigYAML)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"config", "show", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("config show refused: %v", err)
	}
	out := stdout.String()

	// It still shows the file — that is what the operator has to edit.
	if !strings.Contains(out, "default: block") {
		t.Error("config show no longer prints the file it is reporting on")
	}
	// And it says the file is not running, in the document itself, naming why.
	for _, want := range []string{"REJECTED", "NOT in force", `unknown policy outcome "block"`} {
		if !strings.Contains(out, want) {
			t.Errorf("config show does not carry %q:\n%s", want, out)
		}
	}
	// The value in force is the built-in, and it is marked as a built-in. The
	// missing (default) marker was the second half of the lie: it attributed
	// the built-in value to the operator's file.
	if !strings.Contains(out, "preferences.log_level") {
		t.Fatalf("no log_level line:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "preferences.log_level ") {
			continue
		}
		if !strings.Contains(line, "warn") {
			t.Errorf("log_level line reports a value that is not in force: %q", line)
		}
		if !strings.Contains(line, "(default)") {
			t.Errorf("log_level line credits the rejected file for a built-in value: %q", line)
		}
	}
}

// TestRejectedConfig_ConfigShowJSONMarksRejected covers the machine channel: a
// consumer branching only on config_file.present would read a rejected file's
// defaults as the operator's settings.
func TestRejectedConfig_ConfigShowJSONMarksRejected(t *testing.T) {
	isolateInvocationState(t)
	root := storeWithConfig(t, rejectedConfigYAML)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"config", "show", "--json", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("config show --json refused: %v", err)
	}
	var got struct {
		ConfigFile struct {
			Path            string `json:"path"`
			Present         bool   `json:"present"`
			Rejected        bool   `json:"rejected"`
			RejectionReason string `json:"rejection_reason"`
		} `json:"config_file"`
		Preferences struct {
			LogLevel string `json:"log_level"`
		} `json:"preferences"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not the JSON document: %v\n%s", err, stdout.String())
	}
	if !got.ConfigFile.Rejected {
		t.Error("config_file.rejected is false for a rejected file")
	}
	if !strings.Contains(got.ConfigFile.RejectionReason, "unknown policy outcome") {
		t.Errorf("config_file.rejection_reason does not say why: %q", got.ConfigFile.RejectionReason)
	}
	if got.Preferences.LogLevel != "warn" {
		t.Errorf("preferences.log_level = %q, want the built-in warn that is in force", got.Preferences.LogLevel)
	}
}

// TestRejectedConfig_ConfigSetRepairsAndOrdinaryCommandsResume is the round
// trip: the exemption is worth having only if it leads back to a working store.
func TestRejectedConfig_ConfigSetRepairsAndOrdinaryCommandsResume(t *testing.T) {
	isolateInvocationState(t)
	root := storeWithConfig(t, rejectedConfigYAML)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"walk-list", "--store-root", root}, &stdout, &stderr); err == nil {
		t.Fatal("precondition: the store must start out refused")
	}

	// The illegal value is a rule default, which config set does not address
	// by key; the operator edits that line. What config set must prove here is
	// that it reaches the file at all while the file is rejected.
	stdout.Reset()
	stderr.Reset()
	if err := Run([]string{"config", "set", "preferences.json", "true", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("config set could not touch a rejected file: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(root, "config.yaml")) // #nosec G304 -- t.TempDir path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fixed := strings.Replace(string(body), "default: block", "default: warn", 1)
	if fixed == string(body) {
		t.Fatalf("config set rewrote the offending line out of recognition:\n%s", body)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(fixed), 0o600); err != nil { // #nosec G703 -- t.TempDir path
		t.Fatalf("WriteFile: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if err := Run([]string{"walk-list", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("the repaired store is still refused: %v", err)
	}
	if activeConfigErr != nil {
		t.Errorf("repaired file still recorded as rejected: %v", activeConfigErr)
	}
	// And the repair took effect: config set's key is now in force. The key it
	// wrote was preferences.json, so `config get` answers with a document even
	// though no flag was typed — which is the preference doing its job, and the
	// value is read out of it rather than off the line.
	stdout.Reset()
	stderr.Reset()
	if err := Run([]string{"config", "get", "preferences.log_level", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("config get: %v", err)
	}
	var doc struct {
		Value  string `json:"value"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("config get answered %q, which does not parse: %v", stdout.String(), err)
	}
	if doc.Value != "debug" {
		t.Errorf("log_level = %q, want the repaired file's debug", doc.Value)
	}
	if doc.Source != configSourceFile {
		t.Errorf("source = %q, want %q: the repaired file is in force again", doc.Source, configSourceFile)
	}
}
