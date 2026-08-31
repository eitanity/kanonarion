package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
)

// A preference a config file can set has to be provable to change something a
// caller can see. Nothing proved that: every route from `preferences:` to the
// behaviour it governs was one deletable line, and the suite stayed green with
// preferences.log_level going nowhere at all.
//
// Each row below names one field of configdomain.Preferences and the observable
// difference setting it makes. The difference is measured twice — once with the
// key in the file, once without — and has to appear in exactly one arm, so a row
// cannot pass while the route it names is dead. The assertion is on what the
// run emitted, never on the resolved variable: reading logLevel back would pass
// with nothing consuming it, which is the hole this closes.
//
// No row types a flag. The flag path is a separate route and a row that used it
// would prove the wrong thing; flag-over-config is asserted separately below.

type preferenceRoute struct {
	// field is the configdomain.Preferences field this row proves. The
	// completeness test derives the required set from the struct by reflection,
	// so a field added later fails until somebody says what it changes.
	field string
	// key is the config key, for failure messages.
	key string
	// setting is the line written under `preferences:` to move the preference
	// off its built-in default.
	setting string
	// marker is the substring whose presence is the observable difference.
	marker string
	// markerWhenSet says which arm carries it: true when setting the preference
	// makes the marker appear, false when setting it takes the marker away.
	markerWhenSet bool
	// observe runs the invocation and returns the channel the marker lives on.
	observe func(t *testing.T, storeRoot string, args ...string) string
	// overrideArgs contradicts setting on the command line, and
	// markerWhenOverridden is what the output must then carry. Empty for a
	// preference no flag can contradict: --no-progress narrows
	// preferences.progress, it cannot reinstate it.
	overrideArgs         []string
	markerWhenOverridden bool
}

func preferenceRoutes() []preferenceRoute {
	return []preferenceRoute{
		{
			field:   "JSON",
			key:     "preferences.json",
			setting: "  json: true\n",
			// The document `config get` renders under --json. The text arm
			// prints the bare value and names no key at all.
			marker:               `"key": "preferences.log_level"`,
			markerWhenSet:        true,
			observe:              observeConfigGetStdout,
			overrideArgs:         []string{"--json=false"},
			markerWhenOverridden: false,
		},
		{
			field:   "LogLevel",
			key:     "preferences.log_level",
			setting: "  log_level: debug\n",
			// NewContainer logs the orphaned-temp sweep at DEBUG, which the
			// built-in warn suppresses. The line is the level being consumed:
			// it exists only because the resolved level reached a logger.
			marker:               "cleaned orphaned blob temp files",
			markerWhenSet:        true,
			observe:              observeContainerStderr,
			overrideArgs:         []string{"--log-level", "warn"},
			markerWhenOverridden: false,
		},
		{
			field:   "Progress",
			key:     "preferences.progress",
			setting: "  progress: false\n",
			marker:  "staleness progress: retrying example.com/mod",
			// Default true, so this is the arm where the preference takes the
			// narration away.
			markerWhenSet: false,
			observe:       observeStalenessNarration,
		},
	}
}

// observeConfigGetStdout returns the stdout of a command whose rendering the
// json preference governs.
func observeConfigGetStdout(t *testing.T, storeRoot string, args ...string) string {
	t.Helper()
	argv := append([]string{"config", "get", "preferences.log_level", "--store-root", storeRoot}, args...)
	stdout, stderr, code := runCLI(t, argv...)
	if code != ExitOK {
		t.Fatalf("config get exited %d, stderr: %s", code, stderr)
	}
	return stdout
}

// observeContainerStderr returns the stderr of a command that opens the store,
// with one orphaned blob temp file waiting to be swept so the DEBUG line the
// level governs has something to report. Any query command reaches it;
// sbom-list is the shortest.
func observeContainerStderr(t *testing.T, storeRoot string, args ...string) string {
	t.Helper()
	orphanBlobTemp(t, storeRoot)
	argv := append([]string{"sbom-list", "--store-root", storeRoot}, args...)
	stdout, stderr, code := runCLI(t, argv...)
	if code != ExitOK {
		t.Fatalf("sbom-list exited %d, stdout: %s stderr: %s", code, stdout, stderr)
	}
	return stderr
}

// observeStalenessNarration returns the stderr narration the progress
// preference governs, from a config read off disk by the loader the root
// command uses.
//
// It does not run a command, and that is measured rather than convenient. The
// preference gates three narrations: the walk and extract heartbeats, throttled
// to a 20s interval against time.Now, which no test can make emit; and the
// staleness retry line, which needs a proxy answering one empty 200. `audit` is
// the only command composing that line and it builds its proxy client with
// insecure=false, so an httptest server is refused ("uses plain HTTP") before
// the probe runs. What is left is the gate itself, driven from a real config
// file, writing the bytes an operator would read.
func observeStalenessNarration(t *testing.T, storeRoot string, _ ...string) string {
	t.Helper()
	cfg, err := loadStoreConfig(storeRoot)
	if err != nil {
		t.Fatalf("loading config from %s: %v", storeRoot, err)
	}
	var stderr strings.Builder
	// The call audit makes, minus the --no-progress flag no row types.
	reporter := newStalenessProgressReporter(&stderr, false, cfg, "warn")
	if reporter != nil {
		reporter.RetryingLookup("example.com/mod", 2, 4)
	}
	return stderr.String()
}

// orphanBlobTemp leaves one removable .tmp- file in the store's blob directory.
// The sweep removes it and reports the removal at DEBUG; an empty directory
// reports nothing, and the row would then measure silence against silence.
func orphanBlobTemp(t *testing.T, storeRoot string) {
	t.Helper()
	dir := filepath.Join(storeRoot, "blobs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating blobs dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tmp-orphan"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding orphaned temp: %v", err)
	}
}

// storeWithPreference seeds a store root whose config file carries exactly the
// given lines under `preferences:`.
func storeWithPreference(t *testing.T, setting string) string {
	t.Helper()
	root := t.TempDir()
	writeConfig(t, root, "version: \"1\"\npreferences:\n"+setting)
	return root
}

// TestPreferences_EverySettingChangesTheOutput is the contract: setting a
// preference in the config file, with no flag typed, changes what the run
// emits. The two arms differ in one line of config and nothing else.
func TestPreferences_EverySettingChangesTheOutput(t *testing.T) {
	for _, route := range preferenceRoutes() {
		t.Run(route.field, func(t *testing.T) {
			set := route.observe(t, storeWithPreference(t, route.setting))
			unset := route.observe(t, storeWithPreference(t, ""))

			inSet := strings.Contains(set, route.marker)
			inUnset := strings.Contains(unset, route.marker)
			if inSet == inUnset {
				t.Fatalf("%s changed nothing: %q is %s both arms, so the config route is not being read\n"+
					"with the key:\n%s\nwithout it:\n%s",
					route.key, route.marker, presenceWord(inSet), set, unset)
			}
			if inSet != route.markerWhenSet {
				t.Errorf("%s: %q is %s the arm that sets the key, want the other way round\n"+
					"with the key:\n%s\nwithout it:\n%s",
					route.key, route.marker, presenceWord(inSet), set, unset)
			}
		})
	}
}

// TestPreferences_FlagOverridesConfig states the other half of the documented
// precedence — flag > config > default. The config file asks for one thing and
// the flag contradicts it; the flag has to win. Nothing asserted this: the
// json routes are each measured on their own, and the log-level flag was never
// measured against a file that disagreed with it.
func TestPreferences_FlagOverridesConfig(t *testing.T) {
	for _, route := range preferenceRoutes() {
		if len(route.overrideArgs) == 0 {
			continue
		}
		t.Run(route.field, func(t *testing.T) {
			got := route.observe(t, storeWithPreference(t, route.setting), route.overrideArgs...)
			if in := strings.Contains(got, route.marker); in != route.markerWhenOverridden {
				t.Errorf("%s: %v did not override the config file; %q is %s the output:\n%s",
					route.key, route.overrideArgs, route.marker, presenceWord(in), got)
			}
		})
	}
}

func presenceWord(present bool) string {
	if present {
		return "in"
	}
	return "absent from"
}

// TestPreferences_EveryFieldHasARoute derives the required set from the struct
// rather than from a hand-written list. A preference added next month has no
// route asserted until somebody adds a row saying what it changes, which is the
// discipline whose absence let preferences.log_level go nowhere.
func TestPreferences_EveryFieldHasARoute(t *testing.T) {
	covered := make(map[string]bool)
	for _, route := range preferenceRoutes() {
		covered[route.field] = true
	}

	typ := reflect.TypeFor[configdomain.Preferences]()
	if typ.NumField() == 0 {
		t.Fatal("configdomain.Preferences has no fields: the guard would pass vacuously")
	}
	for field := range typ.Fields() {
		if !field.IsExported() {
			continue
		}
		if !covered[field.Name] {
			t.Errorf("configdomain.Preferences.%s has no row in preferenceRoutes(): "+
				"add one naming the observable difference setting it makes, so the "+
				"config route for it cannot be deleted with the suite green",
				field.Name)
		}
		delete(covered, field.Name)
	}
	for name := range covered {
		t.Errorf("preferenceRoutes() has a row for %q, which is not a field of "+
			"configdomain.Preferences; the row proves nothing", name)
	}
}
