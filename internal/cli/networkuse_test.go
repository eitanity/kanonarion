package cli

import (
	"io"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The network property, declared per command and enumerated from the assembled
// cobra tree.
//
// Whether a command can open a socket decides what may be measured offline: a
// guard, a CI step or an air-gapped operator all have to ask it, and before
// this annotation existed they asked store-intent instead, which answers a
// different question. `fips`, `godebug` and `vendor` create the store root and
// scan the working tree — they were withheld from an offline measurement for a
// property they do not have — while `use` reads the store and copies bytes it
// already holds.
//
// The list is derived, never written: TestEveryCommandDeclaresItsNetworkUse
// walks the tree, so a command added next month is decided here rather than
// inheriting whichever value happened to be the default. That is the same
// discipline jsonStdoutCases is held to, and for the same reason — a
// hand-written roster silently misses the command added after it.

// TestEveryCommandDeclaresItsNetworkUse fails when a command in the tree
// declares no network use, declares one this build does not know, or declares
// `avoidable` without naming the flags that make it offline.
func TestEveryCommandDeclaresItsNetworkUse(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	byPath := commandsByPath(root)

	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	counts := map[string]int{}
	for _, p := range paths {
		cmd := byPath[p]
		use := networkUseOf(cmd)
		if use == "" {
			t.Errorf("command %q declares no %s: say whether it opens the network — %q, %q, or %q with the flags that make it offline",
				p, annotationNetworkUse, NetworkNever, NetworkAlways, NetworkAvoidable)
			continue
		}
		counts[use]++
		flags := offlineFlagsOf(cmd)
		if use != NetworkAvoidable {
			if len(flags) > 0 {
				t.Errorf("command %q declares %q and names offline flags %v: only %q has flags to name, "+
					"because only it reaches the network in the first place and offers a way not to",
					p, use, flags, NetworkAvoidable)
			}
			continue
		}
		if len(flags) == 0 {
			t.Errorf("command %q declares %q and names no offline flags: an avoidable reach nobody wrote the remedy for "+
				"is a claim no caller can act on — name them in %s", p, use, annotationOfflineFlags)
			continue
		}
		for _, f := range flags {
			if !strings.HasPrefix(f, "--") {
				t.Errorf("command %q names offline flag %q: write it as the caller types it, with the leading --", p, f)
				continue
			}
			if cmd.Flags().Lookup(strings.TrimPrefix(f, "--")) == nil {
				t.Errorf("command %q names offline flag %q, which it does not register: "+
					"the declaration has to name flags this command actually accepts, or a caller told to pass it gets \"unknown flag\"", p, f)
			}
		}
	}

	// A guard that measured nothing would pass silently, exactly as an empty
	// tree would.
	if len(paths) == 0 {
		t.Fatal("the tree yielded no commands; this test asserted nothing")
	}
	if counts[NetworkNever] == 0 {
		t.Error("no command declares never: the whole tree reaching the network is not a state this build is in, so the enumeration is broken")
	}
	t.Logf("%d command(s): never %d, avoidable %d, always %d",
		len(paths), counts[NetworkNever], counts[NetworkAvoidable], counts[NetworkAlways])
}

// TestNetworkUse_UndeclaredResolvesToNothing states the polarity. store-intent
// defaults to the refusing value because a store can be created by accident;
// network use has no safe default at all — "probably offline" is the guess that
// would put a command back in a hermetic fixture without a decision — so an
// undeclared or misdeclared command resolves to "" and the completeness test
// above fails on it.
func TestNetworkUse_UndeclaredResolvesToNothing(t *testing.T) {
	if got := networkUseOf(&cobra.Command{Use: "undeclared"}); got != "" {
		t.Errorf("a command with no annotation resolves to %q, want \"\": an undeclared command must be reported, not defaulted", got)
	}
	if got := networkUseOf(&cobra.Command{
		Use:         "misdeclared",
		Annotations: map[string]string{annotationNetworkUse: "sometimes"},
	}); got != "" {
		t.Errorf("a command with an unknown value resolves to %q, want \"\"", got)
	}
	if got := networkUseOf(nil); got != "" {
		t.Errorf("a nil command resolves to %q, want \"\"", got)
	}
}

// TestNetworkUse_IsNotStoreIntent is the reason this annotation exists, held as
// a measurement rather than a comment: the two properties disagree in both
// directions on this tree. If a later change made one derivable from the other,
// this fails and the annotation can be reconsidered — until then, deriving
// either from the other withholds commands from measurement, or admits ones
// that dial.
func TestNetworkUse_IsNotStoreIntent(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	byPath := commandsByPath(root)

	var createsButNeverDials, dialsButOnlyReads []string
	for p, cmd := range byPath {
		intent, use := cmd.Annotations[annotationStoreIntent], networkUseOf(cmd)
		if intent == StoreIntentCreate && use == NetworkNever {
			createsButNeverDials = append(createsButNeverDials, p)
		}
		if intent == StoreIntentRead && use != NetworkNever {
			dialsButOnlyReads = append(dialsButOnlyReads, p)
		}
	}
	sort.Strings(createsButNeverDials)
	if len(createsButNeverDials) == 0 {
		t.Error("no command creates the store and opens no network: if that is now true of the whole tree, " +
			"store-intent would answer the network question and this annotation would be redundant")
	}
	t.Logf("creates the store, opens no network: %v", createsButNeverDials)
	t.Logf("reads only, still reaches the network: %v", dialsButOnlyReads)
}

// TestOfflineRemedyNamesOnlyWhatTheCommandAccepts is the guard for the defect
// that produced this rendering: one shared string in the proxy adapter named
// --from-modcache to every command that built it, and `fetch` and `inspect` do
// not define it. An operator inside an air gap read the line that stopped the
// run, typed it, and got "unknown flag".
//
// It walks the tree rather than naming commands, so a command added later is
// held to the same rule, and it reads the flags out of the rendered text rather
// than out of the annotation: the annotation is already checked above, and what
// the operator is told is the text.
func TestOfflineRemedyNamesOnlyWhatTheCommandAccepts(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	byPath := commandsByPath(root)

	flagToken := regexp.MustCompile(`--[a-z0-9][a-z0-9-]*`)
	checked := 0
	for p, cmd := range byPath {
		remedy := renderOfflineRemedy(cmd)
		if remedy == "" {
			continue
		}
		checked++
		// Only the lead-in sentence is about this command. A named alternative
		// is a DIFFERENT command's invocation — that is what makes it an
		// alternative — so its flags belong to the command it names.
		lead, _, _ := strings.Cut(remedy, "\n")
		for _, f := range flagToken.FindAllString(lead, -1) {
			if cmd.Flags().Lookup(strings.TrimPrefix(f, "--")) == nil {
				t.Errorf("the offline remedy for %q names %q, which %q does not register: "+
					"an operator who runs the line that stopped them gets \"unknown flag\"", p, f, p)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no command rendered an offline remedy; this test asserted nothing")
	}
	t.Logf("%d command(s) render an offline remedy", checked)
}

// TestOfflineAlternativeResolvesAgainstTheCommandItNames is the other half of
// the remedy guard. The flag check above reads the lead-in sentence, which is
// about the command that was stopped; a declared alternative is a DIFFERENT
// command's invocation, and one nobody resolved is the same defect displaced by
// one command.
//
// `never` is refused outright: a command that opens no socket is not stopped by
// a no-network refusal, so an alternative on it names a remedy for a problem it
// does not have.
func TestOfflineAlternativeResolvesAgainstTheCommandItNames(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	checked := 0
	for p, cmd := range commandsByPath(root) {
		alt := offlineAlternativeOf(cmd)
		if alt == "" {
			continue
		}
		checked++
		if use := networkUseOf(cmd); use == NetworkNever {
			t.Errorf("command %q declares %q and names the offline alternative %q: it opens no socket, "+
				"so no no-network refusal is about it", p, use, alt)
		}
		if !strings.HasPrefix(alt, "kanonarion ") {
			t.Errorf("command %q names the offline alternative %q: write it as the caller types it, "+
				"a whole invocation starting `kanonarion`", p, alt)
			continue
		}
		// The alternative is checked against the command it names, which is the
		// half the flag guard above cannot do: those flags belong to a different
		// command, and an alternative nobody resolved is the same defect one
		// command further along.
		fields := strings.Fields(strings.TrimPrefix(alt, "kanonarion "))
		named, _, ferr := root.Find(fields[:1])
		if ferr != nil || named == root {
			t.Errorf("command %q names the offline alternative %q, whose command %q is not in this tree",
				p, alt, fields[0])
			continue
		}
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, "--") {
				continue
			}
			flag := strings.TrimPrefix(strings.SplitN(f, "=", 2)[0], "--")
			if named.Flags().Lookup(flag) == nil {
				t.Errorf("command %q names the offline alternative %q, but %q does not register --%s",
					p, alt, fields[0], flag)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no command names an offline alternative; this test asserted nothing")
	}
}

// TestRenderOfflineRemedy_UndeclaredNamesNothing: an undeclared or
// never-dialling command gets no remedy at all. The switch enumerates the
// values it means rather than negating one of them, so a value added later is
// unhandled visibly instead of inheriting whichever branch it fell into.
func TestRenderOfflineRemedy_UndeclaredNamesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"undeclared", &cobra.Command{Use: "u"}},
		{"unknown value", &cobra.Command{Use: "u", Annotations: map[string]string{annotationNetworkUse: "sometimes"}}},
		{"never", &cobra.Command{Use: "u", Annotations: map[string]string{annotationNetworkUse: NetworkNever}}},
		{"avoidable, no flags named", &cobra.Command{Use: "u", Annotations: map[string]string{annotationNetworkUse: NetworkAvoidable}}},
	} {
		if got := renderOfflineRemedy(tc.cmd); got != "" {
			t.Errorf("%s rendered %q, want no remedy: a remedy nobody declared is one nobody can run", tc.name, got)
		}
	}
}
