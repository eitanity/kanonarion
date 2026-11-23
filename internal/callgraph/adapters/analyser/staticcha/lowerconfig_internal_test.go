package staticcha

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
)

// Recover support is the unwind tag's from 0.43.0, which supports recover on
// wasm under asyncify; a release with no such tag keeps the triple's answer.
func TestLowerConfig_ReadsTheUnwindTag(t *testing.T) {
	for _, tc := range []struct {
		triple  string
		tags    []string
		unwind  string
		recover bool
	}{
		{"wasm32-unknown-wasi", []string{"scheduler.asyncify", "tinygo.unwind.asyncify"}, "asyncify", true},
		{"wasm32-unknown-wasi", []string{"scheduler.none", "tinygo.unwind.none"}, "none", false},
		{"xtensa-esp32-none-elf", []string{"scheduler.tasks", "tinygo.unwind.setjmp"}, "setjmp", true},
		{"wasm32-unknown-wasi", []string{"scheduler.asyncify"}, "", false},
		{"xtensa-esp32-none-elf", []string{"scheduler.tasks"}, "", false},
		{"thumbv6m-unknown-unknown-eabi", []string{"scheduler.tasks"}, "", true},
	} {
		goroot, root := t.TempDir(), t.TempDir()
		for _, d := range []string{goroot, root} {
			if err := os.Mkdir(filepath.Join(d, "src"), 0o750); err != nil {
				t.Fatal(err)
			}
		}
		f, err := goenv.NewTinyGo("t", "0.44.0", "go1.27.4", "linux", "arm", "6", goroot, root, tc.triple, tc.tags)
		if err != nil {
			t.Fatal(err)
		}
		cfg := New("0.0.0-test", "", slog.Default()).WithTinyGo(f).lowerConfig()
		if cfg.Unwind != tc.unwind || cfg.Recover != tc.recover {
			t.Errorf("%s %v: unwind %q recover %v, want %q %v", tc.triple, tc.tags, cfg.Unwind, cfg.Recover, tc.unwind, tc.recover)
		}
	}
}
