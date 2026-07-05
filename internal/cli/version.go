package cli

import "runtime/debug"

// version is overridable at build time via
// -ldflags "-X github.com/eitanity/kanonarion/internal/cli.version=v1.2.3".
// When unset, it falls back to the VCS revision embedded by the Go
// toolchain (runtime/debug.ReadBuildInfo).
var version = ""

// resolveVersion returns the build version. Precedence: ldflags override,
// then the module version, then the embedded VCS revision, then "dev".
func resolveVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			rev := s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
			return "dev-" + rev
		}
	}
	return "dev"
}
