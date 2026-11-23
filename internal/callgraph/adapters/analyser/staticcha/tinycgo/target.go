package tinycgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright (c) 2018-2026 The TinyGo Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: TinyGo cgo transform, target definitions and type sizes
// SPDX-SnippetComment: Ported from github.com/tinygo-org/tinygo@v0.42.0, compileopts/target.go (TargetSpec, overrideProperties, resolveInherits) and compileopts/config.go (CFlags)

// TargetSpec is a TinyGo target definition, the fields of compileopts.TargetSpec
// as its JSON files spell them. Every field is kept, not only the ones the C
// flags read, because the merge refuses a duplicate in any slice.
type TargetSpec struct {
	Inherits         []string `json:"inherits,omitempty"`
	InheritableOnly  bool     `json:"inheritable-only"`
	Triple           string   `json:"llvm-target,omitempty"`
	CPU              string   `json:"cpu,omitempty"`
	ABI              string   `json:"target-abi,omitempty"`
	Features         string   `json:"features,omitempty"`
	GOOS             string   `json:"goos,omitempty"`
	GOARCH           string   `json:"goarch,omitempty"`
	SoftFloat        bool
	BuildTags        []string `json:"build-tags,omitempty"`
	BuildMode        string   `json:"buildmode,omitempty"`
	GC               string   `json:"gc,omitempty"`
	Scheduler        string   `json:"scheduler,omitempty"`
	Serial           string   `json:"serial,omitempty"`
	Linker           string   `json:"linker,omitempty"`
	LinkerFlavor     string   `json:"linker-flavor,omitempty"`
	RTLib            string   `json:"rtlib,omitempty"`
	Libc             string   `json:"libc,omitempty"`
	AutoStackSize    *bool    `json:"automatic-stack-size,omitempty"`
	DefaultStackSize uint64   `json:"default-stack-size,omitempty"`
	CFlags           []string `json:"cflags,omitempty"`
	LDFlags          []string `json:"ldflags,omitempty"`
	LinkerScript     string   `json:"linkerscript,omitempty"`
	ExtraFiles       []string `json:"extra-files,omitempty"`
	RP2040BootPatch  *bool    `json:"rp2040-boot-patch,omitempty"`
	BootPatches      []string `json:"boot-patches,omitempty"`
	Emulator         string   `json:"emulator,omitempty"`
	FlashCommand     string   `json:"flash-command,omitempty"`
	GDB              []string `json:"gdb,omitempty"`
	PortReset        string   `json:"flash-1200-bps-reset,omitempty"`
	SerialPort       []string `json:"serial-port,omitempty"`
	FlashMethod      string   `json:"flash-method,omitempty"`
	FlashVolume      []string `json:"msd-volume-name,omitempty"`
	FlashFilename    string   `json:"msd-firmware-name,omitempty"`
	UF2FamilyID      string   `json:"uf2-family-id,omitempty"`
	BinaryFormat     string   `json:"binary-format,omitempty"`
	OpenOCDInterface string   `json:"openocd-interface,omitempty"`
	OpenOCDTarget    string   `json:"openocd-target,omitempty"`
	OpenOCDTransport string   `json:"openocd-transport,omitempty"`
	OpenOCDCommands  []string `json:"openocd-commands,omitempty"`
	OpenOCDVerify    *bool    `json:"openocd-verify,omitempty"`
	JLinkDevice      string   `json:"jlink-device,omitempty"`
	ADBPreCommands   []string `json:"adb-pre-commands,omitempty"`
	ADBPushRemote    string   `json:"adb-push-remote,omitempty"`
	ADBPostCommands  []string `json:"adb-post-commands,omitempty"`
	ProbeRSChip      string   `json:"probe-rs-chip,omitempty"`
	CodeModel        string   `json:"code-model,omitempty"`
	RelocationModel  string   `json:"relocation-model,omitempty"`
	WITPackage       string   `json:"wit-package,omitempty"`
	WITWorld         string   `json:"wit-world,omitempty"`
}

// overrideProperties merges child into spec: strings, unsigned integers, bools
// and pointers override when set, slices append, and a duplicate value in a
// slice is an error.
func (spec *TargetSpec) overrideProperties(child *TargetSpec) error {
	specType := reflect.TypeFor[TargetSpec]()
	specValue := reflect.ValueOf(spec).Elem()
	childValue := reflect.ValueOf(child).Elem()

	for i := range specType.NumField() {
		field := specType.Field(i)
		src := childValue.Field(i)
		dst := specValue.Field(i)

		switch kind := field.Type.Kind(); kind {
		case reflect.String:
			if src.Len() > 0 {
				dst.Set(src)
			}
		case reflect.Uint, reflect.Uint32, reflect.Uint64:
			if src.Uint() != 0 {
				dst.Set(src)
			}
		case reflect.Bool:
			if src.Bool() {
				dst.Set(src)
			}
		case reflect.Pointer:
			if !src.IsNil() {
				dst.Set(src)
			}
		case reflect.Slice:
			dst.Set(reflect.AppendSlice(dst, src))
			for i := 0; i < dst.Len(); i++ {
				v := dst.Index(i).String()
				for j := i + 1; j < dst.Len(); j++ {
					if v == dst.Index(j).String() {
						return fmt.Errorf("duplicate value '%s' in field %s", v, field.Name)
					}
				}
			}
		default:
			return fmt.Errorf("unknown field type: %s", kind)
		}
	}
	return nil
}

// loadTargetFile reads one definition: a path when name ends in .json,
// otherwise <root>/targets/<name>.json.
func loadTargetFile(root, name string) (*TargetSpec, error) {
	path := name
	if !strings.HasSuffix(name, ".json") {
		path = filepath.Join(root, "targets", strings.ToLower(name)+".json")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a target definition under TINYGOROOT, or the path the declaration named
	if err != nil {
		return nil, fmt.Errorf("reading the target definition: %w", err)
	}
	spec := &TargetSpec{}
	if err := json.Unmarshal(raw, spec); err != nil {
		return nil, fmt.Errorf("reading the target definition %s: %w", path, err)
	}
	return spec, nil
}

// resolveInherits loads the inherited definitions, recursively, parents first
// in inherits order and then spec itself.
func (spec *TargetSpec) resolveInherits(root string) error {
	inheritableOnly := spec.InheritableOnly
	newSpec := &TargetSpec{}
	for _, name := range spec.Inherits {
		sub, err := loadTargetFile(root, name)
		if err != nil {
			return err
		}
		if err := sub.resolveInherits(root); err != nil {
			return err
		}
		if err := newSpec.overrideProperties(sub); err != nil {
			return err
		}
	}
	if err := newSpec.overrideProperties(spec); err != nil {
		return err
	}
	*spec = *newSpec
	spec.InheritableOnly = inheritableOnly
	return nil
}

// cFlags is the target part of the clang command, in TinyGo's order: the
// definition's cflags with {root} as TINYGOROOT, the libc's flags, the triple,
// the CPU flag as TinyGo spells it for the architecture, and the ABI when the
// chain names one. TinyGo's resource-dir, debug and optimisation flags are left
// out: clang's own builtin headers serve the libc's.
func cFlags(spec *TargetSpec, root, triple, goarch string, lc libcHeaders) []string {
	var cflags []string
	for _, flag := range spec.CFlags {
		cflags = append(cflags, strings.ReplaceAll(flag, "{root}", root))
	}
	cflags = append(cflags, lc.flags...)
	cflags = append(cflags, "--target="+triple)
	if spec.CPU != "" {
		switch {
		case goarch == "amd64" || goarch == "386":
			cflags = append(cflags, "-march="+spec.CPU)
		case strings.HasPrefix(triple, "avr"):
			cflags = append(cflags, "-mmcu="+spec.CPU)
		default:
			cflags = append(cflags, "-mcpu="+spec.CPU)
		}
	}
	if spec.ABI != "" {
		cflags = append(cflags, "-mabi="+spec.ABI)
	}
	return cflags
}

// SPDX-SnippetEnd

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright (c) 2018-2026 The TinyGo Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: TinyGo libc C flags and library cache paths
// SPDX-SnippetComment: Ported from github.com/tinygo-org/tinygo@v0.44.0, compileopts/config.go (libVersions, LibcNeedsMalloc, LibraryPath, CanonicalArchName, LibcCFlags) and goenv/goenv.go (GOCACHE); v0.43.0 is the same for every libc

// libcVersions are the libc entries of TinyGo's libVersions.
var libcVersions = map[string]int{
	"musl":     3,
	"picolibc": 2,
}

// libcHeaders is the libc part of TinyGo's C flags for one target.
type libcHeaders struct {
	// name is the target's libc, "" when it names none.
	name  string
	flags []string
	// cacheInclude is the include directory TinyGo builds into its cache for
	// this target, "" when the libc has none.
	cacheInclude string
}

// tinyGoCacheDir is where TinyGo keeps the libraries it builds.
func tinyGoCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("finding TinyGo's cache directory: %w", err)
	}
	return filepath.Join(dir, "tinygo"), nil
}

// libraryPath is the cache directory TinyGo builds the named libc into. The
// options are those a target alone selects: kanonarion passes no -gc or
// -trimpath, so neither does the tinygo build its remedy names.
func libraryPath(spec *TargetSpec, triple, cacheDir, name string) string {
	archname := triple
	if spec.CPU != "" {
		archname += "-" + spec.CPU
	}
	if spec.ABI != "" {
		archname += "-" + spec.ABI
	}
	if spec.SoftFloat {
		archname += "-softfloat"
	}
	if v, ok := libcVersions[name]; ok {
		archname += "-v" + strconv.Itoa(v)
	}
	options := ""
	if spec.GC == "boehm" && spec.Libc == "wasi-libc" {
		options += "+malloc"
	}
	return filepath.Join(cacheDir, name+options+"-"+archname)
}

// canonicalArchName folds arm*, thumb*, arm64 and mipsel as TinyGo does.
func canonicalArchName(triple string) string {
	arch, _, _ := strings.Cut(triple, "-")
	if arch == "arm64" {
		return "aarch64"
	}
	if strings.HasPrefix(arch, "arm") || strings.HasPrefix(arch, "thumb") {
		return "arm"
	}
	if arch == "mipsel" {
		return "mips"
	}
	return arch
}

// libcCFlags is TinyGo's LibcCFlags for spec. A libc TinyGo does not define is
// refused, where TinyGo panics.
func libcCFlags(spec *TargetSpec, root, triple, goarch, cacheDir string) (libcHeaders, error) {
	lc := libcHeaders{name: spec.Libc}
	switch spec.Libc {
	case "darwin-libSystem":
		lc.flags = []string{
			"-nostdlibinc",
			"-isystem", filepath.Join(root, "lib/macos-minimal-sdk/src/usr/include"),
		}
	case "picolibc":
		picolibcDir := filepath.Join(root, "lib", "picolibc", "libc")
		lc.cacheInclude = filepath.Join(libraryPath(spec, triple, cacheDir, "picolibc"), "include")
		lc.flags = []string{
			"-nostdlibinc",
			"-isystem", lc.cacheInclude,
			"-isystem", filepath.Join(picolibcDir, "include"),
			"-isystem", filepath.Join(picolibcDir, "stdio"),
			"-D__PICOLIBC_ERRNO_FUNCTION=__errno_location",
		}
	case "musl":
		arch := canonicalArchName(triple)
		lc.cacheInclude = filepath.Join(libraryPath(spec, triple, cacheDir, "musl"), "include")
		lc.flags = []string{
			"-nostdlibinc",
			"-isystem", lc.cacheInclude,
			"-isystem", filepath.Join(root, "lib", "musl", "arch", arch),
			"-isystem", filepath.Join(root, "lib", "musl", "arch", "generic"),
			"-isystem", filepath.Join(root, "lib", "musl", "include"),
		}
	case "wasi-libc":
		lc.cacheInclude = filepath.Join(libraryPath(spec, triple, cacheDir, "wasi-libc"), "include")
		lc.flags = []string{
			"-nostdlibinc",
			"-isystem", lc.cacheInclude,
		}
	case "wasmbuiltins", "":
		// No headers: the library is builtins only, or there is no libc.
	case "mingw-w64":
		lc.cacheInclude = filepath.Join(libraryPath(spec, triple, cacheDir, "mingw-w64"), "include")
		lc.flags = []string{
			"-nostdlibinc",
			"-isystem", lc.cacheInclude,
			"-isystem", filepath.Join(root, "lib", "mingw-w64", "mingw-w64-headers", "crt"),
			"-isystem", filepath.Join(root, "lib", "mingw-w64", "mingw-w64-headers", "include"),
			"-isystem", filepath.Join(root, "lib", "mingw-w64", "mingw-w64-headers", "defaults", "include"),
		}
		if goarch == "386" {
			lc.flags = append(lc.flags, "-D__MSVCRT_VERSION__=0x700", "-D_WIN32_WINNT=0x0501")
		} else {
			lc.flags = append(lc.flags, "-D_UCRT", "-D_WIN32_WINNT=0x0a00")
		}
	default:
		return libcHeaders{}, fmt.Errorf("the target names libc %q, which TinyGo does not define", spec.Libc)
	}
	return lc, nil
}

// SPDX-SnippetEnd

// LoadTarget reads target's definition chain from root. A target with no
// definition file, such as a bare LLVM triple, has an empty chain.
func LoadTarget(root, target string) (*TargetSpec, error) {
	spec, err := loadTargetFile(root, target)
	if errors.Is(err, fs.ErrNotExist) && !strings.HasSuffix(target, ".json") {
		return &TargetSpec{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := spec.resolveInherits(root); err != nil {
		return nil, fmt.Errorf("the target definition %s: %w", target, err)
	}
	return spec, nil
}
