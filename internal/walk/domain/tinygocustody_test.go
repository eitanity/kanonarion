package domain_test

import (
	"bytes"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate"
	domain3 "code.eitanity.com/kanonarion/internal/walk/domain"
)

const (
	tinygoModule = "github.com/tinygo-org/tinygo@v0.42.0"
	tinygoAsset  = "tinygo0.42.0.linux-amd64.tar.gz"
	sumA         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sumB         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sumX         = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

var tinygoMeasuredAt = time.Date(2026, 10, 23, 2, 23, 15, 390878071, time.UTC)

// custodyInput is an install of two module-anchored files and one generated
// file the module zip lacks, every byte as released.
func custodyInput() domain3.TinyGoCustodyInput {
	return domain3.TinyGoCustodyInput{
		Module:             tinygoModule,
		ModuleVerification: "Verified",
		ModuleFiles:        map[string]string{"machine/machine.go": sumA, "runtime/gc.go": sumB},
		Files: []domain3.TinyGoSourceFile{
			{Path: "runtime/gc.go", SHA256: sumB},
			{Path: "device/rp/rp2040.go", SHA256: sumA},
			{Path: "machine/machine.go", SHA256: sumA},
		},
	}
}

func matchedRelease() *domain3.TinyGoRelease {
	return &domain3.TinyGoRelease{
		Asset: tinygoAsset, PublishedDigest: sumX, ObservedDigest: sumX,
		Outcome: domain3.TinyGoReleaseDigestMatched, MeasuredAt: tinygoMeasuredAt,
		Manifest: map[string]string{"device/rp/rp2040.go": sumA, "machine/machine.go": sumA, "runtime/gc.go": sumB},
	}
}

func TestClassifyTinyGoCustody(t *testing.T) {
	notEst := func(reason string) []domain3.TinyGoFileNotEstablished {
		return []domain3.TinyGoFileNotEstablished{{Path: "device/rp/rp2040.go", Reason: reason}}
	}
	for name, tc := range map[string]struct {
		change         func(*domain3.TinyGoCustodyInput)
		module, rel    int
		differs        []domain3.TinyGoFileDiffers
		notEstablished []domain3.TinyGoFileNotEstablished
		outcome        domain3.TinyGoReleaseOutcome
	}{
		"identical install": {
			change: func(*domain3.TinyGoCustodyInput) {}, module: 2, rel: 1, outcome: domain3.TinyGoReleaseDigestMatched,
		},
		"a module-anchored file altered": {
			change: func(in *domain3.TinyGoCustodyInput) { in.Files[2].SHA256 = sumB },
			module: 1, rel: 1, outcome: domain3.TinyGoReleaseDigestMatched,
			differs: []domain3.TinyGoFileDiffers{{Path: "machine/machine.go", Anchor: domain3.TinyGoAnchorModule}},
		},
		"a release-anchored file altered": {
			change: func(in *domain3.TinyGoCustodyInput) { in.Files[1].SHA256 = sumB },
			module: 2, outcome: domain3.TinyGoReleaseDigestMatched,
			differs: []domain3.TinyGoFileDiffers{{Path: "device/rp/rp2040.go", Anchor: domain3.TinyGoAnchorRelease}},
		},
		"digest mismatch": {
			change: func(in *domain3.TinyGoCustodyInput) {
				in.Release.Outcome, in.Release.ObservedDigest, in.Release.Manifest = domain3.TinyGoReleaseDigestMismatch, sumB, nil
			},
			module: 2, outcome: domain3.TinyGoReleaseDigestMismatch,
			notEstablished: notEst("the release archive " + tinygoAsset + " did not match its published digest (published " + sumX + ", observed " + sumB + ")"),
		},
		"no digest published": {
			change: func(in *domain3.TinyGoCustodyInput) {
				in.Release = &domain3.TinyGoRelease{Asset: tinygoAsset, Outcome: domain3.TinyGoReleaseNoDigest, Reason: "no digest for it"}
			},
			module: 2, outcome: domain3.TinyGoReleaseNoDigest, notEstablished: notEst("no digest for it"),
		},
		"asset absent": {
			change: func(in *domain3.TinyGoCustodyInput) {
				in.Release = &domain3.TinyGoRelease{Asset: tinygoAsset, Outcome: domain3.TinyGoReleaseAssetAbsent, Reason: "no such asset"}
			},
			module: 2, outcome: domain3.TinyGoReleaseAssetAbsent, notEstablished: notEst("no such asset"),
		},
		"offline with no held measurement": {
			change: func(in *domain3.TinyGoCustodyInput) {
				in.Release = &domain3.TinyGoRelease{Asset: tinygoAsset, Outcome: domain3.TinyGoReleaseUnavailable, Reason: "release archive unavailable offline"}
			},
			module: 2, outcome: domain3.TinyGoReleaseUnavailable, notEstablished: notEst("release archive unavailable offline"),
		},
		"an outcome without a reason still says which": {
			change: func(in *domain3.TinyGoCustodyInput) {
				in.Release = &domain3.TinyGoRelease{Asset: tinygoAsset, Outcome: domain3.TinyGoReleaseUnavailable}
			},
			module: 2, outcome: domain3.TinyGoReleaseUnavailable, notEstablished: notEst("the release archive " + tinygoAsset + ": unavailable"),
		},
		"a file in neither anchor": {
			change: func(in *domain3.TinyGoCustodyInput) { delete(in.Release.Manifest, "device/rp/rp2040.go") },
			module: 2, outcome: domain3.TinyGoReleaseDigestMatched,
			notEstablished: notEst("absent from both the module zip and the release archive " + tinygoAsset),
		},
		"no release consulted": {
			change: func(in *domain3.TinyGoCustodyInput) { in.Release = nil },
			module: 2, notEstablished: notEst("absent from the module zip and no release archive was consulted"),
		},
		"an unverified module zip vouches for nothing": {
			change: func(in *domain3.TinyGoCustodyInput) { in.ModuleVerification = "Unverified" },
			rel:    1, outcome: domain3.TinyGoReleaseDigestMatched,
			notEstablished: []domain3.TinyGoFileNotEstablished{
				{Path: "machine/machine.go", Reason: `the module zip ` + tinygoModule + ` is not verified (status "Unverified")`},
				{Path: "runtime/gc.go", Reason: `the module zip ` + tinygoModule + ` is not verified (status "Unverified")`},
			},
		},
		"a module zip that could not be read": {
			change: func(in *domain3.TinyGoCustodyInput) {
				in.ModuleVerification, in.ModuleFiles, in.ModuleFailure, in.Release = "", nil, "offline", nil
			},
			notEstablished: []domain3.TinyGoFileNotEstablished{
				{Path: "device/rp/rp2040.go", Reason: "the module zip " + tinygoModule + " could not be read: offline"},
				{Path: "machine/machine.go", Reason: "the module zip " + tinygoModule + " could not be read: offline"},
				{Path: "runtime/gc.go", Reason: "the module zip " + tinygoModule + " could not be read: offline"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := custodyInput()
			in.Release = matchedRelease()
			tc.change(&in)
			got := domain3.ClassifyTinyGoCustody(in)
			if got.VerifiedByModule != tc.module || got.VerifiedByRelease != tc.rel {
				t.Errorf("verified by module %d, by release %d; want %d, %d", got.VerifiedByModule, got.VerifiedByRelease, tc.module, tc.rel)
			}
			if !reflect.DeepEqual(got.Differs, tc.differs) {
				t.Errorf("differs = %+v, want %+v", got.Differs, tc.differs)
			}
			if !reflect.DeepEqual(got.NotEstablished, tc.notEstablished) {
				t.Errorf("not established = %+v, want %+v", got.NotEstablished, tc.notEstablished)
			}
			if got.ReleaseOutcome != tc.outcome || got.Compiled() != 3 || got.Module != tinygoModule {
				t.Errorf("custody = %+v", got)
			}
		})
	}
}

func TestTinyGoCustodyInput_AbsentFromModule(t *testing.T) {
	got := custodyInput().AbsentFromModule()
	if len(got) != 1 || got[0].Path != "device/rp/rp2040.go" {
		t.Errorf("absent = %+v, want the generated file alone", got)
	}
}

func TestTinyGoCustody_Statement(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*domain3.TinyGoCustodyInput)
		want   []string
	}{
		"matched": {func(*domain3.TinyGoCustodyInput) {}, []string{
			"2 of 3 compiled TinyGo file(s) match the module zip " + tinygoModule + " (fetch verification Verified)",
			"1 match the release archive " + tinygoAsset + ", whose bytes matched the SHA-256 GitHub publishes for it",
			"0 differ from their anchor", "0 not established",
		}},
		"mismatch": {func(in *domain3.TinyGoCustodyInput) {
			in.Release.Outcome, in.Release.Manifest = domain3.TinyGoReleaseDigestMismatch, nil
		}, []string{"did NOT match the SHA-256 GitHub publishes", "1 not established"}},
		"unmeasured": {func(in *domain3.TinyGoCustodyInput) {
			in.Release = &domain3.TinyGoRelease{Asset: tinygoAsset, Outcome: domain3.TinyGoReleaseAssetAbsent}
		}, []string{"no file was checked against the release archive " + tinygoAsset + " (asset_absent)"}},
		"no release": {func(in *domain3.TinyGoCustodyInput) {
			in.ModuleVerification, in.ModuleFailure, in.Release = "", "gone", nil
		}, []string{"(the module zip could not be read)", "no release archive was consulted", "3 not established"}},
	} {
		t.Run(name, func(t *testing.T) {
			in := custodyInput()
			in.Release = matchedRelease()
			tc.change(&in)
			got := domain3.ClassifyTinyGoCustody(in).Statement()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("statement %q lacks %q", got, w)
				}
			}
		})
	}
}

func TestTinyGoCustody_GroupsForSurfaces(t *testing.T) {
	c := domain3.TinyGoCustody{
		Differs: []domain3.TinyGoFileDiffers{
			{Path: "z.go", Anchor: domain3.TinyGoAnchorModule}, {Path: "a.go", Anchor: domain3.TinyGoAnchorModule},
			{Path: "g.go", Anchor: domain3.TinyGoAnchorRelease},
		},
		NotEstablished: []domain3.TinyGoFileNotEstablished{{Path: "b", Reason: "r2"}, {Path: "c", Reason: "r1"}, {Path: "a", Reason: "r2"}},
	}
	if got := c.DiffersFrom(domain3.TinyGoAnchorModule); !reflect.DeepEqual(got, []string{"a.go", "z.go"}) {
		t.Errorf("DiffersFrom(module) = %v", got)
	}
	reasons, by := c.NotEstablishedByReason()
	if !reflect.DeepEqual(reasons, []string{"r1", "r2"}) || !reflect.DeepEqual(by["r2"], []string{"a", "b"}) {
		t.Errorf("NotEstablishedByReason = %v %v", reasons, by)
	}
}

func tinyGoCustodyRecord(t *testing.T, custody *domain3.TinyGoCustody) domain3.WalkRecord {
	t.Helper()
	rec := makeTiedWalkRecord()
	node := rec.Graph.Nodes[1]
	node.Coordinate = mustCoord("github.com/tinygo-org/tinygo", "v0.42.0")
	node.ResolutionSource = domain3.ResolutionTinyGo
	node.OriginalCoordinate = coordinate.ModuleCoordinate{}
	node.TinyGo = &domain3.TinyGoFacts{Target: "pico", Packages: []string{"machine"}, Custody: custody}
	rec.Graph.Nodes = append(rec.Graph.Nodes, node)
	return rec
}

func TestWalkRecordHasher_TinyGoCustodyRoundTrip(t *testing.T) {
	in := custodyInput()
	in.Release = matchedRelease()
	in.Files[2].SHA256 = sumB
	in.Files = append(in.Files, domain3.TinyGoSourceFile{Path: "x.c", SHA256: sumA})
	in.Release.Manifest["x.c"] = sumB
	custody := domain3.ClassifyTinyGoCustody(in)
	custody.NotEstablished = append(custody.NotEstablished, domain3.TinyGoFileNotEstablished{Path: "y.S", Reason: "r"})

	h := domain3.WalkRecordHasher{}
	rec, err := h.SetContentHash(tinyGoCustodyRecord(t, &custody))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"release_measured_at":"2026-10-23T02:23:15.390878071Z"`)) {
		t.Errorf("the measurement time is not in the record:\n%s", data)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var got *domain3.TinyGoCustody
	for _, n := range back.Graph.Nodes {
		if n.TinyGo != nil {
			got = n.TinyGo.Custody
		}
	}
	if got == nil || !reflect.DeepEqual(*got, custody) {
		t.Errorf("custody after round trip = %+v, want %+v", got, custody)
	}
	if verr := h.VerifyContentHash(back); verr != nil {
		t.Errorf("a walk with custody does not verify after a round trip: %v", verr)
	}
}

// TestWalkRecordHasher_TinyGoCustodyIsHashTransparentWhenAbsent: a TinyGo walk
// without custody marshals with no custody key, so records written before it
// keep their seal; one with custody, even an empty one, names the key.
func TestWalkRecordHasher_TinyGoCustodyIsHashTransparentWhenAbsent(t *testing.T) {
	h := domain3.WalkRecordHasher{}
	bare, err := h.Marshal(tinyGoCustodyRecord(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bare, []byte(`"custody"`)) {
		t.Errorf("a TinyGo walk without custody marshals a custody key:\n%s", bare)
	}
	empty, err := h.Marshal(tinyGoCustodyRecord(t, &domain3.TinyGoCustody{Module: tinygoModule}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(empty, []byte(`"custody":{"differs":[],"module":"`+tinygoModule+`","module_verification":"","not_established":[],"verified_by_module":0,"verified_by_release":0}`)) {
		t.Errorf("custody without a release does not marshal in canonical form:\n%s", empty)
	}
}

// TestTinyGoCustody_ContentHashIsIndependentOfInputOrder: lists whose entries
// tie on path seal the same in any input order.
func TestTinyGoCustody_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	var want string
	h := domain3.WalkRecordHasher{}
	for i := range determinismShuffles {
		c := domain3.TinyGoCustody{
			Module: tinygoModule,
			Differs: []domain3.TinyGoFileDiffers{
				{Path: "a.go", Anchor: domain3.TinyGoAnchorRelease}, {Path: "a.go", Anchor: domain3.TinyGoAnchorModule}, {Path: "b.go"},
			},
			NotEstablished: []domain3.TinyGoFileNotEstablished{{Path: "a", Reason: "y"}, {Path: "a", Reason: "x"}, {Path: "b", Reason: "x"}},
		}
		rng := rand.New(rand.NewSource(int64(i))) /* #nosec G404 -- a reproducible shuffle is the guard's evidence */
		rng.Shuffle(len(c.Differs), func(a, b int) { c.Differs[a], c.Differs[b] = c.Differs[b], c.Differs[a] })
		rng.Shuffle(len(c.NotEstablished), func(a, b int) { c.NotEstablished[a], c.NotEstablished[b] = c.NotEstablished[b], c.NotEstablished[a] })
		sealed, err := h.SetContentHash(tinyGoCustodyRecord(t, &c))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			want = sealed.ContentHash
		} else if sealed.ContentHash != want {
			t.Fatalf("shuffle %d sealed %s, shuffle 0 %s", i, sealed.ContentHash, want)
		}
	}
}

func TestWalkRecordHasher_RefusesAnUnreadableMeasurementTime(t *testing.T) {
	c := domain3.TinyGoCustody{Module: tinygoModule, ReleaseAsset: tinygoAsset, ReleaseMeasuredAt: tinygoMeasuredAt}
	h := domain3.WalkRecordHasher{}
	data, err := h.Marshal(tinyGoCustodyRecord(t, &c))
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(data, []byte("2026-10-23T02:23:15.390878071Z"), []byte("yesterday"), 1)
	if _, err := h.Unmarshal(bad); err == nil || !strings.Contains(err.Error(), "TinyGo release measurement time") {
		t.Errorf("Unmarshal err = %v, want the measurement time refused", err)
	}
}

// TestWalkRecordHasher_TinyGoCustodyStatesEachReasonOnce: a reason shared by
// many files is written once, with its paths sorted, and reads back per file.
func TestWalkRecordHasher_TinyGoCustodyStatesEachReasonOnce(t *testing.T) {
	const shared = "the module zip could not be read: no go.sum entry"
	c := domain3.TinyGoCustody{Module: tinygoModule, NotEstablished: []domain3.TinyGoFileNotEstablished{
		{Path: "z.go", Reason: shared}, {Path: "b.S", Reason: "release archive unavailable offline"}, {Path: "a.go", Reason: shared},
	}}
	h := domain3.WalkRecordHasher{}
	data, err := h.Marshal(tinyGoCustodyRecord(t, &c))
	if err != nil {
		t.Fatal(err)
	}
	want := `"not_established":[{"paths":["b.S"],"reason":"release archive unavailable offline"},{"paths":["a.go","z.go"],"reason":"` + shared + `"}]`
	if !bytes.Contains(data, []byte(want)) || bytes.Count(data, []byte(shared)) != 1 {
		t.Errorf("not established is not grouped by reason, want %s in:\n%s", want, data)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range back.Graph.Nodes {
		if n.TinyGo != nil {
			got := n.TinyGo.Custody.NotEstablished
			if len(got) != 3 || got[0].Path != "a.go" || got[0].Reason != shared || got[1].Path != "b.S" {
				t.Errorf("read back = %+v", got)
			}
		}
	}
}
