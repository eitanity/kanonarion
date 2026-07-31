package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// The tests in this file pin the refusals and tie-breaks that the fetch domain
// reaches only on inputs a healthy pipeline does not produce: a hash column that
// cannot be parsed, a composite envelope that cannot be read back, and the rungs
// of the serving order that only two otherwise-identical measurements ever
// consult. They live in the internal test package because two of them drive the
// canonicalMarshal seam, which is the only way to make the never-silent marshal
// guards answer.

var gapCoord = coordinatetest.MustNew("example.com/mod", "v1.0.0")

// gapAt is a whole-second measurement time. Whole seconds matter: canonicalTime
// renders sub-second values in a wider format, and UnmarshalComposite reads the
// record's own fetched_at back with time.RFC3339.
func gapAt(day int) time.Time { return time.Date(2026, 3, day, 9, 0, 0, 0, time.UTC) }

// gapRecord seals a record built from the invariant fields every persisted
// record carries plus whatever the caller states. It does not go through
// fetchtest: this is the in-package test binary, and fetchtest imports the
// package under test.
func gapRecord(t *testing.T, mutate func(*FactRecord)) FactRecord {
	t.Helper()
	r := FactRecord{SchemaVersion: SchemaVersion, Ecosystem: EcosystemGo}
	mutate(&r)
	sealed, err := (CanonicalHasher{}).SetContentHash(r)
	if err != nil {
		t.Fatalf("sealing fixture record: %v", err)
	}
	return sealed
}

// gapH1 is the h1 hash of value, panicking on one the domain refuses so a bad
// fixture points at its own line.
func gapH1(t *testing.T, value string) string {
	t.Helper()
	h, err := NewModuleHash("h1", value)
	if err != nil {
		t.Fatalf("building fixture hash h1:%s: %v", value, err)
	}
	return h.String()
}

// gapFailAfter replaces the canonical marshal seam with one that delegates for
// the first n calls and then fails, and restores it when the test ends. It is
// how a failure can be aimed at ONE of the two marshals MarshalComposite
// performs: the served record's, and the envelope's.
func gapFailAfter(t *testing.T, n int, err error) {
	t.Helper()
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	calls := 0
	canonicalMarshal = func(v any) ([]byte, error) {
		calls++
		if calls > n {
			return nil, err
		}
		//nolint:wrapcheck // the seam stands in for json.Marshal, which wraps nothing
		return original(v)
	}
}

// A local coordinate's measurements are read as a sequence, and the ledger's
// insertion order is that sequence only for measurements that share a time. A
// measurement carrying a STRICTLY LATER time is the later observation whatever
// position it occupies, so it is served even when an earlier-timed record was
// appended after it — the alternative hands a reader a state of the working tree
// that a later run has already been shown to have superseded.
func TestCompose_LocalCoordinateServesAStrictlyLaterMeasurementOutOfPosition(t *testing.T) {
	local := coordinatetest.MustNew("example.com/proj", coordinate.LocalVersion)
	later := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = local.Path(), local.Version()
		r.ModuleHash = gapH1(t, "tree-later==")
		r.VerificationStatus = string(LocalSource)
		r.FetchedAt = gapAt(2)
	})
	earlier := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = local.Path(), local.Version()
		r.ModuleHash = gapH1(t, "tree-earlier==")
		r.VerificationStatus = string(LocalSource)
		r.FetchedAt = gapAt(1)
	})

	// The later measurement is listed FIRST, so position alone would serve the
	// earlier one.
	got, err := Compose([]FactRecord{later, earlier})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != later.ContentHash {
		t.Error("served the last-listed measurement though an earlier position carried a strictly later measurement time")
	}
}

// A hash column that cannot be parsed stops composition rather than producing a
// composite with a zero identity. A zero identity is the spelling of "this
// record names no artefact", and handing one back for a corrupt column is how a
// corrupt store becomes a silently empty one.
func TestCompose_UnparseableHashStopsTheCompositionInsteadOfZeroingTheIdentity(t *testing.T) {
	corrupt := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = "not-a-hash"
		r.VerificationStatus = string(Verified)
		r.FetchedAt = gapAt(1)
	})

	got, err := Compose([]FactRecord{corrupt})
	if err == nil {
		t.Fatalf("Compose accepted an unparseable module hash and returned identity %q", got.Identity)
	}
	if !strings.Contains(err.Error(), "module hash") {
		t.Errorf("error = %v, want it to name the hash it could not read", err)
	}
}

// MarshalComposite reports a failure in the SERVED RECORD's own bytes rather
// than emitting an envelope around nothing. The record is nested as its own
// canonical JSON precisely so a reader can lift it out and verify its content
// hash; an envelope whose record member is empty would verify as a composite and
// pin no measurement at all.
func TestCanonicalHasher_MarshalComposite_ReportsAFailureInTheServedRecord(t *testing.T) {
	injected := errors.New("injected marshal failure")
	c := gapComposite(t)
	gapFailAfter(t, 0, injected)

	_, err := CanonicalHasher{}.MarshalComposite(c)
	if !errors.Is(err, injected) {
		t.Fatalf("MarshalComposite error = %v, want it to wrap the injected failure", err)
	}
	if !strings.Contains(err.Error(), "served record") {
		t.Errorf("error = %q, want it to name the served record as the leg that failed", err.Error())
	}
}

// The envelope's own marshal is guarded separately, and names itself. Two
// marshals happen here and they fail for different reasons; an error that did
// not say which one answered would send a reader to the wrong bytes.
func TestCanonicalHasher_MarshalComposite_ReportsAFailureInTheEnvelope(t *testing.T) {
	injected := errors.New("injected marshal failure")
	c := gapComposite(t)
	gapFailAfter(t, 1, injected) // the served record marshals; the envelope does not

	_, err := CanonicalHasher{}.MarshalComposite(c)
	if !errors.Is(err, injected) {
		t.Fatalf("MarshalComposite error = %v, want it to wrap the injected failure", err)
	}
	if !strings.Contains(err.Error(), "canonical composite") {
		t.Errorf("error = %q, want it to name the composite envelope as the leg that failed", err.Error())
	}
}

// The validation legs survive the round trip through the canonical form, each
// still carrying the date it was established and whether the measurement holding
// it rechecked it or inherited it. A serialisation that dropped the provenance
// would turn an inherited copy into a claim that the check was performed here,
// which is the one thing the leg fields exist to keep apart.
func TestCanonicalHasher_Composite_RoundTripsValidationLegs(t *testing.T) {
	c := gapComposite(t)
	if len(c.Legs) != 2 {
		t.Fatalf("fixture composed %d legs, want both the sumdb and the VCS leg", len(c.Legs))
	}

	h := CanonicalHasher{}
	data, err := h.MarshalComposite(c)
	if err != nil {
		t.Fatalf("MarshalComposite: %v", err)
	}
	got, err := h.UnmarshalComposite(data)
	if err != nil {
		t.Fatalf("UnmarshalComposite: %v", err)
	}

	if len(got.Legs) != len(c.Legs) {
		t.Fatalf("round trip returned %d legs, want %d", len(got.Legs), len(c.Legs))
	}
	for i, want := range c.Legs {
		if got.Legs[i] != want {
			t.Errorf("leg %d = %+v, want %+v", i, got.Legs[i], want)
		}
	}
	if got.ContentHash != c.ContentHash {
		t.Errorf("served record's content hash = %q, want %q", got.ContentHash, c.ContentHash)
	}
	if !got.Identity.Equal(c.Identity) {
		t.Errorf("Identity = %s, want %s", got.Identity, c.Identity)
	}
	if !got.FirstFetchedAt.Equal(c.FirstFetchedAt) || !got.LatestFetchedAt.Equal(c.LatestFetchedAt) {
		t.Errorf("dates = (%v, %v), want (%v, %v)", got.FirstFetchedAt, got.LatestFetchedAt, c.FirstFetchedAt, c.LatestFetchedAt)
	}
}

// Every unreadable part of a stored composite is an error rather than a
// partially-populated value. A composite whose dates would not parse, or whose
// nested record is not a record, describes nothing a reader can act on, and
// answering with a half-filled struct is how an unreadable row becomes an
// artefact that appears never to have been measured.
func TestCanonicalHasher_UnmarshalComposite_RejectsEveryUnreadablePart(t *testing.T) {
	h := CanonicalHasher{}
	good, err := h.MarshalComposite(gapComposite(t))
	if err != nil {
		t.Fatalf("MarshalComposite: %v", err)
	}

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "not JSON at all",
			data: []byte("{"),
			want: "unmarshalling canonical composite",
		},
		{
			name: "nested record is not a record",
			data: gapMutateComposite(t, good, "record", json.RawMessage("123")),
			want: "unmarshalling canonical fact record",
		},
		{
			name: "nested record carries an unreadable hash",
			data: gapMutateComposite(t, good, "record",
				json.RawMessage(gapMutateComposite(t, gapRecordJSON(t, good), "module_hash", json.RawMessage(`"not-a-hash"`)))),
			want: "module hash",
		},
		{
			name: "first_fetched_at is not a time",
			data: gapMutateComposite(t, good, "first_fetched_at", json.RawMessage(`"yesterday"`)),
			want: "first_fetched_at",
		},
		{
			name: "latest_fetched_at is not a time",
			data: gapMutateComposite(t, good, "latest_fetched_at", json.RawMessage(`"tomorrow"`)),
			want: "latest_fetched_at",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := h.UnmarshalComposite(tt.data)
			if err == nil {
				t.Fatalf("UnmarshalComposite accepted %s and returned %+v", tt.name, got.Identity)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to name %q", err.Error(), tt.want)
			}
		})
	}
}

// Anchor strength and schema version are the rungs of the serving order that two
// otherwise-identical measurements consult, and each has to be able to decide
// alone. Without the anchor rung a weaker measurement appended later would be
// indistinguishable from the stronger one it must not displace; without the
// schema rung the choice between two records of different generations would fall
// through to a content-hash comparison that carries no authority at all.
func TestCompose_AnchorStrengthThenSchemaVersionDecideBetweenEqualMeasurements(t *testing.T) {
	base := func(status VerificationStatus, schema string, hash string) FactRecord {
		return gapRecord(t, func(r *FactRecord) {
			r.SchemaVersion = schema
			r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
			r.ModuleHash = gapH1(t, hash)
			r.GoModHash = gapH1(t, "mod==")
			r.VerificationStatus = string(status)
			r.FetchedAt = gapAt(1)
		})
	}

	tests := []struct {
		name          string
		stronger      FactRecord
		weaker        FactRecord
		wantDecidedBy string
	}{
		{
			name:          "anchor strength",
			stronger:      base(Verified, SchemaVersion, "zip=="),
			weaker:        base(VerifiedByGoSum, SchemaVersion, "zip=="),
			wantDecidedBy: "the stronger trust anchor",
		},
		{
			name:          "schema version, anchors equal",
			stronger:      base(Verified, "5", "zip=="),
			weaker:        base(Verified, "4", "zip=="),
			wantDecidedBy: "the newer schema version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, order := range []struct {
				name    string
				records []FactRecord
			}{
				{"weaker first", []FactRecord{tt.weaker, tt.stronger}},
				{"stronger first", []FactRecord{tt.stronger, tt.weaker}},
			} {
				t.Run(order.name, func(t *testing.T) {
					got, err := Compose(order.records)
					if err != nil {
						t.Fatalf("Compose: %v", err)
					}
					if got.ContentHash != tt.stronger.ContentHash {
						t.Errorf("served the record with hash %q; %s must decide here", got.ContentHash, tt.wantDecidedBy)
					}
				})
			}
		})
	}
}

// A leg established on the same date by two measurements is decided by which one
// actually performed the check. The inherited copy is a transcription of some
// earlier recheck, so the recheck is the primary evidence; composing the copy
// instead would leave a reader chasing a Source pointer for a result that is
// stated first-hand on a record right beside it.
func TestCompose_ARecheckedLegBeatsAnInheritedOneOfTheSameDate(t *testing.T) {
	// Both measurements share a fetch time, so the legs share an EstablishedAt
	// and provenance is all that is left to decide with.
	inheritor := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = gapH1(t, "zip==")
		r.VerificationStatus = string(Verified)
		r.FetchedAt = gapAt(1)
		r.SumDBCheck = string(LegInherited)
		r.SumDBCheckSource = "sha256:earlier"
	})
	rechecker := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = gapH1(t, "zip==")
		r.VerificationStatus = string(Verified)
		r.FetchedAt = gapAt(1)
		r.SumDBCheck = string(LegRechecked)
	})

	// The inherited leg is seen first, so it is the incumbent the recheck has to
	// displace.
	got, err := Compose([]FactRecord{inheritor, rechecker})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if len(got.Legs) != 1 {
		t.Fatalf("composed %d legs, want the single sumdb leg", len(got.Legs))
	}
	if got.Legs[0].Provenance != LegRechecked {
		t.Errorf("composed the %q leg; the measurement that performed the check is the primary evidence", got.Legs[0].Provenance)
	}
	if got.Legs[0].Source != "" {
		t.Errorf("composed leg names a source %q; a rechecked leg was established here and inherits nothing", got.Legs[0].Source)
	}
}

// A divergence is returned to the commands that fail closed on it, so its
// message has to carry everything an operator needs to reach the rows: the
// coordinate, the pipeline generations involved, the field that disagrees, both
// values and the records holding them. A message naming only "records disagree"
// leaves the operator to find them.
func TestDivergence_ErrorNamesTheCoordinateFieldValuesAndRecords(t *testing.T) {
	d := Divergence{
		Coordinate:      gapCoord,
		PipelineVersion: "fetch-1, fetch-2",
		Field:           "module_hash",
		Values:          []string{"h1:a==", "h1:b=="},
		ContentHashes:   []string{"sha256:aaa", "sha256:bbb"},
	}

	var asError error = d
	msg := asError.Error()
	for _, want := range []string{
		gapCoord.String(), "fetch-1, fetch-2", "module_hash",
		"h1:a==", "h1:b==", "sha256:aaa", "sha256:bbb",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to name %q", msg, want)
		}
	}
}

// A record whose hashes cannot be parsed is MALFORMED, not shallow. Reporting it
// as go.mod-only would tell a caller a verified go.mod is available when the
// column holding its hash is unreadable, and that caller would go on to resolve a
// module graph from bytes nobody can address.
func TestFactRecord_IsGoModOnly_AnUnreadableHashIsNotAShallowMeasurement(t *testing.T) {
	tests := []struct {
		name       string
		moduleHash string
		goModHash  string
	}{
		{"module hash unreadable", "not-a-hash", gapH1(t, "mod==")},
		{"go.mod hash unreadable", ZeroString, "not-a-hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := FactRecord{ModuleHash: tt.moduleHash, GoModHash: tt.goModHash}
			if r.IsGoModOnly() {
				t.Error("a record with an unreadable hash reported itself as a go.mod-only measurement")
			}
		})
	}
}

// The go.mod hash is read on the same terms as the module hash: a value that is
// neither well-formed nor the canonical spelling of absence is an error, never a
// silently zero identity. Without this leg, a record whose zip was never fetched
// and whose go.mod column is corrupt would compose under the zero identity —
// joining every other record that names no artefact.
func TestArtefactIdentityOf_AnUnreadableGoModHashIsReported(t *testing.T) {
	r := FactRecord{
		ModulePath:    gapCoord.Path(),
		ModuleVersion: gapCoord.Version(),
		ModuleHash:    ZeroString,
		GoModHash:     "not-a-hash",
	}

	got, err := ArtefactIdentityOf(r)
	if err == nil {
		t.Fatalf("ArtefactIdentityOf accepted an unreadable go.mod hash and returned %q", got)
	}
	if !strings.Contains(err.Error(), "go.mod hash") {
		t.Errorf("error = %v, want it to name the go.mod hash", err)
	}
}

// ParseArtefactIdentity fails closed on a value carrying no depth prefix at all.
// The prefix is what keeps a go.mod hash from colliding with a zip hash holding
// the same value, so a bare value is not an identity missing a decoration — it is
// a value whose depth nothing states.
func TestParseArtefactIdentity_RejectsAValueWithNoDepthPrefix(t *testing.T) {
	got, err := ParseArtefactIdentity("bare-value-with-no-separator")
	if err == nil {
		t.Fatalf("ParseArtefactIdentity accepted a value with no depth prefix and returned %q", got)
	}
	for _, want := range []string{identityPrefixZip, identityPrefixGoMod} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name the %q depth prefix it expected", err, want)
		}
	}
}

// Seal computes the hash at construction so no unsealed record ever exists, which
// means a hashing failure has to be reported rather than absorbed: returning the
// zero SealedRecord with a nil error would hand the write path a value that seals
// nothing and passes for a record of the empty module at the empty version.
func TestSeal_ReportsAHashingFailureInsteadOfAnUnsealedRecord(t *testing.T) {
	injected := errors.New("injected marshal failure")
	gapFailAfter(t, 0, injected)

	got, err := Seal(FetchedModule{Coordinate: gapCoord})
	if !errors.Is(err, injected) {
		t.Fatalf("Seal error = %v, want it to wrap the injected failure", err)
	}
	if !got.IsZero() {
		t.Error("Seal returned a non-zero SealedRecord after failing to hash it")
	}
	if !strings.Contains(err.Error(), gapCoord.String()) {
		t.Errorf("error = %v, want it to name the module it was sealing", err)
	}
}

// A sealed record answers for the identity of the artefact it describes, derived
// from the very hashes its content hash already covers. A caller that had to
// unwrap the record and derive the identity itself is a caller that can derive a
// different one, which is exactly how a measurement's identity and its record's
// come to disagree.
func TestSealedRecord_ArtefactIdentityDescribesTheSealedMeasurement(t *testing.T) {
	r := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = gapH1(t, "zip==")
		r.GoModHash = gapH1(t, "mod==")
		r.VerificationStatus = string(Verified)
		r.FetchedAt = gapAt(1)
	})
	sealed, err := Rehydrate(r)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	got, err := sealed.ArtefactIdentity()
	if err != nil {
		t.Fatalf("ArtefactIdentity: %v", err)
	}
	want, err := ArtefactIdentityOf(r)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("ArtefactIdentity() = %s, want the identity of the record it seals (%s)", got, want)
	}
	if got.GoModOnly() {
		t.Error("a record carrying a zip hash reported a go.mod-only identity")
	}

	// A sealed record whose hashes are malformed reports the parse failure rather
	// than a zero identity: the seal proves the bytes were not tampered with, not
	// that they were well-formed when they were written.
	malformed, err := Rehydrate(gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = "not-a-hash"
		r.FetchedAt = gapAt(1)
	}))
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if _, err := malformed.ArtefactIdentity(); err == nil {
		t.Error("a sealed record with an unreadable hash reported an identity")
	}
}

// gapComposite is a composite of one measurement carrying both validation legs,
// which is the shape the marshal and unmarshal tests need: a nested record, two
// legs and two distinct dates.
func gapComposite(t *testing.T) CompositeRecord {
	t.Helper()
	first := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = gapH1(t, "zip==")
		r.GoModHash = gapH1(t, "mod==")
		r.VerificationStatus = string(Verified)
		r.FetchedAt = gapAt(1)
		r.SumDBCheck = string(LegRechecked)
		r.VCSCheck = string(LegRechecked)
	})
	latest := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = gapH1(t, "zip==")
		r.GoModHash = gapH1(t, "mod==")
		r.VerificationStatus = string(VerifiedByGoSum)
		r.FetchedAt = gapAt(4)
		r.VCSCheck = string(LegInherited)
		r.VCSCheckSource = "sha256:earlier"
	})
	c, err := Compose([]FactRecord{first, latest})
	if err != nil {
		t.Fatalf("composing fixture: %v", err)
	}
	return c
}

// gapMutateComposite rewrites one member of a JSON object, so a test can state
// the single part it wants unreadable rather than hand-writing the whole
// envelope and drifting from what MarshalComposite actually emits.
func gapMutateComposite(t *testing.T, data []byte, key string, value json.RawMessage) []byte {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("reading fixture JSON: %v", err)
	}
	obj[key] = value
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("rewriting fixture JSON: %v", err)
	}
	return out
}

// gapRecordJSON lifts the nested record out of a composite's canonical bytes.
func gapRecordJSON(t *testing.T, data []byte) []byte {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("reading fixture JSON: %v", err)
	}
	return obj["record"]
}

// A composite with no validation legs must serialise `legs` as absent, not as an
// empty array. The seal is computed over exactly these bytes, so the two
// spellings are two different content hashes for one composite — and every
// record composed before a leg was ever established takes this branch, which is
// most of a fresh store.
func TestCanonicalHasher_MarshalComposite_NoLegsSerialiseAsAbsentNotEmpty(t *testing.T) {
	bare := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = gapH1(t, "zip==")
		r.GoModHash = gapH1(t, "mod==")
		r.VerificationStatus = string(Verified)
		r.FetchedAt = gapAt(1)
	})
	c, err := Compose([]FactRecord{bare})
	if err != nil {
		t.Fatalf("composing fixture: %v", err)
	}
	if len(c.Legs) != 0 {
		t.Fatalf("fixture carries %d leg(s); this test is about a composite with none", len(c.Legs))
	}

	data, err := (CanonicalHasher{}).MarshalComposite(c)
	if err != nil {
		t.Fatalf("MarshalComposite: %v", err)
	}
	var envelope map[string]json.RawMessage
	if uerr := json.Unmarshal(data, &envelope); uerr != nil {
		t.Fatalf("marshalled composite is not an object: %v", uerr)
	}
	if raw, present := envelope["legs"]; present && string(raw) != "null" {
		t.Errorf("legs = %s, want absent or null for a composite with no legs", raw)
	}
	if strings.Contains(string(data), `"legs":[]`) {
		t.Errorf("no-leg composite serialised legs as an empty array:\n%s", data)
	}

	// And it must read back as the same composite, so the absent spelling is not
	// a shape only the writer understands.
	back, err := (CanonicalHasher{}).UnmarshalComposite(data)
	if err != nil {
		t.Fatalf("UnmarshalComposite: %v", err)
	}
	if len(back.Legs) != 0 {
		t.Errorf("round-tripped legs = %v, want none", back.Legs)
	}
}

// Divergence is a disagreement BETWEEN measurements, so fewer than two of them
// cannot exhibit one. The guard matters because the answer for "one record" and
// the answer for "two records that agree" are the same nil, and only one of them
// is a comparison — a divergence check that reported on a single record would be
// asserting agreement it never tested.
func TestFindDivergence_FewerThanTwoRecordsCannotDisagree(t *testing.T) {
	one := gapRecord(t, func(r *FactRecord) {
		r.ModulePath, r.ModuleVersion = gapCoord.Path(), gapCoord.Version()
		r.ModuleHash = gapH1(t, "zip==")
		r.GoModHash = gapH1(t, "mod==")
		r.VerificationStatus = string(Verified)
		r.FetchedAt = gapAt(1)
	})
	for _, tt := range []struct {
		name    string
		records []FactRecord
	}{
		{name: "no records"},
		{name: "empty slice", records: []FactRecord{}},
		{name: "one record", records: []FactRecord{one}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if d := FindDivergence(tt.records); d != nil {
				t.Errorf("FindDivergence(%d record(s)) = %v, want nil", len(tt.records), d)
			}
		})
	}
}
