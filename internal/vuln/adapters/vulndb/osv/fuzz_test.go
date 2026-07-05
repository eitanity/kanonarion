package osv

import (
	"archive/zip"
	"bytes"
	"testing"
)

// FuzzDecode exercises the two untrusted-JSON ingestion points of the OSV
// vuln-DB adapter: index/db.json (read out of the downloaded vulndb.zip) and
// index/modules.json. These payloads originate from the external vuln.go.dev
// database (relates), so the decoders must never panic and must bound
// their allocation on adversarial input — Go's encoding/json caps slice/map
// growth to the input size, so a malformed payload cannot inflate memory
// beyond it.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzDecode./internal/vuln/adapters/vulndb/osv
func FuzzDecode(f *testing.F) {
	// Valid, well-formed payloads.
	f.Add([]byte(`{"modified":"2024-01-02T03:04:05Z"}`))
	f.Add([]byte(`[{"path":"golang.org/x/net","vulns":[{"id":"GO-2024-0001","fixed":"0.23.0"}]}]`))

	// Empty / null / wrong top-level shape.
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`"a string where an object is expected"`))
	f.Add([]byte(`[{"path":42,"vulns":"not-an-array"}]`))

	// Missing / extra fields.
	f.Add([]byte(`[{"unexpected":true}]`))
	f.Add([]byte(`{"modified":null}`))
	f.Add([]byte(`[{"path":"m","vulns":[{}]}]`))

	// Wrong types where strings/arrays are expected.
	f.Add([]byte(`[{"id":123,"aliases":"x"}]`))
	f.Add([]byte(`{"modified":["array"]}`))

	// Deeply nested / malformed structure.
	f.Add([]byte(`[[[[[[[[[[]]]]]]]]]]`))
	f.Add([]byte(`{"modified":` + `{"x":` + `{"y":1}}}`))

	// Truncated / syntactically invalid JSON.
	f.Add([]byte(`[{"id":"GO-`))
	f.Add([]byte(`{`))
	f.Add([]byte("\x00\x01\x02 not json"))

	// Large array (modest seed; the fuzzer will grow it).
	big := []byte(`[`)
	for i := range 256 {
		if i > 0 {
			big = append(big, ',')
		}
		big = append(big, `{"path":"m","vulns":[{"id":"x","fixed":"1.0.0"}]}`...)
	}
	big = append(big, ']')
	f.Add(big)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Each decoder must return (zero, error) or (value, nil) — never panic.
		_, _ = decodeDBModified(data)

		idx, err := decodeModulesIndex(data)
		if err == nil {
			// On success the map and its slices must be internally consistent:
			// a successful decode never yields a nil map.
			if idx == nil {
				t.Fatalf("decodeModulesIndex returned nil map with nil error for %q", data)
			}
			for path, vulns := range idx {
				for _, v := range vulns {
					_ = isAffectedVersion("v1.0.0", v.fixed)
					_ = path
				}
			}
		}
	})
}

// FuzzValidateSnapshotZip hardens the untrusted-zip ingestion path: the bulk
// /vulndb.zip body is fetched verbatim from vuln.go.dev and run through the
// layout gate before persisting. The validator must never panic and must fail
// closed (non-nil error, empty version) on any malformed, truncated, or
// layout-incomplete archive.
func FuzzValidateSnapshotZip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04 not really a zip"))
	f.Add([]byte("\x00\x01\x02\x03"))
	// A well-formed, complete archive seed.
	f.Add(buildSnapshotZipBytes(map[string]string{
		"index/db.json":        `{"modified":"2024-01-02T03:04:05Z"}`,
		"index/modules.json":   `[]`,
		"ID/GO-2024-0001.json": `{"id":"GO-2024-0001"}`,
	}))
	// A layout-incomplete archive seed (missing modules + entries).
	f.Add(buildSnapshotZipBytes(map[string]string{
		"index/db.json": `{"modified":"2024-01-02T03:04:05Z"}`,
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		version, err := validateSnapshotZip(data)
		if err != nil && version != "" {
			t.Fatalf("validateSnapshotZip returned version %q with error %v", version, err)
		}
	})
}

// buildSnapshotZipBytes builds an in-memory zip from name->content pairs for
// fuzz seeds. Distinct from the test helper of the same purpose so the fuzz
// file stays in the internal (white-box) package.
func buildSnapshotZipBytes(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
