package vulndbindex

import (
	"archive/zip"
	"bytes"
	"errors"
	"reflect"
	"testing"

	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

func zipOf(t *testing.T, name string, method uint16, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
	if err == nil {
		_, err = w.Write([]byte(body))
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const index = `[{"path":"example.com/m","vulns":[{"id":"GO-2","fixed":"v1.1.0"},{"id":"GO-2","fixed":"v1.0.0"},{"id":"GO-1","modified":"b"},{"id":"GO-1","modified":"a"}]}]`

// The entries come back sorted, so two readings of one generation compare equal.
func TestFromZip_DecodesSorted(t *testing.T) {
	got, err := FromZip(zipOf(t, Entry, zip.Deflate, index))
	want := ports.AdvisoryIndex{"example.com/m": {{ID: "GO-1", Modified: "a"}, {ID: "GO-1", Modified: "b"}, {ID: "GO-2", Fixed: "v1.0.0"}, {ID: "GO-2", Fixed: "v1.1.0"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, %v; want %v", got, err, want)
	}
}

// An index over the cap is refused with ErrTooLarge rather than decoded from a
// truncated prefix; one exactly at the cap is read.
func TestFromZip_RefusesAnIndexOverTheCap(t *testing.T) {
	data := zipOf(t, Entry, zip.Deflate, index)
	if _, err := fromZip(data, int64(len(index))-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("one byte over the cap: got %v, want ErrTooLarge", err)
	}
	if _, err := fromZip(data, int64(len(index))); err != nil {
		t.Errorf("exactly at the cap: %v", err)
	}
}

func TestFromZip_Errors(t *testing.T) {
	corrupt := zipOf(t, Entry, zip.Deflate, index)
	corrupt[bytes.Index(corrupt, []byte("PK\x01\x02"))+16] ^= 0xff
	// An unknown compression method in the central directory fails Open.
	badMethod := zipOf(t, Entry, zip.Store, index)
	badMethod[bytes.Index(badMethod, []byte("PK\x01\x02"))+10] = 99
	for name, data := range map[string][]byte{
		"not a zip":   []byte("x"),
		"no index":    zipOf(t, "other.json", zip.Deflate, index),
		"bad json":    zipOf(t, Entry, zip.Deflate, "{"),
		"bad method":  badMethod,
		"bad entry":   corrupt,
		"empty index": zipOf(t, Entry, zip.Store, ""),
	} {
		if got, err := FromZip(data); err == nil {
			t.Errorf("%s: got %v and no error", name, got)
		}
	}
	if _, err := FromZip(zipOf(t, "other.json", zip.Deflate, index)); !errors.Is(err, ErrMissing) {
		t.Errorf("no index: got %v, want ErrMissing", err)
	}
}
