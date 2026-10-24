package osv

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// An entry over the limit is refused, not truncated to a prefix that may still
// decode; one at the limit is read whole.
func TestReadZipFile_RefusesAnEntryOverTheLimit(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("index/db.json")
	if err == nil {
		_, err = w.Write([]byte(`{"modified":"x"}`))
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	if _, err := readZipFile(f, 15); err == nil || !strings.Contains(err.Error(), "larger than 15 bytes") {
		t.Errorf("over the limit: got %v, want a refusal naming the limit", err)
	}
	if data, err := readZipFile(f, 16); err != nil || string(data) != `{"modified":"x"}` {
		t.Errorf("at the limit: got %q, %v", data, err)
	}
}
