package domain_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// buildTarball assembles a gzip'd tar from the given name→content entries, the
// same shape as go{VERSION}.src.tar.gz (every path rooted under "go/").
func buildTarball(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(content)),
		}); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func TestExtractLicense_Found(t *testing.T) {
	const license = "Copyright (c) 2009 The Go Authors. All rights reserved.\nBSD-3-Clause text ..."
	tb := buildTarball(t, map[string]string{
		"go/README.md":        "readme",
		"go/LICENSE":          license,
		"go/src/fmt/print.go": "package fmt",
	})
	got, err := domain.ExtractLicense(tb)
	if err != nil {
		t.Fatalf("ExtractLicense: %v", err)
	}
	if string(got) != license {
		t.Errorf("license text = %q, want %q", got, license)
	}
}

func TestExtractLicense_NotFound(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/README.md": "readme"})
	_, err := domain.ExtractLicense(tb)
	if !errors.Is(err, domain.ErrLicenseNotFound) {
		t.Errorf("err = %v, want ErrLicenseNotFound", err)
	}
}

func TestExtractLicense_NotGzip(t *testing.T) {
	_, err := domain.ExtractLicense([]byte("not a gzip stream"))
	if err == nil {
		t.Error("ExtractLicense on non-gzip input: err = nil, want error")
	}
}

func TestExtractLicense_TruncatedEntry(t *testing.T) {
	// A go/LICENSE header that over-declares its size, followed by a truncated
	// body: the tar header reads fine but reading the entry body fails partway.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "go/LICENSE", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4096}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	// Deliberately do not Close tw (its size accounting would error); flush what
	// was written so the archive holds a header claiming 4096 bytes but only a
	// handful of body bytes.
	_ = tw.Flush()
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := domain.ExtractLicense(buf.Bytes())
	if err == nil {
		t.Error("ExtractLicense on truncated entry: err = nil, want error")
	}
	if errors.Is(err, domain.ErrLicenseNotFound) {
		t.Error("truncated entry should be a read error, not ErrLicenseNotFound")
	}
}

func TestExtractLicense_CorruptTar(t *testing.T) {
	// A valid gzip stream wrapping bytes that are not a valid tar archive: the
	// gzip reader opens, but the first tar-header read fails with a non-EOF error.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte("this is not a tar archive, just some gzipped text padding padding padding")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := domain.ExtractLicense(buf.Bytes())
	if err == nil {
		t.Error("ExtractLicense on corrupt tar: err = nil, want error")
	}
	if errors.Is(err, domain.ErrLicenseNotFound) {
		t.Error("corrupt tar should be a read error, not ErrLicenseNotFound")
	}
}
