package domain_test

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

func sampleReleases() []domain.Release {
	return []domain.Release{
		{Version: "go1.26.4", Files: []domain.ReleaseFile{
			{Filename: "go1.26.4.linux-amd64.tar.gz", Kind: "archive", SHA256: "aaa"},
			{Filename: "go1.26.4.src.tar.gz", Kind: "source", SHA256: "srcsha"},
		}},
		{Version: "go1.26.3", Files: []domain.ReleaseFile{
			{Filename: "go1.26.3.windows-amd64.msi", Kind: "installer", SHA256: "bbb"},
		}},
	}
}

func TestFindSourceChecksum_Found(t *testing.T) {
	f, err := domain.FindSourceChecksum(sampleReleases(), "go1.26.4")
	if err != nil {
		t.Fatalf("FindSourceChecksum: %v", err)
	}
	if f.SHA256 != "srcsha" || f.Filename != "go1.26.4.src.tar.gz" {
		t.Errorf("got %+v, want source file with srcsha", f)
	}
}

func TestFindSourceChecksum_ReleaseNotFound(t *testing.T) {
	_, err := domain.FindSourceChecksum(sampleReleases(), "go1.99.0")
	if !errors.Is(err, domain.ErrReleaseNotFound) {
		t.Errorf("err = %v, want ErrReleaseNotFound", err)
	}
}

func TestFindSourceChecksum_SourceMissing(t *testing.T) {
	_, err := domain.FindSourceChecksum(sampleReleases(), "go1.26.3")
	if !errors.Is(err, domain.ErrSourceFileMissing) {
		t.Errorf("err = %v, want ErrSourceFileMissing", err)
	}
}
