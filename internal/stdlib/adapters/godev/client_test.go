package godev_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eitanity/kanonarion/internal/stdlib/adapters/godev"
)

func TestClient_FetchReleasesAndDownload(t *testing.T) {
	const manifest = `[{"version":"go1.26.4","files":[{"filename":"go1.26.4.src.tar.gz","kind":"source","sha256":"abc123"}]}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dl/":
			_, _ = w.Write([]byte(manifest))
		case "/dl/go1.26.4.src.tar.gz":
			_, _ = w.Write([]byte("tarball-bytes"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := godev.NewWithManifestURL(srv.URL + "/dl/?mode=json&include=all")

	releases, err := c.FetchReleases(context.Background())
	if err != nil {
		t.Fatalf("FetchReleases: %v", err)
	}
	if len(releases) != 1 || releases[0].Version != "go1.26.4" {
		t.Fatalf("releases = %+v", releases)
	}
	if releases[0].Files[0].SHA256 != "abc123" {
		t.Errorf("sha256 = %q", releases[0].Files[0].SHA256)
	}

	data, err := c.Download(context.Background(), srv.URL+"/dl/go1.26.4.src.tar.gz")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(data) != "tarball-bytes" {
		t.Errorf("tarball = %q", data)
	}
}

func TestClient_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := godev.NewWithManifestURL(srv.URL)
	if _, err := c.FetchReleases(context.Background()); err == nil {
		t.Error("expected error on 500 response")
	}
	if _, err := c.Download(context.Background(), srv.URL); err == nil {
		t.Error("expected error on 500 response")
	}
}

func TestClient_BadJSONIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	c := godev.NewWithManifestURL(srv.URL)
	if _, err := c.FetchReleases(context.Background()); err == nil {
		t.Error("expected decode error")
	}
}
