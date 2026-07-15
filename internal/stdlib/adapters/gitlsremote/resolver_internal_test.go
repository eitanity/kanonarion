package gitlsremote

import "testing"

func TestParseLsRemote_PreferPeeled(t *testing.T) {
	out := []byte(
		"1111111111111111111111111111111111111111\trefs/tags/go1.26.4\n" +
			"2222222222222222222222222222222222222222\trefs/tags/go1.26.4^{}\n")
	sha, err := parseLsRemote(out, "refs/tags/go1.26.4")
	if err != nil {
		t.Fatalf("parseLsRemote: %v", err)
	}
	if sha != "2222222222222222222222222222222222222222" {
		t.Errorf("sha = %q, want peeled commit", sha)
	}
}

func TestParseLsRemote_LightweightTag(t *testing.T) {
	out := []byte("3333333333333333333333333333333333333333\trefs/tags/go1.26.4\n")
	sha, err := parseLsRemote(out, "refs/tags/go1.26.4")
	if err != nil {
		t.Fatalf("parseLsRemote: %v", err)
	}
	if sha != "3333333333333333333333333333333333333333" {
		t.Errorf("sha = %q", sha)
	}
}

func TestParseLsRemote_NotFound(t *testing.T) {
	if _, err := parseLsRemote([]byte("garbage\n"), "refs/tags/go1.26.4"); err == nil {
		t.Error("expected error for missing tag")
	}
}
