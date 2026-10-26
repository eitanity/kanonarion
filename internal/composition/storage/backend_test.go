package storage_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/composition/storage"
	"code.eitanity.com/kanonarion/internal/config/domain"
)

func backend(name, section string) storage.Backend {
	return storage.Backend{
		Name: name, Section: section, Defaults: struct {
			Dir string `yaml:"dir"`
		}{},
		Open: func(_ context.Context, req storage.Request) (*storage.Storage, error) {
			st := full()
			st.Close = func() error { return errors.New(name + ":" + string(req.Section)) }
			return st, nil
		},
	}
}

func opened(t *testing.T, st *storage.Storage, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("OpenConfigured: %v", err)
	}
	return st.Close().Error()
}

func TestRegister_RefusesWhatCannotBeSelected(t *testing.T) {
	t.Cleanup(storage.ResetRegistry)
	if err := storage.Register(backend("a", "a")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		b    storage.Backend
		want string
	}{
		{storage.Backend{Open: backend("x", "").Open}, "registering storage backend: empty name"},
		{storage.Backend{Name: "x"}, `registering storage backend "x": nil Open`},
		{backend("a", "other"), `registering storage backend "a": already registered`},
		{backend("b", "a"), `registering storage backend "b": section "a" belongs to backend "a"`},
		{backend("c", "storage"), `registering storage backend "c": section "storage" is a config.yaml section of its own`},
		{backend("d", "version"), `registering storage backend "d": section "version" is a config.yaml section of its own`},
		{storage.Backend{Name: "e", Section: "e", Defaults: struct{ C chan int }{}, Open: backend("e", "").Open},
			`registering storage backend "e": section e: defaults cannot be written as YAML: cannot marshal type: chan int`},
	} {
		if err := storage.Register(tc.b); err == nil || err.Error() != tc.want {
			t.Errorf("Register(%q) = %v, want %q", tc.b.Name, err, tc.want)
		}
	}
	if got := storage.Names(); len(got) != 1 || got[0] != "a" {
		t.Errorf("Names() = %v, want [a]", got)
	}
}

func TestRegister_ListsBackendsAndTheirSections(t *testing.T) {
	t.Cleanup(storage.ResetRegistry)
	for _, b := range []storage.Backend{backend("zeta", "zeta"), backend("alpha", ""), backend("mid", "mid")} {
		if err := storage.Register(b); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(storage.Names(), ","); got != "alpha,mid,zeta" {
		t.Errorf("Names() = %s, want sorted", got)
	}
	specs := storage.ConfigSpecs()
	if len(specs) != 2 || specs[0].Section != "zeta" || specs[1].Section != "mid" {
		t.Errorf("ConfigSpecs() = %+v, want zeta then mid, and none for a backend without a section", specs)
	}
	if _, ok := storage.Lookup("alpha"); !ok {
		t.Error("Lookup(alpha) found nothing")
	}
	if _, ok := storage.Lookup("absent"); ok {
		t.Error("Lookup(absent) found a backend")
	}
}

func TestOpenConfigured_SelectsTheConfiguredBackendWithItsSection(t *testing.T) {
	t.Cleanup(storage.ResetRegistry)
	if err := storage.Register(backend("files", "files")); err != nil {
		t.Fatal(err)
	}
	if err := storage.Register(backend("bare", "")); err != nil {
		t.Fatal(err)
	}
	implicit := backend("sqlite", "sqlite")
	cfg := domain.Config{
		Storage:  domain.StorageConfig{Backend: "files"},
		Sections: map[string][]byte{"files": []byte("dir: x\n"), "sqlite": []byte("ignored\n")},
	}
	st, err := storage.OpenConfigured(context.Background(), storage.Request{Config: cfg, Section: []byte("stale")}, implicit)
	if got := opened(t, st, err); got != "files:dir: x\n" {
		t.Errorf("opened %q, want the files backend with its own section", got)
	}

	cfg.Storage.Backend = "bare"
	st, err = storage.OpenConfigured(context.Background(), storage.Request{Config: cfg, Section: []byte("stale")}, implicit)
	if got := opened(t, st, err); got != "bare:" {
		t.Errorf("opened %q, want the bare backend with no section", got)
	}

	// The implicit backend stays available beside registered ones, and is what
	// a configuration naming nothing gets.
	st, err = storage.OpenConfigured(context.Background(), storage.Request{}, implicit)
	if got := opened(t, st, err); got != "sqlite:" {
		t.Errorf("opened %q, want the implicit backend", got)
	}
}

func TestOpenConfigured_NamesTheBackendsInForceWhenTheConfiguredOneIsAbsent(t *testing.T) {
	t.Cleanup(storage.ResetRegistry)
	implicit := backend("sqlite", "sqlite")
	req := storage.Request{Config: domain.Config{Storage: domain.StorageConfig{Backend: "postgres"}}}

	_, err := storage.OpenConfigured(context.Background(), req, implicit)
	if !errors.Is(err, storage.ErrBackendNotRegistered) ||
		err.Error() != `backend "postgres" is not registered in this binary (registered: sqlite)` {
		t.Errorf("with nothing registered: %v", err)
	}

	if rerr := storage.Register(backend("memory", "")); rerr != nil {
		t.Fatal(rerr)
	}
	_, err = storage.OpenConfigured(context.Background(), req, implicit)
	if err == nil || err.Error() != `backend "postgres" is not registered in this binary (registered: memory, sqlite)` {
		t.Errorf("with memory registered: %v", err)
	}

	if rerr := storage.Register(implicit); rerr != nil {
		t.Fatal(rerr)
	}
	_, err = storage.OpenConfigured(context.Background(), req, implicit)
	if err == nil || err.Error() != `backend "postgres" is not registered in this binary (registered: memory, sqlite)` {
		t.Errorf("with sqlite registered too: %v", err)
	}
}

func TestNotFoundError_NamesWhereItLooked(t *testing.T) {
	err := &storage.NotFoundError{Location: "/r/mirror.db"}
	if err.Error() != "no store at /r/mirror.db" {
		t.Errorf("Error() = %q", err.Error())
	}
}
