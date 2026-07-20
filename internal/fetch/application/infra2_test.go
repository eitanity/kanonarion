package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestExecute_GithubTwoPartPath(t *testing.T) {
	// github.com/foo — only 2 path parts, can't infer full repo URL.
	// With sumdb disabled the overall status is UnverifiedNoSumDB.
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo", Version: "v1.0.0"}
	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("expected UnverifiedNoSumDB, got %q", result.Record.VerificationStatus)
	}
}

func TestExecute_GopkgIn(t *testing.T) {
	// gopkg.in module: can't infer VCS URL. With sumdb disabled → UnverifiedNoSumDB.
	coord := coordinate.ModuleCoordinate{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}
	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("expected UnverifiedNoSumDB, got %q", result.Record.VerificationStatus)
	}
}
