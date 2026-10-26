package ports_test

import (
	"context"
	"errors"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

func TestDropSuperseded(t *testing.T) {
	ctx := context.Background()
	pub := coordinatetest.MustNew("example.com/m", "v1.0.0")
	local := coordinatetest.MustNew("example.com/m", coordinate.LocalVersion)
	ids := []string{"zip:a", "zip:b"}
	self := func(s string) string { return s }
	names := func(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) {
		return map[string]bool{"zip:a": true}, nil
	}

	if got, err := ports.DropSuperseded(ctx, names, pub, ids, self); err != nil || len(got) != 1 || got[0] != "zip:b" {
		t.Errorf("published = %v, %v; want [zip:b]", got, err)
	}
	if got, err := ports.DropSuperseded(ctx, names, local, ids, self); err != nil || len(got) != 2 {
		t.Errorf("a local coordinate's own generations are never left out: %v, %v", got, err)
	}
	if got, err := ports.DropSuperseded(ctx, nil, pub, ids, self); err != nil || len(got) != 2 {
		t.Errorf("no reader leaves every generation in: %v, %v", got, err)
	}
	failing := func(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) {
		return nil, errors.New("store gone")
	}
	if _, err := ports.DropSuperseded(ctx, failing, pub, ids, self); err == nil {
		t.Error("a reader that failed must fail the read, not compose everything")
	}
	if held, err := ports.HoldsSuperseded(ctx, names, "example.com/m", "v1.0.0"); err != nil || !held {
		t.Errorf("HoldsSuperseded = %v, %v; want true", held, err)
	}
	if held, err := ports.HoldsSuperseded(ctx, names, "example.com/m", coordinate.LocalVersion); err != nil || held {
		t.Errorf("a local key holds nothing superseded: %v, %v", held, err)
	}
	if held, err := ports.HoldsSuperseded(ctx, nil, "example.com/m", "v1.0.0"); err != nil || held {
		t.Errorf("no reader holds nothing superseded: %v, %v", held, err)
	}
}
