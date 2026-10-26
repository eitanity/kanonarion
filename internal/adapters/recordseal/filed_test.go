package recordseal_test

import (
	"errors"
	"fmt"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
)

func TestCheckFiled_AgreeingValuesPass(t *testing.T) {
	if err := recordseal.CheckFiled("licence record", "licence_records", "remedy",
		recordseal.Key("a@v1", "a@v1"), recordseal.Column("goos", "frame.goos", "linux", "linux")); err != nil {
		t.Fatalf("CheckFiled = %v, want nil", err)
	}
}

func TestCheckFiled_StatesTheFirstDisagreement(t *testing.T) {
	recordseal.SetStoreLocation("/store/mirror.db")
	t.Cleanup(func() { recordseal.SetStoreLocation("") })
	for _, tc := range []struct {
		name   string
		values []recordseal.Filed
		want   string
	}{
		{"key", []recordseal.Filed{recordseal.Key("a@v1", "b@v2"), recordseal.Column("goos", "frame.goos", "x", "y")},
			"walk record filed under a@v1 is sealed as b@v2 (table walks in the store at /store/mirror.db); restore it"},
		{"column", []recordseal.Filed{recordseal.Key("a@v1", "a@v1"), recordseal.Column("goos", "graph.build_env.goos", "windows", "linux")},
			"goos windows does not match the sealed graph.build_env.goos linux of the walk record it selected (table walks in the store at /store/mirror.db); restore it"},
		{"blank column", []recordseal.Filed{recordseal.Column("goarm", "frame.goarm", "", "7")},
			`goarm "" does not match the sealed frame.goarm 7 of the walk record it selected (table walks in the store at /store/mirror.db); restore it`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := recordseal.CheckFiled("walk record", "walks", "restore it", tc.values...)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v\nwant %s", err, tc.want)
			}
			if !recordseal.IsMisfiled(fmt.Errorf("wrapped: %w", err)) {
				t.Error("a wrapped refusal is not recognised as misfiled")
			}
		})
	}
}

func TestCheckFiled_NamesNoStoreOrRemedyItWasNotGiven(t *testing.T) {
	recordseal.SetStoreLocation("")
	err := recordseal.CheckFiled("walk record", "walks", "", recordseal.Key("a", "b"))
	if want := "walk record filed under a is sealed as b (table walks)"; err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %s", err, want)
	}
	if recordseal.IsMisfiled(errors.New("walk record filed under a")) {
		t.Error("a plain error is reported as misfiled")
	}
}
