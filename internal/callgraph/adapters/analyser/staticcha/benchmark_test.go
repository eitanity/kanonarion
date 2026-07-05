package staticcha_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
)

func BenchmarkAnalyse_Basic(b *testing.B) {
	a := staticcha.New("0.1.0", "", slog.Default())
	zipData := makeZip(b, testCoord, testModuleFiles)
	ctx := context.Background()

	// Write to temp file once to avoid filesystem overhead in the loop
	f, err := os.CreateTemp("", "kanonarion-bench-*.zip")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, io.NopCloser(bytes.NewReader(zipData))); err != nil {
		b.Fatal(err)
	}
	zipPath := f.Name()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := a.Analyse(ctx, zipPath, testCoord)
		if err != nil {
			b.Fatalf("Analyse returned error: %v", err)
		}
	}
}
