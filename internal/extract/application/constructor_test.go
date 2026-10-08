package application

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// mustExtractUseCase fails the test when cfg is refused.
func mustExtractUseCase(tb testing.TB, cfg Config) *ExtractUseCase {
	tb.Helper()
	uc, err := NewExtractUseCase(cfg)
	if err != nil {
		tb.Fatalf("NewExtractUseCase: %v", err)
	}
	return uc
}

func completeConfig() Config {
	return Config{
		Runs:      &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)},
		Walks:     &mockWalkStore{walks: map[string]walkdomain.WalkRecord{}},
		Extractor: &mockExtractor{},
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
	}
}

func TestNewExtractUseCase_RefusesNilRequiredDependency(t *testing.T) {
	cases := map[string]func(*Config){
		"Runs":      func(c *Config) { c.Runs = nil },
		"Walks":     func(c *Config) { c.Walks = nil },
		"Extractor": func(c *Config) { c.Extractor = nil },
		"Stages":    func(c *Config) { c.Stages = nil },
		"Clock":     func(c *Config) { c.Clock = nil },
		"Stopwatch": func(c *Config) { c.Stopwatch = nil },
	}
	for name, unset := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := completeConfig()
			unset(&cfg)
			uc, err := NewExtractUseCase(cfg)
			if !errors.Is(err, ErrMissingDependency) {
				t.Fatalf("NewExtractUseCase with nil %s: err = %v, want ErrMissingDependency", name, err)
			}
			if !strings.HasSuffix(err.Error(), ": "+name) {
				t.Errorf("error %q does not name %s", err, name)
			}
			if uc != nil {
				t.Errorf("refused construction returned a use case")
			}
		})
	}
}

func TestNewExtractUseCase_AcceptsCompleteConfigWithoutLogger(t *testing.T) {
	cfg := completeConfig()
	cfg.Logger = nil
	if _, err := NewExtractUseCase(cfg); err != nil {
		t.Fatalf("NewExtractUseCase: %v", err)
	}
}
