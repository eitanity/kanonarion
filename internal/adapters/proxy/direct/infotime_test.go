package direct_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	proxyadapter "code.eitanity.com/kanonarion/internal/adapters/proxy/direct"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
)

// The proxy's .info Time is decoded as the instant it names, and an .info with
// none decodes to the zero time, which the record keeps as unknown.
func TestProxy_Info_DecodesTime(t *testing.T) {
	for body, want := range map[string]time.Time{
		`{"Version":"v0.42.0","Time":"2026-09-08T16:29:55Z"}`: time.Date(2026, 9, 8, 16, 29, 55, 0, time.UTC),
		`{"Version":"v0.42.0"}`:                               {},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("writing .info: %v", err)
			}
		}))
		p, err := proxyadapter.New(srv.URL, true)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		info, err := p.Info(context.Background(), coordinatetest.MustNew("golang.org/x/text", "v0.42.0"))
		srv.Close()
		if err != nil {
			t.Fatalf("Info(%s): %v", body, err)
		}
		if !info.Time.Equal(want) || info.Time.IsZero() != want.IsZero() {
			t.Errorf("Info(%s).Time = %v, want %v", body, info.Time, want)
		}
	}
}
