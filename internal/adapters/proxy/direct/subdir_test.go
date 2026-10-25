package direct_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// The Origin's Subdir names where in the repository a module lives; a proxy that
// omits it describes a module at the repository root.
func TestProxy_Info_DecodesOriginSubdir(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "with Subdir",
			body: `{"Version":"v3.6.14","Time":"2026-01-01T00:00:00Z","Origin":{"VCS":"git","URL":"https://github.com/etcd-io/etcd","Subdir":"client","Hash":"0123456789abcdef0123456789abcdef01234567","Ref":"refs/tags/client/v3.6.14"}}`,
			want: "client",
		},
		{
			name: "without Subdir",
			body: `{"Version":"v3.6.14","Time":"2026-01-01T00:00:00Z","Origin":{"VCS":"git","URL":"https://github.com/etcd-io/etcd","Hash":"0123456789abcdef0123456789abcdef01234567","Ref":"refs/tags/v3.6.14"}}`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Errorf("writing .info: %v", err)
				}
			}))
			defer srv.Close()
			p, err := proxyadapter.New(srv.URL, true)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			info, err := p.Info(context.Background(), coordinatetest.MustNew("go.etcd.io/etcd/client/v3", "v3.6.14"))
			if err != nil {
				t.Fatalf("Info: %v", err)
			}
			if info.Origin == nil {
				t.Fatal("Origin is nil")
			}
			if info.Origin.Subdir != tc.want {
				t.Errorf("Origin.Subdir = %q, want %q", info.Origin.Subdir, tc.want)
			}
		})
	}
}
