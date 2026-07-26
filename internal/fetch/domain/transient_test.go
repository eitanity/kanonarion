package domain_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"syscall"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// wrapped nests err a couple of layers deep the way the fetch path does
// ("inner fetcher: fetching module: proxy download: ...") so classification is
// exercised through the same wrapping the walker sees.
func wrapped(err error) error {
	return fmt.Errorf("inner fetcher: %w", fmt.Errorf("fetching module: %w", err))
}

func TestIsTransientFetchError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Transient: HTTP/2 stream resets received mid-download.
		{
			name: "http2 stream internal error",
			err:  errors.New("proxy download: reading zip: stream error: stream ID 587; INTERNAL_ERROR; received from peer"),
			want: true,
		},
		{
			name: "http2 stream refused",
			err:  errors.New("proxy download: stream error: stream ID 3; REFUSED_STREAM"),
			want: true,
		},
		{
			name: "http2 stream cancel",
			err:  errors.New("proxy download: stream error: stream ID 9; CANCEL; received from peer"),
			want: true,
		},
		{
			name: "http2 goaway internal error without stream error prefix",
			err:  errors.New("http2: server sent GOAWAY and closed the connection; ErrCode=INTERNAL_ERROR"),
			want: true,
		},
		// Transient: connection-level failures.
		{
			name: "connection reset by peer",
			err:  wrapped(syscall.ECONNRESET),
			want: true,
		},
		{
			name: "unexpected EOF mid transfer",
			err:  wrapped(io.ErrUnexpectedEOF),
			want: true,
		},
		// Transient: proxy status responses.
		{
			name: "proxy 500",
			err:  wrapped(&domain2.ProxyStatusError{StatusCode: 500, URL: "https://proxy.golang.org/x/@v/v1.zip"}),
			want: true,
		},
		{
			name: "proxy 503",
			err:  &domain2.ProxyStatusError{StatusCode: 503, URL: "https://proxy.golang.org"},
			want: true,
		},
		{
			name: "proxy 429 rate limited",
			err:  &domain2.ProxyStatusError{StatusCode: 429, URL: "https://proxy.golang.org"},
			want: true,
		},
		// Non-transient: definitive answers about the module.
		{
			name: "proxy 403",
			err:  &domain2.ProxyStatusError{StatusCode: 403, URL: "https://proxy.golang.org"},
			want: false,
		},
		{
			name: "proxy 410 gone",
			err:  &domain2.ProxyStatusError{StatusCode: 410, URL: "https://proxy.golang.org"},
			want: false,
		},
		{
			name: "not found",
			err:  wrapped(errors.New("not found: https://proxy.golang.org/x/@v/v9.info")),
			want: false,
		},
		{
			name: "checksum mismatch",
			err:  wrapped(errors.New("checksum mismatch: go.sum says h1:aaa, proxy served h1:bbb")),
			want: false,
		},
		{
			name: "verification failure",
			err:  wrapped(errors.New("go.sum verification failed: tampered")),
			want: false,
		},
		// Non-transient: cancellation, even when the transport message underneath
		// reads like a reset.
		{
			name: "context canceled",
			err:  wrapped(context.Canceled),
			want: false,
		},
		{
			name: "context deadline exceeded",
			err:  wrapped(context.DeadlineExceeded),
			want: false,
		},
		{
			name: "cancellation reported as a reset",
			err:  fmt.Errorf("connection reset by peer: %w", context.Canceled),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain2.IsTransientFetchError(tc.err); got != tc.want {
				t.Errorf("IsTransientFetchError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestProxyStatusErrorMessage(t *testing.T) {
	err := &domain2.ProxyStatusError{StatusCode: 502, URL: "https://proxy.golang.org/x/@v/list"}
	const want = "HTTP 502 from https://proxy.golang.org/x/@v/list"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// A ProxyStatusError must remain recoverable through wrapping, since the
// classifier only sees it several fmt.Errorf layers down.
func TestProxyStatusErrorUnwrapsFromChain(t *testing.T) {
	var pse *domain2.ProxyStatusError
	if !errors.As(wrapped(&domain2.ProxyStatusError{StatusCode: 500}), &pse) {
		t.Fatal("errors.As did not recover *ProxyStatusError from the wrapped chain")
	}
	if pse.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", pse.StatusCode)
	}
}
