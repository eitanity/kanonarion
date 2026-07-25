package domain

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ProxyStatusError is returned by module-proxy adapters when the proxy answers
// with a status other than 200 or 404 (404 has its own not-found meaning). It
// carries the status code as data rather than only as message text so callers
// can classify the response — a 500 or 429 is a transient proxy condition worth
// retrying, while a 4xx is a definitive answer.
type ProxyStatusError struct {
	StatusCode int
	URL        string
}

func (e *ProxyStatusError) Error() string {
	return fmt.Sprintf("HTTP %d from %s", e.StatusCode, e.URL)
}

// transientMarkers are substrings that identify a transient transport failure
// in an error whose type cannot be inspected. The HTTP/2 stream errors raised
// mid-download by net/http's bundled http2 implementation use an unexported
// error type, and the connection-level errors surface as opaque wrapped
// *net.OpError chains, so message matching is the only classification available
// for them. Every marker is matched case-insensitively.
var transientMarkers = []string{
	// HTTP/2 stream resets received from the proxy mid-transfer. The go command
	// treats the same three codes as retryable.
	"stream error",
	"internal_error",
	"refused_stream",
	// Connection-level resets and truncated transfers.
	"connection reset by peer",
	"unexpected eof",
}

// IsTransientFetchError reports whether err describes a transient network
// condition that a later attempt is likely to get past: an HTTP/2 stream reset,
// a connection reset, a truncated transfer, or a 429 / 5xx answer from the
// module proxy.
//
// It is deliberately a positive-match classifier: anything it does not
// recognise is treated as permanent and fails on the first attempt. A checksum
// mismatch, a verification failure or a not-found version is a real answer
// about the module, and retrying it would only delay recording a genuine
// failure. Context cancellation and deadline expiry are excluded up front —
// the caller has stopped caring about the result, and the errno-level messages
// a cancelled transfer produces would otherwise read as transient.
func IsTransientFetchError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var pse *ProxyStatusError
	if errors.As(err, &pse) {
		return isTransientStatus(pse.StatusCode)
	}
	msg := strings.ToLower(err.Error())
	for _, m := range transientMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// isTransientStatus reports whether an HTTP status from the module proxy is a
// retryable condition: rate limiting or a server-side failure.
func isTransientStatus(code int) bool {
	const tooManyRequests = 429
	return code == tooManyRequests || (code >= 500 && code <= 599)
}
