package domain

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
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

// ProxyEmptyResponseError is returned by module-proxy adapters when the proxy
// answers a lookup with 200 and a zero-length body. Nothing is settled by it:
// the request was accepted, no answer came back, and the same request moments
// later returns the module's real answer.
//
// It is a TYPE rather than a message, for the reason ProxyStatusError is one:
// the condition is classified by callers deciding whether to retry, and a
// classifier that matched on the sentence would break the next time the
// sentence is reworded.
type ProxyEmptyResponseError struct {
	// Path is the module path whose lookup came back empty.
	Path string
}

func (e *ProxyEmptyResponseError) Error() string {
	return fmt.Sprintf("proxy returned an empty response for %s@latest", e.Path)
}

// ProxyRequestTimeoutError is returned by module-proxy adapters when a request
// exceeded a deadline the ADAPTER imposed on it, with the caller's own context
// still live.
//
// It exists because the two events that produce an identical
// context.DeadlineExceeded are opposites for a caller deciding whether to ask
// again. The caller cancelling, or the caller's own deadline passing, means the
// answer is no longer wanted and a retry would be work nobody asked for. The
// adapter's own request deadline firing means the proxy did not answer in the
// time this adapter was willing to wait — a transport condition about the
// network, with no caller involvement at all, and exactly the case a retry is
// for.
//
// The distinction is drawn STRUCTURALLY, at the only place that can draw it:
// the adapter compares its own derived request context against the caller's.
// It is not drawn by matching the message, which today differs only by the
// parenthetical net/http appends to a Client.Timeout and would stop working the
// next time that sentence is reworded.
type ProxyRequestTimeoutError struct {
	// URL is the request that ran out of time.
	URL string
	// Timeout is the deadline the adapter imposed.
	Timeout time.Duration
	// Err is the underlying deadline error, kept for unwrapping.
	Err error
}

func (e *ProxyRequestTimeoutError) Error() string {
	return fmt.Sprintf("proxy request to %s exceeded the %s adapter timeout: %v", e.URL, e.Timeout, e.Err)
}

// Unwrap exposes the underlying deadline error. IsTransientFetchError inspects
// this type BEFORE its context guard precisely because unwrapping reaches
// context.DeadlineExceeded: the guard is about the caller's intent, and this
// type is the statement that the caller had no part in it.
func (e *ProxyRequestTimeoutError) Unwrap() error { return e.Err }

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
// a connection reset, a truncated transfer, an empty 200 body, a 429 / 5xx
// answer from the module proxy, or a request that outran the deadline the
// adapter itself imposed.
//
// It is deliberately a positive-match classifier: anything it does not
// recognise is treated as permanent and fails on the first attempt. A checksum
// mismatch, a verification failure or a not-found version is a real answer
// about the module, and retrying it would only delay recording a genuine
// failure. Cancellation and deadline expiry that came from the CALLER'S
// context are excluded up front — the caller has stopped caring about the
// result, and the errno-level messages a cancelled transfer produces would
// otherwise read as transient. A deadline the adapter imposed on its own
// request is a different event with the same error value, so it is carried as
// ProxyRequestTimeoutError and recognised before that exclusion runs.
func IsTransientFetchError(err error) bool {
	if err == nil {
		return false
	}
	// Checked ahead of the context guard below: an adapter-imposed request
	// timeout unwraps to context.DeadlineExceeded, so the guard would otherwise
	// reject it as the caller having stopped caring, which is the one thing it
	// is not.
	if _, ok := errors.AsType[*ProxyRequestTimeoutError](err); ok {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if pse, ok := errors.AsType[*ProxyStatusError](err); ok {
		return isTransientStatus(pse.StatusCode)
	}
	if _, ok := errors.AsType[*ProxyEmptyResponseError](err); ok {
		return true
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
