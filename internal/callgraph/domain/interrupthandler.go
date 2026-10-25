package domain

import (
	"errors"
	"fmt"
	"strconv"
)

// HandlerKind names the call that installs a function as a hardware interrupt
// handler by value.
type HandlerKind string

// HandlerInterruptNew is TinyGo's runtime/interrupt.New(id, handler).
const HandlerInterruptNew HandlerKind = "interrupt.New"

// ErrInvalidInterruptHandler is returned for a handler fact no extraction would
// record: an unknown kind, or a registration with no site.
var ErrInvalidInterruptHandler = errors.New("invalid interrupt handler")

// InterruptHandler records that a function is installed as a hardware interrupt
// handler by value, and where. The zero value means it is not. A handler whose
// registration nothing reaches is still an entry point: rooting it can only
// add paths, never hide one.
type InterruptHandler struct {
	Kind HandlerKind
	// Site is the registration call, rendered as positions are. A handler
	// registered at several sites carries the first in file, then line, order.
	Site SourcePosition
}

// NewInterruptHandler builds a handler fact, refusing every shape Validate
// refuses and the zero value.
func NewInterruptHandler(kind HandlerKind, site SourcePosition) (InterruptHandler, error) {
	h := InterruptHandler{Kind: kind, Site: site}
	if h.IsZero() {
		return InterruptHandler{}, fmt.Errorf("%w: no kind", ErrInvalidInterruptHandler)
	}
	if err := h.Validate(); err != nil {
		return InterruptHandler{}, err
	}
	return h, nil
}

// IsZero reports whether the function carries no handler fact.
func (h InterruptHandler) IsZero() bool { return h == InterruptHandler{} }

// Validate accepts the zero value and every fact NewInterruptHandler builds. It
// is applied on both legs of the store, as ExportDirective's is.
func (h InterruptHandler) Validate() error {
	if h.IsZero() {
		return nil
	}
	if h.Kind != HandlerInterruptNew {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidInterruptHandler, h.Kind)
	}
	if h.Site.File == "" || h.Site.Line <= 0 {
		return fmt.Errorf("%w: %s needs a registration site, got %q:%d", ErrInvalidInterruptHandler, h.Kind, h.Site.File, h.Site.Line)
	}
	return nil
}

// SiteString renders the registration site as file:line, and "" for the zero value.
func (h InterruptHandler) SiteString() string {
	if h.IsZero() {
		return ""
	}
	return h.Site.File + ":" + strconv.Itoa(h.Site.Line)
}
