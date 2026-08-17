package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// renderNoticeEntry renders one module entry and returns the document.
func renderNoticeEntry(t *testing.T, e licdomain.NoticeEntry) string {
	t.Helper()
	var buf bytes.Buffer
	if err := writeNoticeDocument(
		[]licdomain.NoticeEntry{e},
		map[coordinate.ModuleCoordinate]coordinate.ModuleCoordinate{},
		&buf,
	); err != nil {
		t.Fatalf("rendering notice: %v", err)
	}
	return buf.String()
}

// The gap this closes: gopkg.in/yaml.v3 is governed by MIT AND Apache-2.0, and
// the document stated only its primary. A reader building an obligations list
// from the License: lines missed Apache-2.0's attribution and NOTICE
// requirements for that module.
func TestNoticeDocument_ExpressionLineStatesTheWholeLicencePosition(t *testing.T) {
	doc := renderNoticeEntry(t, licdomain.NoticeEntry{
		Coordinate: coordinatetest.MustNew("example.com/dual", "v1.0.0"),
		SPDX:       "MIT",
		Expression: "Apache-2.0 AND MIT",
	})

	if !strings.Contains(doc, "\nLicense: MIT\n") {
		t.Error("the License: line must keep naming the primary; a consumer may parse it")
	}
	if !strings.Contains(doc, "\nLicense expression: Apache-2.0 AND MIT\n") {
		t.Errorf("expected the whole expression on its own line, got:\n%s", doc)
	}
}

// A single-licence module gains nothing from a second line saying the same
// thing twice, and the noise trains a reader to skip the line that matters.
func TestNoticeDocument_NoExpressionLineWhenItRepeatsThePrimary(t *testing.T) {
	doc := renderNoticeEntry(t, licdomain.NoticeEntry{
		Coordinate: coordinatetest.MustNew("example.com/single", "v1.0.0"),
		SPDX:       "MIT",
		Expression: "MIT",
	})

	if strings.Contains(doc, "License expression:") {
		t.Errorf("expression repeating the primary must not be emitted, got:\n%s", doc)
	}
}

// A record written before the expression field existed carries no expression.
// Absence is not a licence position, so nothing is stated.
func TestNoticeDocument_NoExpressionLineWhenUnrecorded(t *testing.T) {
	doc := renderNoticeEntry(t, licdomain.NoticeEntry{
		Coordinate: coordinatetest.MustNew("example.com/old", "v1.0.0"),
		SPDX:       "MIT",
	})

	if strings.Contains(doc, "License expression:") {
		t.Errorf("an absent expression must not be rendered, got:\n%s", doc)
	}
}
