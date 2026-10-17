package cli

import (
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	cganalyser "github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// hostFrame is the frame an undeclared read selects, which a record seeded into
// a real store must carry for that read to be served it.
func hostFrame() cgdomain.BuildFrame {
	return cganalyser.DeclaredFrame(goenv.Target{}, goenv.TinyGo{})
}
