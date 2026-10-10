package staticcha

import (
	"go/types"
	"testing"

	"golang.org/x/tools/go/types/typeutil"
)

// The analyser's typeutil indexes hold one value type each. A read of an
// unseen key is an empty answer; a value of any other type is a bug and must
// stop the analysis rather than read as an empty answer.
func TestTypeIndexesReadUnseenAsEmptyAndRefuseForeignValues(t *testing.T) {
	var m typeutil.Map
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	if got := funcsWithSig(&m, sig); got != nil {
		t.Fatalf("unseen signature: got %v, want nil", got)
	}
	if got := visitStateOf(&m, sig); got != nil {
		t.Fatalf("unseen type: got %v, want nil", got)
	}
	m.Set(sig, "foreign")
	for name, read := range map[string]func(){
		"funcsWithSig": func() { funcsWithSig(&m, sig) },
		"visitStateOf": func() { visitStateOf(&m, sig) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s read a foreign value without refusing", name)
				}
			}()
			read()
		})
	}
}
