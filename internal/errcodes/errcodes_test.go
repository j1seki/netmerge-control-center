package errcodes

import (
	"os"
	"strings"
	"testing"
)

// The registry is the one place codes are explained; these tests keep it usable. They are not
// simulations of anything - they check the real catalog.

func TestRegistryIsSelfConsistent(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("the registry is empty")
	}
	for _, e := range all {
		if e.Code == "" || e.Meaning == "" {
			t.Errorf("entry %+v has an empty code or meaning", e)
		}
		switch e.Kind {
		case KindError, KindSafety:
			// An error or a refusal that cannot say what to do next is the thing this registry
			// exists to prevent.
			if e.Fix == "" {
				t.Errorf("%s (%s) has no suggested next step", e.Code, e.Kind)
			}
		case KindEvent:
			// Events record what happened; a fix is not required, and inventing one would be noise.
		default:
			t.Errorf("%s has unknown kind %q", e.Code, e.Kind)
		}
		if got, ok := Lookup(e.Code); !ok || got.Code != e.Code {
			t.Errorf("%s is not reachable through Lookup", e.Code)
		}
	}
}

func TestLookupUnknownCodeIsNotInvented(t *testing.T) {
	if e, ok := Lookup("dashboard_never_heard_of_this"); ok {
		t.Errorf("Lookup invented an entry: %+v", e)
	}
}

func TestCodesAreSortedAndUnique(t *testing.T) {
	codes := Codes()
	seen := map[string]bool{}
	for i, c := range codes {
		if seen[c] {
			t.Errorf("duplicate code %s", c)
		}
		seen[c] = true
		if i > 0 && codes[i-1] >= c {
			t.Errorf("codes are not sorted: %q before %q", codes[i-1], c)
		}
	}
}

func TestDocumentationListsEveryCode(t *testing.T) {
	// The document is generated from this registry by ./docgen; this test is what makes a
	// forgotten regeneration fail loudly instead of leaving a stale table on disk.
	b, err := os.ReadFile("../../docs/ERROR-CODES.md")
	if err != nil {
		t.Fatalf("docs/ERROR-CODES.md: %v", err)
	}
	doc := string(b)
	for _, c := range Codes() {
		if !strings.Contains(doc, "| `"+c+"` |") {
			t.Errorf("docs/ERROR-CODES.md does not list %s; regenerate it with: go run ./internal/errcodes/docgen > docs/ERROR-CODES.md", c)
		}
	}
}
