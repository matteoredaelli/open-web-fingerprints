package domain

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// The Go model must round-trip the public example without losing or
// inventing fields, and its output must satisfy the JSON Schema.
func TestRegistryRoundTrip(t *testing.T) {
	orig, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(orig))
	dec.DisallowUnknownFields()
	var r Registry
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("decode strictly: %v", err)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateRegistry(out); err != nil {
		t.Fatalf("re-encoded registry invalid: %v", err)
	}
	var a, b any
	if err := json.Unmarshal(orig, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("round trip changed the document")
	}
}

func TestNewID(t *testing.T) {
	a, err := NewID(KindTechnology)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewID(KindTechnology)
	if a == b || !strings.HasPrefix(a, "tech_") {
		t.Fatalf("bad ids %q %q", a, b)
	}
	if a >= b {
		t.Fatalf("ids must be time ordered: %q >= %q", a, b)
	}
}
