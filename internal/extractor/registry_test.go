package extractor_test

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/extractortest"
)

type fake struct{ id string }

func (f fake) ID() string   { return f.id }
func (f fake) Name() string { return "Fake " + f.id }
func (f fake) Extract(ctx context.Context, _ extractor.Source) (*extractor.ExtractionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := 0.9
	return &extractor.ExtractionResult{
		Categories:   []extractor.ExtractedCategory{{Key: "1", Name: "CMS"}},
		Technologies: []extractor.ExtractedTechnology{{Key: "A", Name: "A", CategoryKeys: []string{"1"}}},
		Fingerprints: []extractor.ExtractedFingerprint{{
			TechnologyKey: "A", Observation: domain.ObsHTTPHeader, Target: "Server",
			Operator: domain.OpRegex, Pattern: "^a", RegexFlavor: domain.FlavorRE2, Confidence: &c,
		}},
	}, nil
}

func TestRegistry(t *testing.T) {
	r := extractor.NewRegistry()
	if err := r.Register(fake{"b"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(fake{"a"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(fake{"a"}); err == nil {
		t.Fatal("duplicate must fail")
	}
	if err := r.Register(fake{""}); err == nil {
		t.Fatal("empty ID must fail")
	}
	if _, err := r.Get("zzz"); err == nil {
		t.Fatal("unknown must fail")
	}
	l := r.List()
	if len(l) != 2 || l[0].ID() != "a" || l[1].ID() != "b" {
		t.Fatalf("List not sorted: %v", l)
	}
}

func TestContractWithFake(t *testing.T) {
	extractortest.RunContract(t, fake{"a"}, extractor.Source{ID: "s", FS: fstest.MapFS{}})
}
