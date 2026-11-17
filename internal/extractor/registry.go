package extractor

import (
	"fmt"
	"sort"
)

// Registry resolves extractors by stable ID. It is an ordinary value passed
// explicitly, not a global.
type Registry struct {
	byID map[string]Extractor
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byID: map[string]Extractor{}} }

// Register adds an extractor. IDs must be non-empty and unique.
func (r *Registry) Register(e Extractor) error {
	id := e.ID()
	if id == "" {
		return fmt.Errorf("extractor has empty ID")
	}
	if _, dup := r.byID[id]; dup {
		return fmt.Errorf("extractor %q already registered", id)
	}
	r.byID[id] = e
	return nil
}

// Get returns the extractor with the given ID.
func (r *Registry) Get(id string) (Extractor, error) {
	e, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("unknown extractor %q", id)
	}
	return e, nil
}

// List returns all extractors sorted by ID.
func (r *Registry) List() []Extractor {
	out := make([]Extractor, 0, len(r.byID))
	for _, e := range r.byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
