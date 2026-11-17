// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package normalizer

import (
	"fmt"
	"sync"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// IDAllocator returns the canonical ID for an upstream record. Calling it
// again with the same (sourceID, key) must return the same ID, so importing
// the same revision twice never creates duplicates. The key is namespaced by
// the caller, for example "technology:WordPress".
//
// A repository-backed implementation will persist the mapping; the
// normalizer only depends on this interface.
type IDAllocator interface {
	Allocate(kind domain.Kind, sourceID, key string) (string, error)
}

// MemoryAllocator is an in-memory IDAllocator that generates UUIDv7 IDs.
type MemoryAllocator struct {
	mu  sync.Mutex
	ids map[string]string
	gen func(domain.Kind) (string, error)
}

// NewMemoryAllocator returns an allocator using domain.NewID.
func NewMemoryAllocator() *MemoryAllocator {
	return &MemoryAllocator{ids: map[string]string{}, gen: domain.NewID}
}

// Allocate implements IDAllocator.
func (m *MemoryAllocator) Allocate(kind domain.Kind, sourceID, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := fmt.Sprintf("%s|%s|%s", kind, sourceID, key)
	if id, ok := m.ids[k]; ok {
		return id, nil
	}
	id, err := m.gen(kind)
	if err != nil {
		return "", err
	}
	m.ids[k] = id
	return id, nil
}
