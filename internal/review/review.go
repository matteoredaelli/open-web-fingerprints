// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package review applies reviewer decisions about conflicts to the registry.
package review

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/merge"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// Request selects conflicts and the decision to apply to them.
type Request struct {
	// IDs resolves exactly these conflicts. Each must be open.
	IDs []domain.ConflictID
	// Otherwise the filter selects conflicts (open ones unless State is set).
	Kind     string
	Websites string // same_domain, different, unknown
	State    string
	// Bulk allows a filter-based selection; without IDs it is required.
	Bulk     bool
	Decision merge.Decision
	Note     string
	DryRun   bool
	Now      func() time.Time
}

// Result summarizes what a request did or, for DryRun, would do.
type Result struct {
	Selected      int
	Merged        int
	KeptSeparate  int
	AlreadyMerged int
	Skipped       int // closed meanwhile, for example superseded by an earlier merge
	Delete        repository.RecordIDs
	Aliases       int
	SelfRelations int
	Applied       bool
}

// Resolve loads the registry, applies the decisions in memory and stores the
// outcome as one atomic change set.
func Resolve(ctx context.Context, repo repository.Repository, req Request) (*Result, error) {
	if len(req.IDs) == 0 && !req.Bulk {
		return nil, fmt.Errorf("review: select conflicts by ID or use a bulk filter")
	}
	if req.Decision != merge.Merge && req.Decision != merge.KeepSeparate {
		return nil, fmt.Errorf("review: unknown decision %q", req.Decision)
	}
	now := time.Now
	if req.Now != nil {
		now = req.Now
	}
	all, err := repo.AllRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("review: load records: %w", err)
	}
	aliases, err := repo.Aliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("review: load aliases: %w", err)
	}
	known, err := repo.Conflicts(ctx)
	if err != nil {
		return nil, fmt.Errorf("review: load conflicts: %w", err)
	}
	ws := merge.NewWorkspace(all, aliases, known, func(k domain.Kind, key string) (string, error) {
		return repo.Allocate(k, "", key)
	}, now().UTC())

	selected, err := selectConflicts(known, req)
	if err != nil {
		return nil, err
	}
	res := &Result{Selected: len(selected)}
	for _, c := range selected {
		if req.Bulk && len(req.IDs) == 0 {
			// An earlier merge may have closed it.
			if cur := currentState(ws, known, c.ID); cur != domain.ConflictOpen {
				res.Skipped++
				continue
			}
		}
		err := ws.Decide(c.ID, req.Decision, req.Note)
		if err != nil {
			return nil, fmt.Errorf("review: %w", err)
		}
		if req.Decision == merge.KeepSeparate {
			res.KeptSeparate++
			continue
		}
		res.Merged++
	}
	cs := ws.ChangeSet()
	res.Delete, res.Aliases = cs.Delete, len(cs.Aliases)
	res.SelfRelations = ws.Stats().DroppedSelfRelationships
	if req.DryRun {
		return res, nil
	}
	if err := repo.Apply(ctx, cs); err != nil {
		return nil, fmt.Errorf("review: apply: %w", err)
	}
	res.Applied = true
	return res, nil
}

// currentState returns the state of a conflict inside the workspace.
func currentState(ws *merge.Workspace, known []domain.Conflict, id domain.ConflictID) string {
	if s, ok := ws.ConflictState(id); ok {
		return s
	}
	for _, c := range known {
		if c.ID == id {
			return c.State
		}
	}
	return ""
}

func selectConflicts(known []domain.Conflict, req Request) ([]domain.Conflict, error) {
	byID := map[domain.ConflictID]domain.Conflict{}
	for _, c := range known {
		byID[c.ID] = c
	}
	var out []domain.Conflict
	if len(req.IDs) > 0 {
		for _, id := range req.IDs {
			c, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("review: conflict %s not found", id)
			}
			out = append(out, c)
		}
		return out, nil
	}
	state := req.State
	if state == "" {
		state = domain.ConflictOpen
	}
	for _, c := range known {
		if c.State != state || (req.Kind != "" && c.Kind != req.Kind) ||
			(req.Websites != "" && c.Detail["websites"] != req.Websites) {
			continue
		}
		// A bulk merge only touches candidates; other kinds need a person.
		if req.Decision == merge.Merge && c.Kind != domain.ConflictIdentityCandidate && c.Kind != domain.ConflictCategoryCandidate {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
