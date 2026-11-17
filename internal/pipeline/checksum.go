// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// checksumSnapshot hashes every selected file of a snapshot. The overall
// checksum covers sorted (path, file checksum) pairs, so it changes whenever
// any selected file is added, removed or edited.
func checksumSnapshot(fsys fs.FS, include func(string) bool) (string, []domain.SnapshotFile, error) {
	var files []domain.SnapshotFile
	overall := sha256.New()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if include != nil && !include(p) {
			return nil
		}
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return fmt.Errorf("hash %s: %w", p, err)
		}
		sum := "sha256:" + hex.EncodeToString(h.Sum(nil))
		files = append(files, domain.SnapshotFile{Path: p, Checksum: sum})
		overall.Write([]byte(p + "\x00" + sum + "\n"))
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("checksum snapshot: %w", err)
	}
	if len(files) == 0 {
		return "", nil, fmt.Errorf("checksum snapshot: no files selected")
	}
	return "sha256:" + hex.EncodeToString(overall.Sum(nil)), files, nil
}
