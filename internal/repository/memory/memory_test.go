// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package memory

import (
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/repositorytest"
)

func TestContract(t *testing.T) {
	repositorytest.Run(t, func(*testing.T) repository.Repository { return New() })
}
