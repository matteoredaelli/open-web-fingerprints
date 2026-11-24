// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package fingerprinthub extracts fingerprints from
// https://github.com/0x727/FingerprintHub (web-fingerprint/), the database of
// the observer_ward scanner. The files are nuclei-style templates, so the
// reading is the one of the nuclei extractor; this package only gives it the
// identity and the directory of this source. Favicon matchers (md5 or mmh3
// hashes) are read as favicon_hash rules.
package fingerprinthub

import "github.com/matteoredaelli/open-web-fingerprints/internal/extractor/nuclei"

// ID is the stable extractor identifier.
const ID = "fingerprinthub"

// Root is the directory of the snapshot that is read.
const Root = "web-fingerprint"

// New returns the FingerprintHub extractor.
func New() *nuclei.Extractor {
	return nuclei.NewFor(ID, "FingerprintHub web fingerprints", Root)
}
