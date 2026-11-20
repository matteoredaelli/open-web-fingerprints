// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package observe turns a fetched page into the observation the rules read:
// headers, cookies, HTML, the favicon hashes, DNS records and the certificate.
package observe

import (
	"crypto/md5" //nolint:gosec // identifies a favicon; not a security use
	"encoding/base64"
	"encoding/hex"
	"math/bits"
	"strconv"
)

// FaviconHashes returns the hashes that rules use for a favicon: the MD5 of the
// bytes (Recog) and the MurmurHash3 of the base64 encoding in the form used by
// Shodan and nuclei (the base64 is wrapped at 76 characters with a newline after
// each line, like Python's base64.encodebytes, and the 32-bit hash is signed).
func FaviconHashes(b []byte) map[string]string {
	sum := md5.Sum(b) //nolint:gosec // see import
	// The hash is a signed 32-bit value by convention.
	signed := int32(murmur3(shodanBase64(b))) //nolint:gosec // wrapping is intended
	return map[string]string{
		"md5":  hex.EncodeToString(sum[:]),
		"mmh3": strconv.Itoa(int(signed)),
	}
}

// shodanBase64 encodes like Python's base64.encodebytes.
func shodanBase64(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out []byte
	for len(enc) > 76 {
		out = append(out, enc[:76]...)
		out = append(out, '\n')
		enc = enc[76:]
	}
	if len(enc) > 0 {
		out = append(out, enc...)
		out = append(out, '\n')
	}
	return out
}

// murmur3 is MurmurHash3, x86 32-bit, seed 0.
func murmur3(data []byte) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[4*i]) | uint32(data[4*i+1])<<8 | uint32(data[4*i+2])<<16 | uint32(data[4*i+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	tail := data[4*n:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data)) //nolint:gosec // the algorithm takes the length modulo 2^32
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
