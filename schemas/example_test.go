// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package schemas_test

import (
	"fmt"

	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// A document that is not valid says where.
func ExampleValidateScanResult() {
	err := schemas.ValidateScanResult([]byte(`{"schema_version": "0.1.0"}`))
	fmt.Println(err != nil)
	// Output: true
}

// The raw schema is for tools that want to compile it themselves.
func ExampleScanResultSchema() {
	raw := schemas.ScanResultSchema()
	fmt.Println(len(raw) > 0, raw[0] == '{')
	// Output: true true
}

func ExampleValidateCases() {
	doc := `{"schema_version": "0.1.0", "cases": [{
	  "id": "php-header-positive",
	  "rule": {"technology": "php", "observation": "http_header", "target": "Server"},
	  "input": {"headers": {"Server": "Apache/2.4 PHP/8.1"}},
	  "expect": {"match": true}
	}]}`
	fmt.Println(schemas.ValidateCases([]byte(doc)))
	// Output: <nil>
}
