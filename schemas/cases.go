// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package schemas

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed validation-cases.schema.json
var casesSchema []byte

const casesURL = "https://github.com/matteoredaelli/open-web-fingerprints/schemas/validation-cases.schema.json"

// CasesSchema returns the raw JSON Schema of validation case files.
func CasesSchema() []byte { return append([]byte(nil), casesSchema...) }

// ValidateCases validates a validation case file against its schema.
func ValidateCases(doc []byte) error {
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(casesSchema))
	if err != nil {
		return fmt.Errorf("parse schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(casesURL, schemaDoc); err != nil {
		return fmt.Errorf("add schema: %w", err)
	}
	sch, err := c.Compile(casesURL)
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("parse document: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	return nil
}
