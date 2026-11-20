// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package schemas embeds the public JSON Schemas of the open-web-fingerprints project
// and validates documents against them. It does not depend on any domain type, so a
// program can check a file without importing the rest of the project.
//
// There are three schemas:
//
//   - the registry export written by `owf export` (RegistrySchema, ValidateRegistry);
//   - the result of a scan written by `owfscan scan --json` (ScanResultSchema,
//     ValidateScanResult), whose Go types are in the scan package;
//   - the files of validation cases that test fingerprints (CasesSchema,
//     ValidateCases).
//
// Every Validate function returns nil when the document satisfies the schema and an
// error that names the first places where it does not. The Schema functions return a
// copy of the raw schema, for tools that want to compile it themselves.
//
// The schemas are drafts (versions 0.x) and change between releases. A document is
// valid only for the version of the schema in the module that validates it.
package schemas

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed registry.schema.json
var registrySchema []byte

const registryURL = "https://github.com/matteoredaelli/open-web-fingerprints/schemas/registry.schema.json"

// RegistrySchema returns the raw JSON Schema of the registry export.
func RegistrySchema() []byte { return append([]byte(nil), registrySchema...) }

// ValidateRegistry validates a JSON document against the registry schema.
func ValidateRegistry(doc []byte) error {
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(registrySchema))
	if err != nil {
		return fmt.Errorf("parse schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(registryURL, schemaDoc); err != nil {
		return fmt.Errorf("add schema: %w", err)
	}
	sch, err := c.Compile(registryURL)
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
