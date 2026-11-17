// Package schemas embeds the public JSON Schema of the registry export and
// offers a validation helper. It does not depend on any domain type.
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
