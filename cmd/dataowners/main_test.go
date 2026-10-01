package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
)

// The manifest Terraform reads by default (deploy/terraform/data-owners.json)
// is the template's registry as this command prints it: a change to the
// registry that is not regenerated there would deploy the wrong services or
// grant decrypt to the wrong ones. Regenerate it with
//
//	go run ./cmd/dataowners > deploy/terraform/data-owners.json
func TestTerraformManifestMatchesTheRegistry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "terraform", "data-owners.json"))
	if err != nil {
		t.Fatal(err)
	}
	var committed dataowner.Manifest
	if err := json.Unmarshal(raw, &committed); err != nil {
		t.Fatalf("deploy/terraform/data-owners.json: %v", err)
	}
	want := dataowner.Default.Manifest()
	if !reflect.DeepEqual(committed, want) {
		got, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("deploy/terraform/data-owners.json is not the registry; regenerate it with go run ./cmd/dataowners. The registry prints:\n%s", got)
	}
}
