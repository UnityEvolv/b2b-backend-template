// Command dataowners prints the data-owner registry (pkg/dataowner) as the
// deploy reads it: the template's owners and any in DATA_OWNERS, what each
// answers, and the ones that decrypt. Terraform grants KMS decrypt to that
// list and nothing else (docs/data-owners.md):
//
//	DATA_OWNERS='[{"name":"projects","export":true,"purge":true,"erase":true}]' \
//	  go run ./cmd/dataowners > data-owners.json
//
// A product with owners registered in code prints its own with
// dataowner.Default.Manifest() from a command of its own.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
)

func main() {
	if err := dataowner.Default.Load(os.Getenv("DATA_OWNERS")); err != nil {
		fmt.Fprintln(os.Stderr, "DATA_OWNERS:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(dataowner.Default.Manifest()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
