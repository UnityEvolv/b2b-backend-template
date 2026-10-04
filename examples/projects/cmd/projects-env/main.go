// Command projects-env prints what a deployment sets on the template's
// services so they know the example product, from the values the product
// declares in code (package product):
//
//	PLANS                    on the organization, user, billing and webhooks services
//	PERMISSION_GROUPS        on the authorization service
//	NOTIFICATION_CATEGORIES  on the notification service
//	DATA_OWNERS              on every template service
//	WEBHOOK_EVENTS           on the webhooks service
//
// as NAME='value' lines a shell or an env file reads. PROJECTS_URL, where
// the service runs, is the deployment's own and is set beside them on the
// organization and user services.
package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
)

func main() {
	env := product.Env()
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%s='%s'\n", name, strings.ReplaceAll(env[name], "'", `'\''`))
	}
}
