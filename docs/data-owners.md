# Data owners

Every service that holds an org's data, or a person's, is in one registry,
[pkg/dataowner](../pkg/dataowner/dataowner.go), with where it is and what it
answers. Offboarding, exports, account deletion, access to the per-org
encryption keys and service tokens all read it; none of them names a
service. A product's service joins every one of them by being registered.

| capability | the service answers | who calls |
| --- | --- | --- |
| `export` | `GET /v1/internal/organizations/{org_id}/data` (the org export) and `GET /v1/internal/users/{user_id}/data` (a person's) | organization, in the export pass |
| `purge` | `DELETE /v1/internal/organizations/{org_id}/data`, answering how many rows remain | organization, 30 days after an org closes |
| `erase` | `DELETE /v1/internal/organizations/{org_id}/memberships/{membership_id}/data`, 204 | user, when a person's account is deleted |
| `decrypt` | nothing: it may fetch the org's wrapped data key and KMS lets it unwrap it | the service itself ([encryption.md](encryption.md)) |

The shapes are [pkg/orgdata](../pkg/orgdata/orgdata.go)'s. The template
registers its own:

| owner | export | purge | erase | decrypt |
| --- | --- | --- | --- | --- |
| notification | yes | yes | yes | |
| billing | yes | yes | | |
| authorization | yes | yes | | |
| identity | yes | yes | | yes |
| user | yes | yes | | |
| webhooks | yes | yes | | yes |
| audit | yes | yes, last | | |

The organization service holds its own data and handles it in place.

## Registering a product's service

In code, in the `main` of every service that reads the registry, before
serving:

```go
dataowner.Default.Register(dataowner.Owner{Name: "projects", Export: true, Purge: true, Erase: true})
```

or, running the template's services unchanged, in their configuration. Every
template service reads `DATA_OWNERS` at start:

```sh
DATA_OWNERS='[{"name":"projects","url":"http://projects:8080","export":true,"purge":true,"erase":true,"decrypt":false}]'
```

- `name` is the service's name: lower case, a letter first, letters, digits
  and hyphens. It is the name its service tokens carry.
- `url` is its base URL. Left out, it is read from `<NAME>_URL`
  (`PROJECTS_URL`; `project-files` reads `PROJECT_FILES_URL`), which is how
  the template's own are configured. The organization service needs one for
  every owner that exports or purges, the user service for every owner that
  erases; a missing one fails start and names the setting.
- An entry with no capability is a service that holds nothing here but
  calls the template's services with its own token.
- Owners are purged in registration order, then audit, because the others'
  purges are audited.

Being registered is also what makes the name a service everywhere:
`auth.KnownService` is a service registered in `pkg/db` in this process or
in the registry, so the identity service issues it a token and every other
service accepts one. A product service that registers its schema in its own
process is still unknown to the template's services until it is a data
owner (or a caller-only entry).

## Nothing is skipped

- **Export.** The pass asks every exporter in turn. One that fails, or
  answers anything but 200, blocks the export: no archive is made, the
  export stays `pending` with `blocked_by` naming the owner, and the pass is
  retried within the hour. The third failed attempt makes it `failed`, still
  naming the owner.

  ```json
  {"id":"…","kind":"organization","status":"pending","requested_at":"…","blocked_by":"projects"}
  ```

- **Purge.** Every purger in order, each checked: an error, or rows left,
  stops the purge there. The org stays, its closing record intact, the pass
  error names the owner, and `organization.purge_blocked` (`{"blocked_by":
  "projects"}`) goes in the org's audit log. The next day's pass starts again.
- **Erase.** Each membership is erased at every eraser before it is ended
  and anonymised. One that fails stops the deletion there, so the person is
  neither anonymised nor tombstoned until the next pass has every owner
  forget them.

## For the deploy

Terraform grants KMS decrypt to the decrypting owners and nobody else, and
creates a service identity per owner. Both come from the same registry:

```sh
DATA_OWNERS='[…]' go run ./cmd/dataowners > data-owners.json
```

```json
{
  "owners": [
    {"name": "notification", "export": true, "purge": true, "erase": true, "decrypt": false},
    …
    {"name": "audit", "export": true, "purge": true, "erase": false, "decrypt": false, "purge_last": true}
  ],
  "decrypting": ["identity", "webhooks"]
}
```

```hcl
locals {
  data_owners = jsondecode(file("${path.module}/data-owners.json"))
  decrypting  = toset(local.data_owners.decrypting)
}
```

[deploy/terraform](../deploy/terraform/README.md) does this: the
template's manifest is committed there as `data-owners.json` (a test in
`cmd/dataowners` fails when it drifts from the registry), and a product
passes its own as `data_owners_file`.

URLs are left out: they are the deploy's own. A product that registers
owners in code prints its manifest with `dataowner.Default.Manifest()` from
a command of its own.
