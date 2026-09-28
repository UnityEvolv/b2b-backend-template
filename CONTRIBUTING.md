# Contributing

Thank you for helping. This file covers how to propose a change. The
architecture rules a change must follow are described in [docs/](docs/).

## Before you start

- For anything bigger than a small fix, open an issue first so the approach can
  be agreed before you write code.
- Security problems are reported privately. See [SECURITY.md](SECURITY.md).
- Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Making a change

1. Fork the repository and create a branch from `main`.
2. Keep the pull request small and focused on one thing.
3. Put tests beside the code they test.
4. Use [conventional commit](https://www.conventionalcommits.org/) messages, for
   example `feat(identity): ...` or `fix(billing): ...`.
5. Run the checks before opening the pull request:

   ```sh
   go build ./...
   go vet ./...
   go test ./...
   ```

   If you changed a query or an OpenAPI spec, regenerate the code with
   `scripts/generate.sh` and commit the result. CI fails when generated code
   drifts from its sources. Never edit generated code by hand.

## What every change must get right

- Input is validated, and permission is checked on the server.
- Every tenant query is scoped by an explicit `org_id`.
- Errors use the standard `{ code, message, fields? }` envelope.
- No personal data (names, emails) in logs, and no hostnames or product URLs in
  code.
- Anything the UI disables, the API also refuses.

## Licence

By contributing you agree that your contribution is licensed under the
[MIT licence](LICENSE).
