# Clavex Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/clavex-eu/clavex-sdk-go.svg)](https://pkg.go.dev/github.com/clavex-eu/clavex-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/clavex-eu/clavex-sdk-go)](https://goreportcard.com/report/github.com/clavex-eu/clavex-sdk-go)

Official Go management SDK for the [Clavex](https://github.com/clavex-eu/clavex) IAM API.

It covers organizations, users, roles & groups, OIDC/SAML/WS-Fed clients,
federation, FGA, PAM, governance, EUDI wallet (OID4VCI / OID4VP / mdoc),
CIBA, SSF, webhooks, SCIM and more.

## Install

```bash
go get github.com/clavex-eu/clavex-sdk-go
```

Requires Go 1.21+.

## Quickstart

```go
package main

import (
	"context"
	"log"

	clavex "github.com/clavex-eu/clavex-sdk-go"
)

func main() {
	client, err := clavex.New("https://auth.example.com",
		clavex.WithCredentials("myorg", "admin@example.com", "password"),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	users, err := client.Users.List(ctx, "org-id")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("found %d users", len(users))
}
```

## Documentation

Full API reference: [pkg.go.dev/github.com/clavex-eu/clavex-sdk-go](https://pkg.go.dev/github.com/clavex-eu/clavex-sdk-go).

## Versioning

Semantic versioning via git tags (`vX.Y.Z`). Breaking changes only on major bumps.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
