// Package clavex provides a Go management SDK for the Clavex IAM API.
//
// # Quickstart
//
//	client, err := clavex.New("https://auth.example.com",
//	    clavex.WithCredentials("myorg", "admin@example.com", "password"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	users, err := client.Users.List(ctx, orgID)
package clavex
