package clavex_test

import (
	"context"
	"net/http"
	"testing"

	clavex "github.com/clavex-eu/clavex-sdk-go"
)

func TestFGAService(t *testing.T) {
	ms := clavex.NewMockServer()
	defer ms.Close()
	const orgID = "org-1"
	base := "/api/v1/organizations/" + orgID

	ms.Respond("POST", base+"/fga/check", 200, map[string]bool{"allowed": true})
	ms.Respond("POST", base+"/fga/write", 200, map[string]string{"status": "ok"})
	ms.Respond("GET", base+"/fga/read", 200, clavex.FGAReadResult{
		Tuples: []clavex.FGATuple{{User: "user:alice", Relation: "viewer", Object: "doc:1"}},
	})
	// stores GET+POST share path.
	ms.HandleFunc("", base+"/fga/stores", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"store_id":"st-1","model_id":"m-1"}`))
	})

	client, _ := clavex.New(ms.URL(), clavex.WithToken("t"))
	ctx := context.Background()

	if st, err := client.FGA.InitStore(ctx, orgID); err != nil || st.StoreID != "st-1" {
		t.Fatalf("InitStore: %v %#v", err, st)
	}
	allowed, err := client.FGA.Check(ctx, orgID, clavex.FGATuple{User: "user:alice", Relation: "viewer", Object: "doc:1"})
	if err != nil || !allowed {
		t.Fatalf("Check: %v allowed=%v", err, allowed)
	}
	if err := client.FGA.Write(ctx, orgID, []clavex.FGATuple{{User: "user:bob", Relation: "editor", Object: "doc:2"}}, nil); err != nil {
		t.Fatalf("Write: %v", err)
	}
	res, err := client.FGA.Read(ctx, orgID, clavex.FGAReadParams{Object: "doc:1", PageSize: 50})
	if err != nil || len(res.Tuples) != 1 {
		t.Fatalf("Read: %v %#v", err, res)
	}
	if len(ms.CallsFor("GET", base+"/fga/read")) != 1 {
		t.Fatalf("expected read GET with query")
	}
}

func TestPAMService(t *testing.T) {
	ms := clavex.NewMockServer()
	defer ms.Close()
	const orgID = "org-1"
	base := "/api/v1/organizations/" + orgID

	ms.Respond("POST", base+"/pam/credentials/cred-1/checkout", 200, clavex.CheckoutResult{
		Checkout: map[string]interface{}{"id": "co-1"}, Secret: "s3cr3t", Warning: "once",
	})
	ms.Respond("POST", base+"/pam/ssh-ca/sign", 200, clavex.SignSSHKeyResult{
		SignedKey: "ssh-cert", Principals: []string{"root"}, TTL: 3600,
	})
	ms.HandleFunc("GET", base+"/pam/ssh-ca/public-key", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ssh-ed25519 AAAAC3..."))
	})
	ms.HandleFunc("", base+"/pam/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"cred-1","name":"db-root"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"cred-1","name":"db-root"}]}`))
	})

	client, _ := clavex.New(ms.URL(), clavex.WithToken("t"))
	ctx := context.Background()

	cred, err := client.PAM.CreateCredential(ctx, orgID, clavex.CreateCredentialParams{
		Name: "db-root", CredentialType: "password", Secret: "p", CheckoutDuration: 3600,
	})
	if err != nil || cred.ID != "cred-1" {
		t.Fatalf("CreateCredential: %v %#v", err, cred)
	}
	creds, err := client.PAM.ListCredentials(ctx, orgID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("ListCredentials: %v %#v", err, creds)
	}
	co, err := client.PAM.Checkout(ctx, orgID, "cred-1", "", "deploy")
	if err != nil || co.Secret != "s3cr3t" {
		t.Fatalf("Checkout: %v %#v", err, co)
	}
	pk, err := client.PAM.GetCAPublicKey(ctx, orgID)
	if err != nil || pk == "" {
		t.Fatalf("GetCAPublicKey: %v %q", err, pk)
	}
	sign, err := client.PAM.SignSSHKey(ctx, orgID, "ssh-ed25519 AAA", "root", "")
	if err != nil || sign.SignedKey != "ssh-cert" {
		t.Fatalf("SignSSHKey: %v %#v", err, sign)
	}
}
