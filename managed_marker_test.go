package clavex_test

import (
	"context"
	"net/http"
	"testing"

	clavex "github.com/clavex-eu/clavex-sdk-go"
)

// TestManagedHeaders verifies the declarative-management marker context helpers
// stamp the right headers, and that an ordinary request stamps none.
func TestManagedHeaders(t *testing.T) {
	ms := clavex.NewMockServer()
	defer ms.Close()
	const orgID = "org-1"
	base := "/api/v1/organizations/" + orgID

	var gotBy, gotRef, gotRelease string
	ms.HandleFunc("PUT", base+"/rate-limits", func(w http.ResponseWriter, r *http.Request) {
		gotBy = r.Header.Get("X-Clavex-Managed-By")
		gotRef = r.Header.Get("X-Clavex-Managed-Ref")
		gotRelease = r.Header.Get("X-Clavex-Managed-Release")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"org_id":"org-1"}`))
	})

	client, _ := clavex.New(ms.URL(), clavex.WithToken("t"))

	// Adopt: By + Ref headers present.
	ctx := clavex.WithManagedBy(context.Background(), "k8s-operator", "ClavexOrg/ns/name")
	if _, err := client.RateLimits.Update(ctx, orgID, clavex.RateLimitConfig{}); err != nil {
		t.Fatalf("Update (adopt): %v", err)
	}
	if gotBy != "k8s-operator" || gotRef != "ClavexOrg/ns/name" || gotRelease != "" {
		t.Fatalf("adopt headers = by=%q ref=%q release=%q", gotBy, gotRef, gotRelease)
	}

	// Release: only the release header present.
	gotBy, gotRef, gotRelease = "", "", ""
	rctx := clavex.WithManagedRelease(context.Background())
	if _, err := client.RateLimits.Update(rctx, orgID, clavex.RateLimitConfig{}); err != nil {
		t.Fatalf("Update (release): %v", err)
	}
	if gotRelease != "true" || gotBy != "" {
		t.Fatalf("release headers = by=%q release=%q", gotBy, gotRelease)
	}

	// Plain context: no marker headers at all.
	gotBy, gotRef, gotRelease = "", "", ""
	if _, err := client.RateLimits.Update(context.Background(), orgID, clavex.RateLimitConfig{}); err != nil {
		t.Fatalf("Update (plain): %v", err)
	}
	if gotBy != "" || gotRef != "" || gotRelease != "" {
		t.Fatalf("plain request must send no marker headers, got by=%q ref=%q release=%q", gotBy, gotRef, gotRelease)
	}
}
