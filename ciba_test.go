package clavex_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	clavex "github.com/clavex-eu/clavex-sdk-go"
)

func TestCIBAService(t *testing.T) {
	ms := clavex.NewMockServer()
	defer ms.Close()

	const orgID = "org-1"
	const base = "/api/v1/organizations/" + orgID + "/ciba"

	ms.Respond("GET", base+"/pending", 200, []clavex.CIBARequest{
		{AuthReqID: "req-1", OrgID: orgID, ClientID: "cli-1", Status: "pending", Interval: 5},
	})
	ms.Respond("POST", base+"/req-1/approve", 200, map[string]string{"status": "approved"})
	ms.Respond("POST", base+"/req-1/deny", 200, map[string]string{"status": "denied"})
	ms.Respond("DELETE", base+"/device-tokens/dt-1", 204, nil)
	// device-tokens shares one path for GET (list) and POST (register).
	ms.HandleFunc("", base+"/device-tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(clavex.CIBADeviceToken{
				ID: "dt-2", OrgID: orgID, UserID: "usr-1", Platform: "fcm", DeviceToken: "tok2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode([]clavex.CIBADeviceToken{
			{ID: "dt-1", OrgID: orgID, UserID: "usr-1", Platform: "apns", DeviceToken: "tok"},
		})
	})
	// notification-config shares one path for GET / PUT / DELETE.
	ms.HandleFunc("", base+"/notification-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(clavex.CIBANotificationConfig{
			OrgID: orgID, EmailEnabled: true, PushEnabled: r.Method == http.MethodGet, APNsKeySet: r.Method == http.MethodGet,
		})
	})

	client, err := clavex.New(ms.URL(), clavex.WithToken("test-token"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()

	pending, err := client.CIBA.ListPending(ctx, orgID)
	if err != nil || len(pending) != 1 || pending[0].AuthReqID != "req-1" {
		t.Fatalf("ListPending: %v %#v", err, pending)
	}

	if status, err := client.CIBA.Approve(ctx, orgID, "req-1"); err != nil || status != "approved" {
		t.Fatalf("Approve: %q %v", status, err)
	}
	if status, err := client.CIBA.Deny(ctx, orgID, "req-1"); err != nil || status != "denied" {
		t.Fatalf("Deny: %q %v", status, err)
	}

	tokens, err := client.CIBA.ListDeviceTokens(ctx, orgID, "usr-1")
	if err != nil || len(tokens) != 1 || tokens[0].Platform != "apns" {
		t.Fatalf("ListDeviceTokens: %v %#v", err, tokens)
	}
	if len(ms.CallsFor("GET", base+"/device-tokens")) != 1 {
		t.Fatalf("expected device-tokens GET with query, got %#v", ms.CallsFor("GET", base+"/device-tokens"))
	}

	dt, err := client.CIBA.RegisterDeviceToken(ctx, orgID, clavex.RegisterDeviceTokenParams{
		UserID: "usr-1", Platform: "fcm", DeviceToken: "tok2",
	})
	if err != nil || dt.ID != "dt-2" {
		t.Fatalf("RegisterDeviceToken: %v %#v", err, dt)
	}
	if err := client.CIBA.DeleteDeviceToken(ctx, orgID, "dt-1"); err != nil {
		t.Fatalf("DeleteDeviceToken: %v", err)
	}

	cfg, err := client.CIBA.GetNotificationConfig(ctx, orgID)
	if err != nil || !cfg.EmailEnabled || !cfg.APNsKeySet {
		t.Fatalf("GetNotificationConfig: %v %#v", err, cfg)
	}
	if _, err := client.CIBA.PutNotificationConfig(ctx, orgID, clavex.UpsertCIBANotificationConfigParams{EmailEnabled: true}); err != nil {
		t.Fatalf("PutNotificationConfig: %v", err)
	}
	if err := client.CIBA.DeleteNotificationConfig(ctx, orgID); err != nil {
		t.Fatalf("DeleteNotificationConfig: %v", err)
	}
}
