package clavex_test

import (
	"context"
	"net/http"
	"testing"

	clavex "github.com/clavex-eu/clavex-sdk-go"
)

func TestGovernanceServices(t *testing.T) {
	ms := clavex.NewMockServer()
	defer ms.Close()
	const orgID = "org-1"
	base := "/api/v1/organizations/" + orgID

	ms.Respond("POST", base+"/service-accounts", 201, clavex.ServiceAccountWithSecret{
		ServiceAccount: clavex.ServiceAccount{ID: "sa-1", Name: "ci"}, ClientSecret: "sek", SecretNote: "once",
	})
	ms.Respond("POST", base+"/login-flows", 201, map[string]interface{}{"id": "lf-1", "name": "default"})
	ms.Respond("POST", base+"/lifecycle-rules", 201, map[string]interface{}{"id": "lr-1"})
	ms.Respond("GET", base+"/wsfed/relying-parties", 200, []map[string]interface{}{{"id": "rp-1"}})
	ms.Respond("POST", base+"/access-reviews", 201, map[string]interface{}{"id": "cmp-1"})
	ms.Respond("GET", base+"/compliance/score", 200, map[string]interface{}{"score": 87})
	ms.Respond("PUT", base+"/gdpr/retention-policy", 200, map[string]interface{}{"enabled": true})
	ms.Respond("POST", base+"/ai/suggest-policy", 200, map[string]interface{}{"suggestion": "deny RU"})
	ms.Respond("POST", base+"/elevate", 201, map[string]interface{}{"challenge_id": "ch-1"})
	ms.Respond("POST", base+"/agent-tokens", 201, map[string]interface{}{"id": "at-1", "token": "tok"})
	ms.HandleFunc("", base+"/saml/sps", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"sp-1","entity_id":"https://sp"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"sp-1"}]`))
	})

	client, _ := clavex.New(ms.URL(), clavex.WithToken("t"))
	ctx := context.Background()

	if sa, err := client.ServiceAccounts.Create(ctx, orgID, clavex.CreateServiceAccountParams{Name: "ci"}); err != nil || sa.ClientSecret != "sek" {
		t.Fatalf("ServiceAccounts.Create: %v %#v", err, sa)
	}
	if lf, err := client.LoginFlows.Create(ctx, orgID, clavex.CreateLoginFlowParams{Name: "default", IsDefault: true}); err != nil || lf.ID != "lf-1" {
		t.Fatalf("LoginFlows.Create: %v %#v", err, lf)
	}
	if _, err := client.LifecycleRules.Create(ctx, orgID, clavex.LifecycleRuleParams{Name: "joiner", Trigger: "joiner", Conditions: []byte("[]"), Actions: []byte("[]")}); err != nil {
		t.Fatalf("LifecycleRules.Create: %v", err)
	}
	if rps, err := client.WsfedRPs.List(ctx, orgID); err != nil || len(rps) != 1 {
		t.Fatalf("WsfedRPs.List: %v %#v", err, rps)
	}
	if _, err := client.AccessReviews.Create(ctx, orgID, clavex.CreateAccessReviewParams{Name: "Q1"}); err != nil {
		t.Fatalf("AccessReviews.Create: %v", err)
	}
	if sc, err := client.Compliance.Score(ctx, orgID); err != nil || sc["score"].(float64) != 87 {
		t.Fatalf("Compliance.Score: %v %#v", err, sc)
	}
	if _, err := client.GDPR.PutRetentionPolicy(ctx, orgID, clavex.RetentionPolicyParams{Enabled: true, RetentionDays: 365}); err != nil {
		t.Fatalf("GDPR.PutRetentionPolicy: %v", err)
	}
	if r, err := client.AI.Suggest(ctx, orgID, "suggest-policy", map[string]string{"goal": "block ru"}); err != nil || r["suggestion"] == nil {
		t.Fatalf("AI.Suggest: %v %#v", err, r)
	}
	if e, err := client.Elevate.Create(ctx, orgID, clavex.CreateElevateParams{BearerToken: "b", Reason: "delete"}); err != nil || e["challenge_id"] != "ch-1" {
		t.Fatalf("Elevate.Create: %v %#v", err, e)
	}
	if at, err := client.AgentTokens.Issue(ctx, orgID, clavex.IssueAgentTokenParams{UserID: "u", AgentID: "a", AgentName: "n"}); err != nil || at.Token != "tok" {
		t.Fatalf("AgentTokens.Issue: %v %#v", err, at)
	}
	if sp, err := client.SamlSPs.Create(ctx, orgID, clavex.CreateSamlSpParams{EntityID: "https://sp", Name: "SP", ACSURL: "https://sp/acs"}); err != nil || sp.ID != "sp-1" {
		t.Fatalf("SamlSPs.Create: %v %#v", err, sp)
	}
}
