package clavex_test

import (
	"context"
	"net/http"
	"testing"

	clavex "github.com/clavex-eu/clavex-sdk-go"
)

func TestEUDIServices(t *testing.T) {
	ms := clavex.NewMockServer()
	defer ms.Close()

	const orgID = "org-1"
	base := "/api/v1/organizations/" + orgID

	// OID4VCI — GET (list) and POST (create) share /oid4vci/configs.
	ms.HandleFunc("", base+"/oid4vci/configs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"cfg-2","vct":"https://x/badge","display_name":"Badge"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"cfg-1","org_id":"` + orgID + `","vct":"https://x/diploma","display_name":"Diploma","ttl_seconds":86400,"is_active":true}]`))
	})
	ms.Respond("POST", base+"/oid4vci/offers", 201, clavex.CreateVCIOfferResponse{OfferID: "of-1", CredentialOfferURI: "openid-credential-offer://x"})
	ms.Respond("GET", base+"/oid4vci/issued", 200, []clavex.VCIIssuedCredential{{ID: "ic-1", VCT: "https://x/diploma"}})
	ms.Respond("POST", base+"/oid4vci/issued/ic-1/revoke", 200, map[string]string{"status": "revoked"})

	// OID4VP
	ms.Respond("GET", base+"/oid4vp/sessions", 200, []clavex.VPSession{{ID: "vp-1", Status: "verified"}})
	ms.Respond("POST", base+"/oid4vp/batch-verify", 200, map[string]any{
		"results": []clavex.BatchVerifyResult{{ID: "a", Verified: true}},
	})

	// mdoc
	ms.Respond("GET", base+"/mdoc/issuers", 200, []clavex.MdocIssuer{{ID: "is-1", DisplayName: "PID", DocType: "org.iso.18013.5.1.mDL"}})
	ms.Respond("POST", base+"/mdoc/issuers/generate", 201, clavex.GenerateIssuerResponse{
		Issuer: clavex.MdocIssuer{ID: "is-2", DisplayName: "Gen"}, DSCertificate: "PEM", IACACertificate: "PEM",
	})
	ms.Respond("GET", base+"/mdoc/iaca-roots", 200, []clavex.IACARoot{{ID: "r-1", Label: "root"}})

	// Federation — GET (list) and POST (register) share one path.
	ms.HandleFunc("", base+"/federation/subordinates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"id":"s-1","entity_id":"https://sub","name":"Sub","status":"active"}`))
			return
		}
		_, _ = w.Write([]byte(`{"subordinates":[{"id":"s-1","entity_id":"https://sub","name":"Sub","status":"active"}],"count":1}`))
	})

	client, err := clavex.New(ms.URL(), clavex.WithToken("t"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	if cfgs, err := client.OID4VCI.ListConfigs(ctx, orgID); err != nil || len(cfgs) != 1 || cfgs[0].ID != "cfg-1" {
		t.Fatalf("ListConfigs: %v %#v", err, cfgs)
	}
	if cfg, err := client.OID4VCI.CreateConfig(ctx, orgID, clavex.CreateVCIConfigParams{VCT: "https://x/badge", DisplayName: "Badge"}); err != nil || cfg.ID != "cfg-2" {
		t.Fatalf("CreateConfig: %v %#v", err, cfg)
	}
	if off, err := client.OID4VCI.CreateOffer(ctx, orgID, clavex.CreateVCIOfferParams{VCT: "https://x/diploma"}); err != nil || off.OfferID != "of-1" {
		t.Fatalf("CreateOffer: %v %#v", err, off)
	}
	if iss, err := client.OID4VCI.ListIssued(ctx, orgID); err != nil || len(iss) != 1 {
		t.Fatalf("ListIssued: %v %#v", err, iss)
	}
	if err := client.OID4VCI.RevokeIssued(ctx, orgID, "ic-1", "compromised"); err != nil {
		t.Fatalf("RevokeIssued: %v", err)
	}

	if sess, err := client.OID4VP.ListSessions(ctx, orgID); err != nil || sess[0].ID != "vp-1" {
		t.Fatalf("VP ListSessions: %v %#v", err, sess)
	}
	if res, err := client.OID4VP.BatchVerify(ctx, orgID, []clavex.BatchVerifyItem{{ID: "a", VPToken: "tok", Nonce: "n"}}); err != nil || len(res) != 1 || !res[0].Verified {
		t.Fatalf("BatchVerify: %v %#v", err, res)
	}

	if iss, err := client.Mdoc.ListIssuers(ctx, orgID); err != nil || iss[0].ID != "is-1" {
		t.Fatalf("Mdoc ListIssuers: %v %#v", err, iss)
	}
	if gen, err := client.Mdoc.GenerateIssuer(ctx, orgID, clavex.GenerateIssuerParams{DisplayName: "Gen"}); err != nil || gen.Issuer.ID != "is-2" {
		t.Fatalf("GenerateIssuer: %v %#v", err, gen)
	}
	if roots, err := client.Mdoc.ListIACARoots(ctx, orgID); err != nil || roots[0].ID != "r-1" {
		t.Fatalf("ListIACARoots: %v %#v", err, roots)
	}

	if sub, err := client.Federation.RegisterSubordinate(ctx, orgID, clavex.RegisterSubordinateParams{EntityID: "https://sub", Name: "Sub", EntityTypes: []string{"openid_relying_party"}}); err != nil || sub.ID != "s-1" {
		t.Fatalf("RegisterSubordinate: %v %#v", err, sub)
	}
	if subs, err := client.Federation.ListSubordinates(ctx, orgID, "active"); err != nil || len(subs) != 1 || subs[0].EntityID != "https://sub" {
		t.Fatalf("ListSubordinates: %v %#v", err, subs)
	}
}
