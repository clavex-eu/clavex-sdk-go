package clavex

import "context"

// AuthZenService exposes the OpenID AuthZen 1.0 authorization evaluation API.
//
// Resource servers call Evaluate() to ask "can this subject perform this
// action on this resource?" without implementing their own policy engine.
//
// Clavex acts as the Policy Decision Point (PDP); your service is the
// Policy Enforcement Point (PEP).
//
//	ok, err := client.AuthZen.Evaluate(ctx, orgSlug, clavex.EvaluateRequest{
//	    Subject:  clavex.AZSubject{Type: "user", ID: userSub},
//	    Resource: clavex.AZResource{Type: "document", ID: docID},
//	    Action:   clavex.AZAction{Name: "read"},
//	})
//	if err != nil { ... }
//	if !ok.Decision { return http.StatusForbidden }
type AuthZenService struct{ c *Client }

// AZSubject is the AuthZen §5.1 Subject — who is performing the action.
type AZSubject struct {
	// Type identifies the subject kind (e.g. "user", "service_account").
	Type string `json:"type"`
	// ID is the subject identifier. For users, this is the OIDC sub claim
	// or the user's email address.
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AZResource is the AuthZen §5.2 Resource — the target of the action.
type AZResource struct {
	Type       string         `json:"type,omitempty"`
	ID         string         `json:"id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AZAction is the AuthZen §5.3 Action — what the subject wants to do.
type AZAction struct {
	// Name is the action identifier (e.g. "read", "write", "delete", "can_approve").
	Name       string         `json:"name,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AZContext carries additional signals for the authorization decision.
type AZContext struct {
	// IP is the end-user's IP address.
	IP string `json:"ip,omitempty"`
	// Country is the ISO 3166-1 alpha-2 country code.
	Country string `json:"country,omitempty"`
	// UserAgent string.
	UserAgent string `json:"user_agent,omitempty"`
	// Time overrides the evaluation clock (ISO 8601). Useful for testing.
	Time string `json:"time,omitempty"`
}

// EvaluateRequest is the body of POST /access/v1/evaluation (AuthZen §5).
type EvaluateRequest struct {
	Subject  AZSubject  `json:"subject"`
	Resource AZResource `json:"resource"`
	Action   AZAction   `json:"action"`
	Context  AZContext  `json:"context,omitempty"`
}

// EvaluateResponse is the AuthZen §6 evaluation response.
type EvaluateResponse struct {
	// Decision is true when the subject is allowed to perform the action.
	Decision bool           `json:"decision"`
	// Context carries optional diagnostics: rule name, reason, mfa_required.
	Context  map[string]any `json:"context,omitempty"`
}

// Evaluate asks Clavex whether the subject can perform the action on the
// resource. The orgSlug is the tenant identifier (e.g. "acme").
//
// The client must be authenticated with a valid access token issued by the
// same org. Resource servers should use a machine-to-machine client credential
// to obtain this token once and cache it until expiry.
//
//	resp, err := client.AuthZen.Evaluate(ctx, "acme", clavex.EvaluateRequest{
//	    Subject:  clavex.AZSubject{Type: "user", ID: "alice@example.com"},
//	    Resource: clavex.AZResource{Type: "invoice", ID: "inv-9001"},
//	    Action:   clavex.AZAction{Name: "approve"},
//	    Context:  clavex.AZContext{IP: "1.2.3.4"},
//	})
func (s *AuthZenService) Evaluate(ctx context.Context, orgSlug string, req EvaluateRequest) (*EvaluateResponse, error) {
	var out EvaluateResponse
	path := "/" + orgSlug + "/access/v1/evaluation"
	return &out, s.c.post(ctx, path, req, &out)
}

// BatchEvaluateRequest is the body for POST /access/v1/evaluations.
type BatchEvaluateRequest struct {
	Evaluations []EvaluateRequest `json:"evaluations"`
}

// BatchEvaluateResponse is returned by POST /access/v1/evaluations.
type BatchEvaluateResponse struct {
	Evaluations []EvaluateResponse `json:"evaluations"`
}

// BatchEvaluate evaluates multiple authorization requests in a single call.
// Results are returned in the same order as the input requests.
func (s *AuthZenService) BatchEvaluate(ctx context.Context, orgSlug string, reqs []EvaluateRequest) (*BatchEvaluateResponse, error) {
	var out BatchEvaluateResponse
	path := "/" + orgSlug + "/access/v1/evaluations"
	return &out, s.c.post(ctx, path, BatchEvaluateRequest{Evaluations: reqs}, &out)
}
