package clavex

import (
	"context"
	"fmt"
)

// PolicyService manages auth-flow policy rules for an organisation.
// Rules are evaluated in priority order during every authentication event.
//
// Auth0 analogy: Actions / Rules.
// Okta analogy: Authentication Policies / Global Session Policy.
//
//	// Block logins from Russia
//	rule, err := client.Policies.Create(ctx, orgID, clavex.CreatePolicyRuleParams{
//	    Name:     "block-russia",
//	    Priority: 10,
//	    Action:   "deny",
//	    Conditions: clavex.PolicyConditions{Countries: []string{"RU"}},
//	})
type PolicyService struct{ c *Client }

// List returns all auth-flow policy rules for orgID.
func (s *PolicyService) List(ctx context.Context, orgID string) ([]PolicyRule, error) {
	var out []PolicyRule
	return out, s.c.get(ctx, orgPath(orgID, "/auth-policies"), &out)
}

// CreatePolicyRuleParams defines the fields for creating a policy rule.
type CreatePolicyRuleParams struct {
	Name       string           `json:"name"`
	Priority   int              `json:"priority,omitempty"`
	Action     string           `json:"action"` // "allow" | "deny" | "require_mfa" | "step_up"
	Conditions PolicyConditions `json:"conditions,omitempty"`
}

// UpdatePolicyRuleParams defines the mutable fields of a policy rule.
type UpdatePolicyRuleParams struct {
	Name       *string          `json:"name,omitempty"`
	Priority   *int             `json:"priority,omitempty"`
	Enabled    *bool            `json:"enabled,omitempty"`
	Action     *string          `json:"action,omitempty"`
	Conditions PolicyConditions `json:"conditions,omitempty"`
}

// Create adds a new policy rule to orgID.
func (s *PolicyService) Create(ctx context.Context, orgID string, p CreatePolicyRuleParams) (*PolicyRule, error) {
	var out PolicyRule
	return &out, s.c.post(ctx, orgPath(orgID, "/auth-policies"), p, &out)
}

// Update modifies a policy rule.
func (s *PolicyService) Update(ctx context.Context, orgID, ruleID string, p UpdatePolicyRuleParams) (*PolicyRule, error) {
	var out PolicyRule
	return &out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/auth-policies/%s", ruleID)), p, &out)
}

// Delete removes a policy rule.
func (s *PolicyService) Delete(ctx context.Context, orgID, ruleID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/auth-policies/%s", ruleID)))
}

// SimulateParams is the body for the policy dry-run endpoint.
type SimulateParams struct {
	// UserID is the user to evaluate (UUID). If empty, only IP/country/client
	// conditions are checked.
	UserID string `json:"user_id,omitempty"`
	// ClientID is the OIDC client_id being used in the flow.
	ClientID string `json:"client_id,omitempty"`
	// IPAddress to simulate (defaults to the calling IP).
	IPAddress string `json:"ip_address,omitempty"`
	// Country is the ISO 3166-1 alpha-2 override.
	Country string `json:"country,omitempty"`
	// UserAgent string.
	UserAgent string `json:"user_agent,omitempty"`
	// RequestTime overrides the evaluation clock (ISO 8601).
	RequestTime string `json:"request_time,omitempty"`
}

// Simulate performs a dry-run policy evaluation without side effects.
// Returns the outcome and a full trace of all rule evaluations.
//
//	result, err := client.Policies.Simulate(ctx, orgID, clavex.SimulateParams{
//	    UserID:    "550e8400-...",
//	    IPAddress: "1.2.3.4",
//	    Country:   "CN",
//	})
//	fmt.Println(result.Outcome.Action, result.MFARequired)
func (s *PolicyService) Simulate(ctx context.Context, orgID string, p SimulateParams) (*SimulateResult, error) {
	var out SimulateResult
	return &out, s.c.post(ctx, orgPath(orgID, "/auth-policies/simulate"), p, &out)
}
