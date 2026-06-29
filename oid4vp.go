package clavex

import (
	"context"
	"fmt"
	"time"
)

// ── OID4VP (OpenID for Verifiable Presentations) ──────────────────────────────

// OID4VPService manages the verification side of the EUDI wallet stack:
// inspecting presentation sessions and batch-verifying vp_tokens.
type OID4VPService struct{ c *Client }

// VPSession is an OID4VP presentation session.
type VPSession struct {
	ID                     string                 `json:"id"`
	Status                 string                 `json:"status"`
	PresentationDefinition map[string]interface{} `json:"presentation_definition,omitempty"`
	DCQLQuery              map[string]interface{} `json:"dcql_query,omitempty"`
	Nonce                  string                 `json:"nonce,omitempty"`
	ExpiresAt              time.Time              `json:"expires_at"`
	VerifiedClaims         map[string]interface{} `json:"verified_claims,omitempty"`
	CreatedAt              time.Time              `json:"created_at"`
}

// BatchVerifyItem is a single vp_token to verify.
type BatchVerifyItem struct {
	ID                     string                 `json:"id"`
	VPToken                string                 `json:"vp_token"`
	Nonce                  string                 `json:"nonce"`
	Audience               string                 `json:"audience,omitempty"`
	PresentationDefinition map[string]interface{} `json:"presentation_definition,omitempty"`
}

// BatchVerifyResult is the verification outcome for one item.
type BatchVerifyResult struct {
	ID       string                 `json:"id"`
	Verified bool                   `json:"verified"`
	Error    string                 `json:"error,omitempty"`
	Claims   map[string]interface{} `json:"claims,omitempty"`
}

// ListSessions returns the OID4VP presentation sessions for orgID.
func (s *OID4VPService) ListSessions(ctx context.Context, orgID string) ([]VPSession, error) {
	var out []VPSession
	return out, s.c.get(ctx, orgPath(orgID, "/oid4vp/sessions"), &out)
}

// GetSession returns a single presentation session.
func (s *OID4VPService) GetSession(ctx context.Context, orgID, sessionID string) (*VPSession, error) {
	var out VPSession
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/oid4vp/sessions/%s", sessionID)), &out)
}

// BatchVerify verifies a batch of vp_tokens. Results are matched by item ID.
func (s *OID4VPService) BatchVerify(ctx context.Context, orgID string, items []BatchVerifyItem) ([]BatchVerifyResult, error) {
	var out struct {
		Results []BatchVerifyResult `json:"results"`
	}
	err := s.c.post(ctx, orgPath(orgID, "/oid4vp/batch-verify"), map[string]interface{}{"items": items}, &out)
	return out.Results, err
}
