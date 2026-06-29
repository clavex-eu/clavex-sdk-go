package clavex

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// ── PAM (Privileged Access Management) ────────────────────────────────────────

// PAMService manages privileged access: just-in-time access requests, the
// credential vault (checkout/return), an SSH certificate authority, and
// recorded privileged sessions.
//
// Access-request and session/credential read responses are returned as
// decoded JSON objects to remain forward-compatible with the evolving
// server-side records. Write inputs are strongly typed.
//
// SECURITY: Checkout and CreateCredential return plaintext secrets that are
// shown only once — store them securely and never log them.
type PAMService struct{ c *Client }

// PAMListResult is a paginated PAM listing.
type PAMListResult struct {
	Data    []map[string]interface{} `json:"data"`
	Total   int                      `json:"total"`
	Page    int                      `json:"page"`
	PerPage int                      `json:"per_page"`
}

// PAMPage selects a page for paginated PAM listings.
type PAMPage struct {
	Page    int
	PerPage int
}

func (p PAMPage) query() string {
	q := url.Values{}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	if p.PerPage > 0 {
		q.Set("per_page", strconv.Itoa(p.PerPage))
	}
	if enc := q.Encode(); enc != "" {
		return "?" + enc
	}
	return ""
}

// ── Access requests ─────────────────────────────────────────────────────────--

// CreateAccessRequestParams requests just-in-time privileged access.
type CreateAccessRequestParams struct {
	ResourceType      string `json:"resource_type"`
	ResourceID        string `json:"resource_id"`
	ResourceName      string `json:"resource_name"`
	Justification     string `json:"justification"`
	RequestedDuration int    `json:"requested_duration"`
}

// CreateAccessRequest creates a new access request.
func (s *PAMService) CreateAccessRequest(ctx context.Context, orgID string, p CreateAccessRequestParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/pam/access-requests"), p, &out)
}

// ListAccessRequests returns access requests. Pass status="" for all.
func (s *PAMService) ListAccessRequests(ctx context.Context, orgID, status string, page PAMPage) (*PAMListResult, error) {
	q := page.query()
	if status != "" {
		if q == "" {
			q = "?status=" + url.QueryEscape(status)
		} else {
			q += "&status=" + url.QueryEscape(status)
		}
	}
	var out PAMListResult
	return &out, s.c.get(ctx, orgPath(orgID, "/pam/access-requests"+q), &out)
}

// GetAccessRequest returns a single access request.
func (s *PAMService) GetAccessRequest(ctx context.Context, orgID, reqID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/pam/access-requests/%s", reqID)), &out)
}

// ApproveAccessRequest approves a pending access request.
func (s *PAMService) ApproveAccessRequest(ctx context.Context, orgID, reqID, note string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/pam/access-requests/%s/approve", reqID)), map[string]string{"note": note}, &out)
}

// DenyAccessRequest denies a pending access request.
func (s *PAMService) DenyAccessRequest(ctx context.Context, orgID, reqID, note string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/pam/access-requests/%s/deny", reqID)), map[string]string{"note": note}, &out)
}

// RevokeAccessRequest revokes an approved access request.
func (s *PAMService) RevokeAccessRequest(ctx context.Context, orgID, reqID, reason string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/pam/access-requests/%s/revoke", reqID)), map[string]string{"reason": reason}, &out)
}

// BreakGlass creates an emergency break-glass access request.
func (s *PAMService) BreakGlass(ctx context.Context, orgID string, p CreateAccessRequestParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/pam/access-requests/break-glass"), p, &out)
}

// ── Credentials ─────────────────────────────────────────────────────────────--

// CreateCredentialParams defines a new vaulted credential.
type CreateCredentialParams struct {
	Name                 string  `json:"name"`
	Description          *string `json:"description,omitempty"`
	CredentialType       string  `json:"credential_type"`
	Username             *string `json:"username,omitempty"`
	Secret               string  `json:"secret"`
	TargetHost           *string `json:"target_host,omitempty"`
	CheckoutDuration     int     `json:"checkout_duration"`
	RequireAccessRequest bool    `json:"require_access_request"`
	RotationIntervalDays *int    `json:"rotation_interval_days,omitempty"`
}

// UpdateCredentialParams are the mutable fields of a credential.
type UpdateCredentialParams struct {
	Name                 *string `json:"name,omitempty"`
	Description          *string `json:"description,omitempty"`
	Username             *string `json:"username,omitempty"`
	Secret               *string `json:"secret,omitempty"`
	TargetHost           *string `json:"target_host,omitempty"`
	CheckoutDuration     *int    `json:"checkout_duration,omitempty"`
	RequireAccessRequest *bool   `json:"require_access_request,omitempty"`
	IsActive             *bool   `json:"is_active,omitempty"`
	RotationIntervalDays *int    `json:"rotation_interval_days,omitempty"`
}

// CheckoutResult carries the (one-time) plaintext secret for a checkout.
type CheckoutResult struct {
	Checkout map[string]interface{} `json:"checkout"`
	Secret   string                 `json:"secret"`
	Warning  string                 `json:"warning,omitempty"`
}

// PAMCredential is a vaulted privileged credential (secret never returned here).
type PAMCredential struct {
	ID                   string     `json:"id"`
	OrgID                string     `json:"org_id"`
	Name                 string     `json:"name"`
	Description          *string    `json:"description,omitempty"`
	CredentialType       string     `json:"credential_type"`
	Username             *string    `json:"username,omitempty"`
	TargetHost           *string    `json:"target_host,omitempty"`
	CheckoutDuration     int        `json:"checkout_duration"`
	RequireAccessRequest bool       `json:"require_access_request"`
	IsActive             bool       `json:"is_active"`
	RotationIntervalDays *int       `json:"rotation_interval_days,omitempty"`
	LastRotatedAt        *time.Time `json:"last_rotated_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// ListCredentials returns the vaulted credentials for orgID.
func (s *PAMService) ListCredentials(ctx context.Context, orgID string) ([]PAMCredential, error) {
	var out struct {
		Data []PAMCredential `json:"data"`
	}
	err := s.c.get(ctx, orgPath(orgID, "/pam/credentials"), &out)
	return out.Data, err
}

// CreateCredential vaults a new credential. The response includes the stored
// record; the plaintext secret is only retrievable later via Checkout.
func (s *PAMService) CreateCredential(ctx context.Context, orgID string, p CreateCredentialParams) (*PAMCredential, error) {
	var out PAMCredential
	return &out, s.c.post(ctx, orgPath(orgID, "/pam/credentials"), p, &out)
}

// UpdateCredential modifies a vaulted credential.
func (s *PAMService) UpdateCredential(ctx context.Context, orgID, credID string, p UpdateCredentialParams) error {
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/pam/credentials/%s", credID)), p, nil)
}

// DeleteCredential removes a vaulted credential.
func (s *PAMService) DeleteCredential(ctx context.Context, orgID, credID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/pam/credentials/%s", credID)))
}

// Checkout retrieves the plaintext secret for a credential for a limited time.
// The secret is shown only once — store it securely.
func (s *PAMService) Checkout(ctx context.Context, orgID, credID, accessRequestID, reason string) (*CheckoutResult, error) {
	body := map[string]interface{}{"reason": reason}
	if accessRequestID != "" {
		body["access_request_id"] = accessRequestID
	}
	var out CheckoutResult
	return &out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/pam/credentials/%s/checkout", credID)), body, &out)
}

// ReturnCheckout returns a checked-out credential early.
func (s *PAMService) ReturnCheckout(ctx context.Context, orgID, credID, checkoutID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/pam/credentials/%s/return", credID)), map[string]string{"checkout_id": checkoutID}, nil)
}

// ListRotationLog returns the rotation history for a credential.
func (s *PAMService) ListRotationLog(ctx context.Context, orgID, credID string) ([]map[string]interface{}, error) {
	var out struct {
		Data []map[string]interface{} `json:"data"`
	}
	err := s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/pam/credentials/%s/rotation-log", credID)), &out)
	return out.Data, err
}

// ── SSH certificate authority ──────────────────────────────────────────────────

// SSHCAParams configures the SSH CA (HashiCorp Vault-backed).
type SSHCAParams struct {
	VaultAddr            string `json:"vault_addr"`
	VaultToken           string `json:"vault_token"`
	VaultMount           string `json:"vault_mount,omitempty"`
	VaultRole            string `json:"vault_role"`
	CertTTLSeconds       int    `json:"cert_ttl_seconds,omitempty"`
	RequireAccessRequest bool   `json:"require_access_request"`
}

// SignSSHKeyResult is the signed SSH certificate.
type SignSSHKeyResult struct {
	SignedKey    string   `json:"signed_key"`
	Principals   []string `json:"principals"`
	TTL          int      `json:"ttl"`
	ExpiresAt    string   `json:"expires_at"`
	Instructions string   `json:"instructions,omitempty"`
}

// GetSSHCA returns the SSH CA configuration.
func (s *PAMService) GetSSHCA(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/pam/ssh-ca"), &out)
}

// UpsertSSHCA creates or replaces the SSH CA configuration.
func (s *PAMService) UpsertSSHCA(ctx context.Context, orgID string, p SSHCAParams) error {
	return s.c.put(ctx, orgPath(orgID, "/pam/ssh-ca"), p, nil)
}

// DeleteSSHCA removes the SSH CA configuration.
func (s *PAMService) DeleteSSHCA(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, orgPath(orgID, "/pam/ssh-ca"))
}

// GetCAPublicKey returns the SSH CA public key in OpenSSH format (plain text).
func (s *PAMService) GetCAPublicKey(ctx context.Context, orgID string) (string, error) {
	token, err := s.c.bearerToken(ctx)
	if err != nil {
		return "", err
	}
	req, err := newGetRequest(ctx, s.c.base+orgPath(orgID, "/pam/ssh-ca/public-key"), token)
	if err != nil {
		return "", err
	}
	resp, err := s.c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", &APIError{StatusCode: resp.StatusCode}
	}
	b, err := readAll(resp)
	return string(b), err
}

// SignSSHKey signs an SSH public key, returning a short-lived certificate.
func (s *PAMService) SignSSHKey(ctx context.Context, orgID, publicKey, validPrincipals, accessRequestID string) (*SignSSHKeyResult, error) {
	body := map[string]interface{}{
		"public_key":       publicKey,
		"valid_principals": validPrincipals,
	}
	if accessRequestID != "" {
		body["access_request_id"] = accessRequestID
	}
	var out SignSSHKeyResult
	return &out, s.c.post(ctx, orgPath(orgID, "/pam/ssh-ca/sign"), body, &out)
}

// ── Sessions ────────────────────────────────────────────────────────────────--

// StartSessionParams begins a recorded privileged session.
type StartSessionParams struct {
	AccessRequestID *string `json:"access_request_id,omitempty"`
	SessionType     string  `json:"session_type"`
	TargetHost      *string `json:"target_host,omitempty"`
	TargetPort      *int    `json:"target_port,omitempty"`
	TargetUser      *string `json:"target_user,omitempty"`
}

// StartSession begins a recorded privileged session.
func (s *PAMService) StartSession(ctx context.Context, orgID string, p StartSessionParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/pam/sessions"), p, &out)
}

// ListSessions returns recorded privileged sessions.
func (s *PAMService) ListSessions(ctx context.Context, orgID string, page PAMPage) (*PAMListResult, error) {
	var out PAMListResult
	return &out, s.c.get(ctx, orgPath(orgID, "/pam/sessions"+page.query()), &out)
}

// GetSession returns a single privileged session.
func (s *PAMService) GetSession(ctx context.Context, orgID, sessionID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/pam/sessions/%s", sessionID)), &out)
}

// EndSession terminates a privileged session.
func (s *PAMService) EndSession(ctx context.Context, orgID, sessionID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/pam/sessions/%s/end", sessionID)), nil, nil)
}

// AddSessionEvent appends an event to a session's recording.
func (s *PAMService) AddSessionEvent(ctx context.Context, orgID, sessionID, eventType string, payload json.RawMessage) (map[string]interface{}, error) {
	body := map[string]interface{}{"event_type": eventType}
	if payload != nil {
		body["payload"] = payload
	}
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/pam/sessions/%s/events", sessionID)), body, &out)
}

// ListSessionEvents returns the events recorded for a session.
func (s *PAMService) ListSessionEvents(ctx context.Context, orgID, sessionID string) ([]map[string]interface{}, error) {
	var out struct {
		Data []map[string]interface{} `json:"data"`
	}
	err := s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/pam/sessions/%s/events", sessionID)), &out)
	return out.Data, err
}

// ── Break-glass config ─────────────────────────────────────────────────────────

// BreakGlassConfigParams configures the break-glass policy.
type BreakGlassConfigParams struct {
	MaxUsesPerWeek     int      `json:"max_uses_per_week"`
	AutoRevokeHours    int      `json:"auto_revoke_hours"`
	NotificationEmails []string `json:"notification_emails"`
}

// GetBreakGlassConfig returns the break-glass policy and this week's usage.
func (s *PAMService) GetBreakGlassConfig(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/pam/break-glass/config"), &out)
}

// PutBreakGlassConfig creates or replaces the break-glass policy.
func (s *PAMService) PutBreakGlassConfig(ctx context.Context, orgID string, p BreakGlassConfigParams) error {
	return s.c.put(ctx, orgPath(orgID, "/pam/break-glass/config"), p, nil)
}
