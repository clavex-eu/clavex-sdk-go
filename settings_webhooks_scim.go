package clavex

import (
	"context"
	"fmt"
)

// BrandingService manages organisation branding settings.
type BrandingService struct{ c *Client }

// Get returns the branding settings for orgID.
func (s *BrandingService) Get(ctx context.Context, orgID string) (*Branding, error) {
	var out Branding
	return &out, s.c.get(ctx, orgPath(orgID, "/branding"), &out)
}

// Put replaces the branding settings for orgID.
func (s *BrandingService) Put(ctx context.Context, orgID string, b Branding) (*Branding, error) {
	var out Branding
	return &out, s.c.put(ctx, orgPath(orgID, "/branding"), b, &out)
}

// PasswordPolicyService manages the password policy for an organisation.
type PasswordPolicyService struct{ c *Client }

// Get returns the password policy for orgID.
func (s *PasswordPolicyService) Get(ctx context.Context, orgID string) (*PasswordPolicy, error) {
	var out PasswordPolicy
	return &out, s.c.get(ctx, orgPath(orgID, "/password-policy"), &out)
}

// Put replaces the password policy for orgID.
func (s *PasswordPolicyService) Put(ctx context.Context, orgID string, p PasswordPolicy) (*PasswordPolicy, error) {
	var out PasswordPolicy
	return &out, s.c.put(ctx, orgPath(orgID, "/password-policy"), p, &out)
}

// ReleaseManagedMarker clears the declarative-management marker on orgID's
// password policy without changing its configured values. A declarative caller
// (the Kubernetes operator) calls this when it stops managing the section.
func (s *PasswordPolicyService) ReleaseManagedMarker(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, orgPath(orgID, "/password-policy/managed-marker"))
}

// SMTPService manages the SMTP settings for an organisation.
type SMTPService struct{ c *Client }

// Get returns the SMTP config for orgID.
func (s *SMTPService) Get(ctx context.Context, orgID string) (*SMTPConfig, error) {
	var out SMTPConfig
	return &out, s.c.get(ctx, orgPath(orgID, "/smtp"), &out)
}

// Put replaces the SMTP config for orgID.
func (s *SMTPService) Put(ctx context.Context, orgID string, cfg SMTPConfig) (*SMTPConfig, error) {
	var out SMTPConfig
	return &out, s.c.put(ctx, orgPath(orgID, "/smtp"), cfg, &out)
}

// SMTPTestResult holds the result of an SMTP send test.
type SMTPTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// Test sends a test email using the current SMTP config.
func (s *SMTPService) Test(ctx context.Context, orgID string) (*SMTPTestResult, error) {
	var out SMTPTestResult
	return &out, s.c.post(ctx, orgPath(orgID, "/smtp/test"), nil, &out)
}

// CaptchaService manages CAPTCHA settings for an organisation.
type CaptchaService struct{ c *Client }

// Get returns the current CAPTCHA config for orgID.
func (s *CaptchaService) Get(ctx context.Context, orgID string) (*CaptchaSettings, error) {
	var out CaptchaSettings
	return &out, s.c.get(ctx, orgPath(orgID, "/captcha"), &out)
}

// Put replaces the CAPTCHA config for orgID.
func (s *CaptchaService) Put(ctx context.Context, orgID string, cfg CaptchaSettings) (*CaptchaSettings, error) {
	var out CaptchaSettings
	return &out, s.c.put(ctx, orgPath(orgID, "/captcha"), cfg, &out)
}

// Delete removes the CAPTCHA config, disabling CAPTCHA for orgID.
func (s *CaptchaService) Delete(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, orgPath(orgID, "/captcha"))
}

// WebhookService manages outbound webhooks for an organisation.
type WebhookService struct{ c *Client }

// CreateWebhookParams defines the fields for a webhook.
type CreateWebhookParams struct {
	URL      string   `json:"url"`
	Events   []string `json:"events"`
	Secret   string   `json:"secret,omitempty"`
	IsActive *bool    `json:"is_active,omitempty"`
}

// Create registers a new webhook.
func (s *WebhookService) Create(ctx context.Context, orgID string, p CreateWebhookParams) (*Webhook, error) {
	var out Webhook
	return &out, s.c.post(ctx, orgPath(orgID, "/webhooks"), p, &out)
}

// List returns all webhooks in orgID.
func (s *WebhookService) List(ctx context.Context, orgID string) ([]Webhook, error) {
	var out []Webhook
	return out, s.c.get(ctx, orgPath(orgID, "/webhooks"), &out)
}

// Update modifies a webhook.
func (s *WebhookService) Update(ctx context.Context, orgID, webhookID string, p CreateWebhookParams) (*Webhook, error) {
	var out Webhook
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/webhooks/%s", webhookID)), p, &out)
}

// Delete removes a webhook.
func (s *WebhookService) Delete(ctx context.Context, orgID, webhookID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/webhooks/%s", webhookID)))
}

// InvitationService manages pending user invitations.
type InvitationService struct{ c *Client }

// CreateInvitationParams holds the invitation request fields.
type CreateInvitationParams struct {
	Email   string   `json:"email"`
	RoleIDs []string `json:"role_ids,omitempty"`
}

// List returns all pending invitations for orgID.
func (s *InvitationService) List(ctx context.Context, orgID string) ([]Invitation, error) {
	var out []Invitation
	return out, s.c.get(ctx, orgPath(orgID, "/invitations"), &out)
}

// Create sends an invitation email and records the invitation.
func (s *InvitationService) Create(ctx context.Context, orgID string, p CreateInvitationParams) (*Invitation, error) {
	var out Invitation
	return &out, s.c.post(ctx, orgPath(orgID, "/invitations"), p, &out)
}

// Delete revokes a pending invitation.
func (s *InvitationService) Delete(ctx context.Context, orgID, inviteID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/invitations/%s", inviteID)))
}

// SCIMService manages SCIM 2.0 bearer tokens for an organisation.
type SCIMService struct{ c *Client }

// CreateTokenResult holds the freshly generated SCIM token.
type CreateTokenResult struct {
	Token     string    `json:"token"`
	SCIMToken SCIMToken `json:"scim_token"`
}

// CreateToken generates a new SCIM token.
func (s *SCIMService) CreateToken(ctx context.Context, orgID string) (*CreateTokenResult, error) {
	var out CreateTokenResult
	return &out, s.c.post(ctx, orgPath(orgID, "/scim/tokens"), nil, &out)
}

// ListTokens returns all SCIM tokens for orgID.
func (s *SCIMService) ListTokens(ctx context.Context, orgID string) ([]SCIMToken, error) {
	var out []SCIMToken
	return out, s.c.get(ctx, orgPath(orgID, "/scim/tokens"), &out)
}

// DeleteToken revokes a SCIM token.
func (s *SCIMService) DeleteToken(ctx context.Context, orgID, tokenID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/scim/tokens/%s", tokenID)))
}
