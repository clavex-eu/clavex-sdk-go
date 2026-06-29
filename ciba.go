package clavex

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// ── CIBA (Client-Initiated Backchannel Authentication) ────────────────────────

// CIBAService manages the admin/management surface of OpenID CIBA Core 1.0:
// pending request approval, push device-token registration, and the per-org
// notification configuration (webhook / email / SMS / APNs / FCM).
//
// The backchannel authorize and token-polling legs are OAuth endpoints driven
// by the relying party, not this management SDK.
//
//	pending, err := client.CIBA.ListPending(ctx, orgID)
//	_, err = client.CIBA.Approve(ctx, orgID, pending[0].AuthReqID)
type CIBAService struct{ c *Client }

// CIBARequest is a pending (or recently resolved) backchannel auth request.
type CIBARequest struct {
	AuthReqID      string                 `json:"auth_req_id"`
	OrgID          string                 `json:"org_id"`
	ClientID       string                 `json:"client_id"`
	UserID         *string                `json:"user_id"`
	Scope          string                 `json:"scope"`
	BindingMessage *string                `json:"binding_message"`
	LoginHint      *string                `json:"login_hint"`
	Status         string                 `json:"status"` // "pending"|"approved"|"denied"
	Interval       int                    `json:"interval"`
	ExpiresAt      time.Time              `json:"expires_at"`
	CreatedAt      time.Time              `json:"created_at"`
	VPClaims       map[string]interface{} `json:"vp_claims,omitempty"`
	ACR            string                 `json:"acr,omitempty"`
}

// CIBADeviceToken is a push token registered for a user's mobile device.
type CIBADeviceToken struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	UserID      string    `json:"user_id"`
	Platform    string    `json:"platform"` // "apns"|"fcm"
	DeviceToken string    `json:"device_token"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RegisterDeviceTokenParams registers a push token on behalf of a user (admin).
type RegisterDeviceTokenParams struct {
	UserID      string `json:"user_id"`
	Platform    string `json:"platform"` // "apns"|"fcm"
	DeviceToken string `json:"device_token"`
}

// CIBANotificationConfig is the per-org notification configuration returned by
// the API. Secret material is never returned — only *_set booleans indicate
// whether a value is stored.
type CIBANotificationConfig struct {
	OrgID                string            `json:"org_id"`
	WebhookURL           *string           `json:"webhook_url"`
	WebhookSecretSet     bool              `json:"webhook_secret_set"`
	WebhookHeaders       map[string]string `json:"webhook_headers"`
	EmailEnabled         bool              `json:"email_enabled"`
	SMSEnabled           bool              `json:"sms_enabled"`
	BaseURL              *string           `json:"base_url"`
	PushEnabled          bool              `json:"push_enabled"`
	APNsKeySet           bool              `json:"apns_key_set"`
	APNsKeyID            *string           `json:"apns_key_id"`
	APNsTeamID           *string           `json:"apns_team_id"`
	APNsBundleID         *string           `json:"apns_bundle_id"`
	APNsProduction       bool              `json:"apns_production"`
	FCMServiceAccountSet bool              `json:"fcm_service_account_set"`
}

// UpsertCIBANotificationConfigParams creates or replaces the notification config.
// Secret fields (webhook_secret, apns_key_p8, fcm_service_account_json) are
// write-only; omit them to leave the stored value unchanged is NOT supported —
// the endpoint replaces the whole config.
type UpsertCIBANotificationConfigParams struct {
	WebhookURL            *string           `json:"webhook_url,omitempty"`
	WebhookSecret         *string           `json:"webhook_secret,omitempty"`
	WebhookHeaders        map[string]string `json:"webhook_headers,omitempty"`
	EmailEnabled          bool              `json:"email_enabled"`
	SMSEnabled            bool              `json:"sms_enabled"`
	BaseURL               *string           `json:"base_url,omitempty"`
	PushEnabled           bool              `json:"push_enabled"`
	APNsKeyP8             *string           `json:"apns_key_p8,omitempty"`
	APNsKeyID             *string           `json:"apns_key_id,omitempty"`
	APNsTeamID            *string           `json:"apns_team_id,omitempty"`
	APNsBundleID          *string           `json:"apns_bundle_id,omitempty"`
	APNsProduction        bool              `json:"apns_production"`
	FCMServiceAccountJSON *string           `json:"fcm_service_account_json,omitempty"`
}

// ── Pending requests ──────────────────────────────────────────────────────────

// ListPending returns the pending CIBA requests for an org.
func (s *CIBAService) ListPending(ctx context.Context, orgID string) ([]CIBARequest, error) {
	var out []CIBARequest
	return out, s.c.get(ctx, orgPath(orgID, "/ciba/pending"), &out)
}

// Approve marks a pending CIBA request as approved. The approved user is the one
// resolved from the original login_hint/id_token_hint; it cannot be substituted.
func (s *CIBAService) Approve(ctx context.Context, orgID, authReqID string) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	err := s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/ciba/%s/approve", authReqID)), nil, &out)
	return out.Status, err
}

// Deny marks a pending CIBA request as denied.
func (s *CIBAService) Deny(ctx context.Context, orgID, authReqID string) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	err := s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/ciba/%s/deny", authReqID)), nil, &out)
	return out.Status, err
}

// ── Push device tokens ────────────────────────────────────────────────────────

// ListDeviceTokens returns all registered push tokens for an org. Pass a
// non-empty userID to filter by user.
func (s *CIBAService) ListDeviceTokens(ctx context.Context, orgID, userID string) ([]CIBADeviceToken, error) {
	path := orgPath(orgID, "/ciba/device-tokens")
	if userID != "" {
		path += "?user_id=" + url.QueryEscape(userID)
	}
	var out []CIBADeviceToken
	return out, s.c.get(ctx, path, &out)
}

// RegisterDeviceToken registers a push token on behalf of a user (admin).
func (s *CIBAService) RegisterDeviceToken(ctx context.Context, orgID string, p RegisterDeviceTokenParams) (*CIBADeviceToken, error) {
	var out CIBADeviceToken
	return &out, s.c.post(ctx, orgPath(orgID, "/ciba/device-tokens"), p, &out)
}

// DeleteDeviceToken removes a push token by its UUID.
func (s *CIBAService) DeleteDeviceToken(ctx context.Context, orgID, tokenID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/ciba/device-tokens/%s", tokenID)))
}

// ── Notification config ───────────────────────────────────────────────────────

// GetNotificationConfig returns the CIBA notification configuration for an org.
func (s *CIBAService) GetNotificationConfig(ctx context.Context, orgID string) (*CIBANotificationConfig, error) {
	var out CIBANotificationConfig
	return &out, s.c.get(ctx, orgPath(orgID, "/ciba/notification-config"), &out)
}

// PutNotificationConfig creates or replaces the CIBA notification configuration.
func (s *CIBAService) PutNotificationConfig(ctx context.Context, orgID string, p UpsertCIBANotificationConfigParams) (*CIBANotificationConfig, error) {
	var out CIBANotificationConfig
	return &out, s.c.put(ctx, orgPath(orgID, "/ciba/notification-config"), p, &out)
}

// DeleteNotificationConfig removes the CIBA notification configuration.
func (s *CIBAService) DeleteNotificationConfig(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, orgPath(orgID, "/ciba/notification-config"))
}
