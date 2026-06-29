package clavex

import (
	"context"
	"fmt"
	"time"
)

// ── OID4VCI (OpenID for Verifiable Credential Issuance) ───────────────────────

// OID4VCIService manages the issuance side of the EUDI wallet stack: credential
// configurations, the credential catalog, pre-authorized offers, issued
// credentials, and deferred issuance transactions.
//
//	cfg, err := client.OID4VCI.CreateConfig(ctx, orgID, clavex.CreateVCIConfigParams{
//	    VCT:         "https://example.com/credentials/diploma",
//	    DisplayName: "University Diploma",
//	})
type OID4VCIService struct{ c *Client }

// VCICredentialConfig is a credential-type configuration (SD-JWT VC issuance).
type VCICredentialConfig struct {
	ID            string                 `json:"id"`
	OrgID         string                 `json:"org_id"`
	VCT           string                 `json:"vct"`
	DisplayName   string                 `json:"display_name"`
	Description   *string                `json:"description,omitempty"`
	ClaimsMapping map[string]interface{} `json:"claims_mapping,omitempty"`
	TTLSeconds    int                    `json:"ttl_seconds"`
	Category      string                 `json:"category,omitempty"`
	SchemaFields  []VCISchemaField       `json:"schema_fields,omitempty"`
	IsActive      bool                   `json:"is_active"`
}

// VCISchemaField describes one credential payload field for the admin issue UI.
type VCISchemaField struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Type      string `json:"type"` // "string"|"date"|"number"|"url"
	Mandatory bool   `json:"mandatory"`
}

// CreateVCIConfigParams are the fields for a new credential configuration.
type CreateVCIConfigParams struct {
	VCT           string                 `json:"vct"`
	DisplayName   string                 `json:"display_name"`
	Description   *string                `json:"description,omitempty"`
	ClaimsMapping map[string]interface{} `json:"claims_mapping,omitempty"`
	TTLSeconds    int                    `json:"ttl_seconds,omitempty"`
	Category      string                 `json:"category,omitempty"` // identity|training|qualification|badge
	SchemaFields  []VCISchemaField       `json:"schema_fields,omitempty"`
}

// PatchVCIConfigParams are the mutable fields of a credential configuration.
// Nil pointers leave the corresponding value unchanged.
type PatchVCIConfigParams struct {
	PreIssuanceWebhookURL     *string                `json:"pre_issuance_webhook_url,omitempty"`
	PreIssuanceWebhookSecret  *string                `json:"pre_issuance_webhook_secret,omitempty"`
	RequireVP                 *bool                  `json:"require_vp,omitempty"`
	PresentationDefinitionVPR map[string]interface{} `json:"presentation_definition_vpr,omitempty"`
	SourceIdpType             *string                `json:"source_idp_type,omitempty"`
	SelectiveDisclosure       *bool                  `json:"selective_disclosure,omitempty"`
	RequireKeyAttestation     *bool                  `json:"require_key_attestation,omitempty"`
	ClaimsMapping             map[string]interface{} `json:"claims_mapping,omitempty"`
}

// VCIOffer is a pre-authorized credential offer.
type VCIOffer struct {
	ID        string                 `json:"id"`
	OrgID     string                 `json:"org_id"`
	UserID    *string                `json:"user_id,omitempty"`
	VCT       string                 `json:"vct"`
	Status    string                 `json:"status"`
	ExpiresAt time.Time              `json:"expires_at"`
	CreatedAt time.Time              `json:"created_at"`
	Payload   map[string]interface{} `json:"payload,omitempty"`
}

// CreateVCIOfferParams are the fields for a new credential offer.
type CreateVCIOfferParams struct {
	UserID  *string                `json:"user_id,omitempty"`
	VCT     string                 `json:"vct"`
	TxCode  *string                `json:"tx_code,omitempty"`
	TTLMins int                    `json:"ttl_minutes,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// CreateVCIOfferResponse is returned when an offer is created.
type CreateVCIOfferResponse struct {
	OfferID            string                 `json:"offer_id"`
	CredentialOffer    map[string]interface{} `json:"credential_offer"`
	CredentialOfferURI string                 `json:"credential_offer_uri"`
	ExpiresAt          time.Time              `json:"expires_at"`
}

// SendVCIOfferParams selects the delivery channel for an offer deep-link.
type SendVCIOfferParams struct {
	Channel string `json:"channel"` // "sms"|"email"
	To      string `json:"to,omitempty"`
}

// VCIIssuedCredential is an issued SD-JWT VC record.
type VCIIssuedCredential struct {
	ID               string     `json:"id"`
	OrgID            string     `json:"org_id"`
	UserID           *string    `json:"user_id,omitempty"`
	VCT              string     `json:"vct"`
	IssuedAt         time.Time  `json:"issued_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	IsRevoked        bool       `json:"is_revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason *string    `json:"revocation_reason,omitempty"`
}

// ── Configs ────────────────────────────────────────────────────────────────────

// ListConfigs returns all credential configurations for orgID.
func (s *OID4VCIService) ListConfigs(ctx context.Context, orgID string) ([]VCICredentialConfig, error) {
	var out []VCICredentialConfig
	return out, s.c.get(ctx, orgPath(orgID, "/oid4vci/configs"), &out)
}

// CreateConfig creates a new credential configuration.
func (s *OID4VCIService) CreateConfig(ctx context.Context, orgID string, p CreateVCIConfigParams) (*VCICredentialConfig, error) {
	var out VCICredentialConfig
	return &out, s.c.post(ctx, orgPath(orgID, "/oid4vci/configs"), p, &out)
}

// PatchConfig updates a credential configuration.
func (s *OID4VCIService) PatchConfig(ctx context.Context, orgID, configID string, p PatchVCIConfigParams) (*VCICredentialConfig, error) {
	var out VCICredentialConfig
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/oid4vci/configs/%s", configID)), p, &out)
}

// DeleteConfig removes a credential configuration.
func (s *OID4VCIService) DeleteConfig(ctx context.Context, orgID, configID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/oid4vci/configs/%s", configID)))
}

// ── Catalog ────────────────────────────────────────────────────────────────────

// Catalog returns the credential catalog (available seed templates / types).
func (s *OID4VCIService) Catalog(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/oid4vci/catalog"), &out)
}

// SeedCatalog seeds a built-in credential catalog template. Pass an empty
// variant to seed the default set, or a variant such as "mdl", "spid",
// "it-wallet", "cie", "cie-wallet", "age-over-18", "spid-mdl".
func (s *OID4VCIService) SeedCatalog(ctx context.Context, orgID, variant string) error {
	path := "/oid4vci/catalog/seed"
	if variant != "" {
		path += "-" + variant
	}
	return s.c.post(ctx, orgPath(orgID, path), nil, nil)
}

// AnalyticsSummary returns issuance analytics for orgID.
func (s *OID4VCIService) AnalyticsSummary(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/oid4vci/analytics/summary"), &out)
}

// ── Offers ─────────────────────────────────────────────────────────────────────

// ListOffers returns all credential offers for orgID.
func (s *OID4VCIService) ListOffers(ctx context.Context, orgID string) ([]VCIOffer, error) {
	var out []VCIOffer
	return out, s.c.get(ctx, orgPath(orgID, "/oid4vci/offers"), &out)
}

// CreateOffer creates a pre-authorized credential offer.
func (s *OID4VCIService) CreateOffer(ctx context.Context, orgID string, p CreateVCIOfferParams) (*CreateVCIOfferResponse, error) {
	var out CreateVCIOfferResponse
	return &out, s.c.post(ctx, orgPath(orgID, "/oid4vci/offers"), p, &out)
}

// SendOffer delivers the offer deep-link via SMS or email.
func (s *OID4VCIService) SendOffer(ctx context.Context, orgID, offerID string, p SendVCIOfferParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/oid4vci/offers/%s/send", offerID)), p, &out)
}

// ── Issued credentials ─────────────────────────────────────────────────────────

// ListIssued returns issued credentials for orgID.
func (s *OID4VCIService) ListIssued(ctx context.Context, orgID string) ([]VCIIssuedCredential, error) {
	var out []VCIIssuedCredential
	return out, s.c.get(ctx, orgPath(orgID, "/oid4vci/issued"), &out)
}

// RevokeIssued revokes an issued credential.
func (s *OID4VCIService) RevokeIssued(ctx context.Context, orgID, credID, reason string) error {
	body := map[string]string{"reason": reason}
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/oid4vci/issued/%s/revoke", credID)), body, nil)
}

// RestoreIssued un-revokes a previously revoked credential.
func (s *OID4VCIService) RestoreIssued(ctx context.Context, orgID, credID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/oid4vci/issued/%s/restore", credID)), nil, nil)
}

// ── Deferred issuance ──────────────────────────────────────────────────────────

// ListDeferred returns pending deferred-issuance transactions.
func (s *OID4VCIService) ListDeferred(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/oid4vci/deferred"), &out)
}

// ApproveDeferred approves a deferred-issuance transaction.
func (s *OID4VCIService) ApproveDeferred(ctx context.Context, orgID, txnID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/oid4vci/deferred/%s/approve", txnID)), nil, nil)
}
