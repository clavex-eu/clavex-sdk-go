package clavex

import (
	"context"
	"fmt"
	"time"
)

// ── mdoc (ISO 18013-5 mobile documents) ───────────────────────────────────────

// MdocService manages ISO 18013-5 mdoc issuers and the IACA trust roots used to
// validate presented mobile documents (mDL, PID, etc).
type MdocService struct{ c *Client }

// MdocIssuer is an org's mdoc Document Signer (DS) configuration.
type MdocIssuer struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"org_id"`
	DisplayName        string    `json:"display_name"`
	DocType            string    `json:"doc_type"`
	DSCertificatePEM   string    `json:"ds_certificate_pem"`
	IACACertificatePEM *string   `json:"iaca_certificate_pem,omitempty"`
	ValidityHours      int       `json:"validity_hours"`
	IsActive           bool      `json:"is_active"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// IACARoot is a trusted IACA root certificate.
type IACARoot struct {
	ID                string    `json:"id"`
	OrgID             string    `json:"org_id"`
	Label             string    `json:"label"`
	SubjectDN         string    `json:"subject_dn"`
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
	PEM               string    `json:"pem"`
	DocTypes          []string  `json:"doc_types"`
	IsActive          bool      `json:"is_active"`
	CreatedAt         time.Time `json:"created_at"`
}

// GenerateIssuerParams requests a freshly generated self-signed DS/IACA pair.
type GenerateIssuerParams struct {
	DisplayName string `json:"display_name"`
	DocType     string `json:"doc_type,omitempty"`
}

// GenerateIssuerResponse carries the new issuer plus its generated certificates.
type GenerateIssuerResponse struct {
	Issuer          MdocIssuer `json:"issuer"`
	DSCertificate   string     `json:"ds_certificate"`
	IACACertificate string     `json:"iaca_certificate"`
}

// CreateIssuerParams registers an issuer with caller-provided key material.
type CreateIssuerParams struct {
	DisplayName        string  `json:"display_name"`
	DocType            string  `json:"doc_type"`
	DSPrivateKeyPEM    string  `json:"ds_private_key_pem"`
	DSCertificatePEM   string  `json:"ds_certificate_pem"`
	IACACertificatePEM *string `json:"iaca_certificate_pem,omitempty"`
	ValidityHours      int     `json:"validity_hours,omitempty"`
}

// CreateIACARootParams uploads a trusted IACA root certificate.
type CreateIACARootParams struct {
	Label    string   `json:"label"`
	PEM      string   `json:"pem"`
	DocTypes []string `json:"doc_types,omitempty"`
}

// ── Issuers ────────────────────────────────────────────────────────────────────

// ListIssuers returns all mdoc issuers for orgID.
func (s *MdocService) ListIssuers(ctx context.Context, orgID string) ([]MdocIssuer, error) {
	var out []MdocIssuer
	return out, s.c.get(ctx, orgPath(orgID, "/mdoc/issuers"), &out)
}

// GenerateIssuer creates an issuer with a freshly generated self-signed DS pair.
func (s *MdocService) GenerateIssuer(ctx context.Context, orgID string, p GenerateIssuerParams) (*GenerateIssuerResponse, error) {
	var out GenerateIssuerResponse
	return &out, s.c.post(ctx, orgPath(orgID, "/mdoc/issuers/generate"), p, &out)
}

// CreateIssuer registers an issuer with caller-provided key material.
func (s *MdocService) CreateIssuer(ctx context.Context, orgID string, p CreateIssuerParams) (*MdocIssuer, error) {
	var out MdocIssuer
	return &out, s.c.post(ctx, orgPath(orgID, "/mdoc/issuers"), p, &out)
}

// DeleteIssuer removes an mdoc issuer.
func (s *MdocService) DeleteIssuer(ctx context.Context, orgID, issuerID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/mdoc/issuers/%s", issuerID)))
}

// ── IACA roots ─────────────────────────────────────────────────────────────────

// ListIACARoots returns all trusted IACA roots for orgID.
func (s *MdocService) ListIACARoots(ctx context.Context, orgID string) ([]IACARoot, error) {
	var out []IACARoot
	return out, s.c.get(ctx, orgPath(orgID, "/mdoc/iaca-roots"), &out)
}

// CreateIACARoot uploads a trusted IACA root certificate.
func (s *MdocService) CreateIACARoot(ctx context.Context, orgID string, p CreateIACARootParams) (*IACARoot, error) {
	var out IACARoot
	return &out, s.c.post(ctx, orgPath(orgID, "/mdoc/iaca-roots"), p, &out)
}

// DeleteIACARoot removes a trusted IACA root.
func (s *MdocService) DeleteIACARoot(ctx context.Context, orgID, rootID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/mdoc/iaca-roots/%s", rootID)))
}

// ── Presentation sessions ──────────────────────────────────────────────────────

// ListSessions returns mdoc presentation sessions for orgID.
func (s *MdocService) ListSessions(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/mdoc/sessions"), &out)
}

// GetSession returns a single mdoc presentation session.
func (s *MdocService) GetSession(ctx context.Context, orgID, sessionID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/mdoc/sessions/%s", sessionID)), &out)
}
