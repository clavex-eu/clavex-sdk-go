package clavex

import (
	"context"
	"net/url"
	"time"
)

// ── OpenID Federation (trust anchor) ──────────────────────────────────────────

// FederationService manages the OpenID Federation trust-anchor surface:
// subordinate entities and trust-mark types.
//
// Subordinate operations identify the entity via the `entity_id` query
// parameter rather than a path segment, mirroring the backend API.
type FederationService struct{ c *Client }

// FederationSubordinate is a registered subordinate entity statement.
type FederationSubordinate struct {
	ID                       string    `json:"id"`
	EntityID                 string    `json:"entity_id"`
	Name                     string    `json:"name"`
	EntityTypes              []string  `json:"entity_types"`
	TrustMarkIDs             []string  `json:"trust_mark_ids,omitempty"`
	Status                   string    `json:"status"`
	StatementLifetimeSeconds int       `json:"statement_lifetime_seconds,omitempty"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

// RegisterSubordinateParams registers or updates a subordinate entity.
type RegisterSubordinateParams struct {
	EntityID                 string                 `json:"entity_id"`
	Name                     string                 `json:"name"`
	EntityTypes              []string               `json:"entity_types"`
	JWKS                     map[string]interface{} `json:"jwks,omitempty"`
	JWKSURI                  string                 `json:"jwks_uri,omitempty"`
	MetadataOverride         map[string]interface{} `json:"metadata_override,omitempty"`
	MetadataPolicy           map[string]interface{} `json:"metadata_policy,omitempty"`
	TrustMarkIDs             []string               `json:"trust_mark_ids,omitempty"`
	Status                   string                 `json:"status,omitempty"`
	StatementLifetimeSeconds int                    `json:"statement_lifetime_seconds,omitempty"`
}

// TrustMarkType is a trust-mark type definition issued by this trust anchor.
type TrustMarkType struct {
	TrustMarkID     string    `json:"trust_mark_id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	LogoURI         string    `json:"logo_uri,omitempty"`
	RefURI          string    `json:"ref_uri,omitempty"`
	LifetimeSeconds int       `json:"lifetime_seconds,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// UpsertTrustMarkTypeParams creates or replaces a trust-mark type.
type UpsertTrustMarkTypeParams struct {
	TrustMarkID     string `json:"trust_mark_id"`
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	RefURI          string `json:"ref_uri,omitempty"`
	LifetimeSeconds int    `json:"lifetime_seconds,omitempty"`
}

// RevokeTrustMarkParams revokes an issued trust mark for a subject.
type RevokeTrustMarkParams struct {
	TrustMarkID string `json:"trust_mark_id"`
	Sub         string `json:"sub"`
	Reason      string `json:"reason,omitempty"`
}

// ── Subordinates ───────────────────────────────────────────────────────────────

// ListSubordinates returns subordinate entities. status may be "active",
// "suspended", "revoked", "all", or empty for the default view.
func (s *FederationService) ListSubordinates(ctx context.Context, orgID, status string) ([]FederationSubordinate, error) {
	path := orgPath(orgID, "/federation/subordinates")
	if status != "" {
		path += "?status=" + url.QueryEscape(status)
	}
	var out struct {
		Subordinates []FederationSubordinate `json:"subordinates"`
		Count        int                     `json:"count"`
	}
	err := s.c.get(ctx, path, &out)
	return out.Subordinates, err
}

// GetSubordinate returns a single subordinate by entity ID.
func (s *FederationService) GetSubordinate(ctx context.Context, orgID, entityID string) (*FederationSubordinate, error) {
	path := orgPath(orgID, "/federation/subordinates/detail") + "?entity_id=" + url.QueryEscape(entityID)
	var out FederationSubordinate
	return &out, s.c.get(ctx, path, &out)
}

// RegisterSubordinate registers a new subordinate entity.
func (s *FederationService) RegisterSubordinate(ctx context.Context, orgID string, p RegisterSubordinateParams) (*FederationSubordinate, error) {
	var out FederationSubordinate
	return &out, s.c.post(ctx, orgPath(orgID, "/federation/subordinates"), p, &out)
}

// UpdateSubordinate updates an existing subordinate (identified by entity ID).
func (s *FederationService) UpdateSubordinate(ctx context.Context, orgID, entityID string, p RegisterSubordinateParams) (*FederationSubordinate, error) {
	path := orgPath(orgID, "/federation/subordinates") + "?entity_id=" + url.QueryEscape(entityID)
	var out FederationSubordinate
	return &out, s.c.put(ctx, path, p, &out)
}

// RevokeSubordinate removes a subordinate entity.
func (s *FederationService) RevokeSubordinate(ctx context.Context, orgID, entityID string) error {
	path := orgPath(orgID, "/federation/subordinates") + "?entity_id=" + url.QueryEscape(entityID)
	return s.c.delete(ctx, path)
}

// ── Trust marks ────────────────────────────────────────────────────────────────

// ListTrustMarkTypes returns the trust-mark types defined by this trust anchor.
func (s *FederationService) ListTrustMarkTypes(ctx context.Context, orgID string) ([]TrustMarkType, error) {
	var out []TrustMarkType
	return out, s.c.get(ctx, orgPath(orgID, "/federation/trust-mark-types"), &out)
}

// UpsertTrustMarkType creates or replaces a trust-mark type.
func (s *FederationService) UpsertTrustMarkType(ctx context.Context, orgID string, p UpsertTrustMarkTypeParams) (*TrustMarkType, error) {
	var out TrustMarkType
	return &out, s.c.post(ctx, orgPath(orgID, "/federation/trust-mark-types"), p, &out)
}

// RevokeTrustMark revokes an issued trust mark for a subject. The backend
// DELETE endpoint accepts the parameters in the request body.
func (s *FederationService) RevokeTrustMark(ctx context.Context, orgID string, p RevokeTrustMarkParams) error {
	return s.c.do(ctx, "DELETE", orgPath(orgID, "/federation/trust-marks"), p, nil)
}
