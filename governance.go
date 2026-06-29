package clavex

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// This file groups the identity/governance management services that complete
// the admin API surface: service accounts, login flows, lifecycle rules,
// SCIM push, SAML SPs, WS-Fed RPs, application families and agent tokens.
//
// Entity read responses are returned as decoded JSON objects to stay
// forward-compatible with the evolving server records; write inputs are typed.

// ── Service accounts ───────────────────────────────────────────────────────────

// ServiceAccountService manages machine-to-machine service accounts.
type ServiceAccountService struct{ c *Client }

// CreateServiceAccountParams defines a new service account.
type CreateServiceAccountParams struct {
	Name        string   `json:"name"`
	Description *string  `json:"description,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// UpdateServiceAccountParams are the mutable fields of a service account.
type UpdateServiceAccountParams struct {
	Name        *string  `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	IsActive    *bool    `json:"is_active,omitempty"`
}

// ServiceAccount is a machine-to-machine service account.
type ServiceAccount struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	ClientID    string     `json:"client_id"`
	Scopes      []string   `json:"scopes"`
	IsActive    bool       `json:"is_active"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ServiceAccountWithSecret is returned by create / rotate-secret; the secret is
// shown only once.
type ServiceAccountWithSecret struct {
	ServiceAccount ServiceAccount `json:"service_account"`
	ClientSecret   string         `json:"client_secret"`
	SecretNote     string         `json:"secret_note,omitempty"`
}

func (s *ServiceAccountService) List(ctx context.Context, orgID string) ([]ServiceAccount, error) {
	var out []ServiceAccount
	return out, s.c.get(ctx, orgPath(orgID, "/service-accounts"), &out)
}

func (s *ServiceAccountService) Get(ctx context.Context, orgID, id string) (*ServiceAccount, error) {
	var out ServiceAccount
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/service-accounts/%s", id)), &out)
}

func (s *ServiceAccountService) Create(ctx context.Context, orgID string, p CreateServiceAccountParams) (*ServiceAccountWithSecret, error) {
	var out ServiceAccountWithSecret
	return &out, s.c.post(ctx, orgPath(orgID, "/service-accounts"), p, &out)
}

func (s *ServiceAccountService) Update(ctx context.Context, orgID, id string, p UpdateServiceAccountParams) (*ServiceAccount, error) {
	var out ServiceAccount
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/service-accounts/%s", id)), p, &out)
}

func (s *ServiceAccountService) Delete(ctx context.Context, orgID, id string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/service-accounts/%s", id)))
}

// RotateSecret generates a new client secret (shown only once).
func (s *ServiceAccountService) RotateSecret(ctx context.Context, orgID, id string) (*ServiceAccountWithSecret, error) {
	var out ServiceAccountWithSecret
	return &out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/service-accounts/%s/secret", id)), nil, &out)
}

// ── Login flows ────────────────────────────────────────────────────────────────

// LoginFlowService manages multi-step login flows and their client bindings.
type LoginFlowService struct{ c *Client }

// CreateLoginFlowParams defines a new login flow.
type CreateLoginFlowParams struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	IsDefault   bool    `json:"is_default"`
}

// UpdateLoginFlowParams updates a login flow.
type UpdateLoginFlowParams struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	IsDefault   bool    `json:"is_default"`
	IsActive    bool    `json:"is_active"`
}

// LoginFlowStep is one step in a login flow (write shape).
type LoginFlowStep struct {
	StepType string                 `json:"step_type"`
	Position int                    `json:"position"`
	Config   map[string]interface{} `json:"config,omitempty"`
	IsActive *bool                  `json:"is_active,omitempty"`
}

// LoginFlow is a multi-step login flow.
type LoginFlow struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	IsDefault   bool       `json:"is_default"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Steps       []FlowStep `json:"steps,omitempty"`
}

// FlowStep is a stored login-flow step (read shape).
type FlowStep struct {
	ID       string          `json:"id"`
	FlowID   string          `json:"flow_id"`
	OrgID    string          `json:"org_id"`
	StepType string          `json:"step_type"`
	Position int             `json:"position"`
	Config   json.RawMessage `json:"config,omitempty"`
	IsActive bool            `json:"is_active"`
}

func (s *LoginFlowService) List(ctx context.Context, orgID string) ([]LoginFlow, error) {
	var out []LoginFlow
	return out, s.c.get(ctx, orgPath(orgID, "/login-flows"), &out)
}

func (s *LoginFlowService) Get(ctx context.Context, orgID, flowID string) (*LoginFlow, error) {
	var out LoginFlow
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/login-flows/%s", flowID)), &out)
}

func (s *LoginFlowService) Create(ctx context.Context, orgID string, p CreateLoginFlowParams) (*LoginFlow, error) {
	var out LoginFlow
	return &out, s.c.post(ctx, orgPath(orgID, "/login-flows"), p, &out)
}

func (s *LoginFlowService) Update(ctx context.Context, orgID, flowID string, p UpdateLoginFlowParams) (*LoginFlow, error) {
	var out LoginFlow
	return &out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/login-flows/%s", flowID)), p, &out)
}

func (s *LoginFlowService) Delete(ctx context.Context, orgID, flowID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/login-flows/%s", flowID)))
}

// ReplaceSteps replaces the ordered steps of a flow.
func (s *LoginFlowService) ReplaceSteps(ctx context.Context, orgID, flowID string, steps []LoginFlowStep) ([]FlowStep, error) {
	var out []FlowStep
	return out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/login-flows/%s/steps", flowID)), steps, &out)
}

// ListClients returns the client IDs bound to a flow.
func (s *LoginFlowService) ListClients(ctx context.Context, orgID, flowID string) ([]string, error) {
	var out []string
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/login-flows/%s/clients", flowID)), &out)
}

// AssignClient binds a client to a flow.
func (s *LoginFlowService) AssignClient(ctx context.Context, orgID, flowID, clientID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/login-flows/%s/clients", flowID)), map[string]string{"client_id": clientID}, nil)
}

// UnassignClient unbinds a client from a flow.
func (s *LoginFlowService) UnassignClient(ctx context.Context, orgID, flowID, clientID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/login-flows/%s/clients/%s", flowID, clientID)))
}

// ── Lifecycle rules ────────────────────────────────────────────────────────────

// LifecycleRuleService manages joiner/mover/leaver automation rules.
type LifecycleRuleService struct{ c *Client }

// LifecycleRuleParams defines a lifecycle rule. Conditions and actions are
// passed as raw JSON to match the server's evolving rule schema.
type LifecycleRuleParams struct {
	Name        string          `json:"name"`
	Description *string         `json:"description,omitempty"`
	Trigger     string          `json:"trigger"` // "joiner"|"mover"|"leaver"
	Priority    int             `json:"priority"`
	Conditions  json.RawMessage `json:"conditions"`
	Actions     json.RawMessage `json:"actions"`
	IsActive    *bool           `json:"is_active,omitempty"`
}

// LifecycleRule is a joiner/mover/leaver automation rule.
type LifecycleRule struct {
	ID          string          `json:"id"`
	OrgID       string          `json:"org_id"`
	Name        string          `json:"name"`
	Description *string         `json:"description,omitempty"`
	Trigger     string          `json:"trigger"`
	Priority    int             `json:"priority"`
	Conditions  json.RawMessage `json:"conditions"`
	Actions     json.RawMessage `json:"actions"`
	IsActive    bool            `json:"is_active"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func (s *LifecycleRuleService) List(ctx context.Context, orgID string) ([]LifecycleRule, error) {
	var out []LifecycleRule
	return out, s.c.get(ctx, orgPath(orgID, "/lifecycle-rules"), &out)
}

func (s *LifecycleRuleService) Get(ctx context.Context, orgID, ruleID string) (*LifecycleRule, error) {
	var out LifecycleRule
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/lifecycle-rules/%s", ruleID)), &out)
}

func (s *LifecycleRuleService) Create(ctx context.Context, orgID string, p LifecycleRuleParams) (*LifecycleRule, error) {
	var out LifecycleRule
	return &out, s.c.post(ctx, orgPath(orgID, "/lifecycle-rules"), p, &out)
}

func (s *LifecycleRuleService) Update(ctx context.Context, orgID, ruleID string, p LifecycleRuleParams) (*LifecycleRule, error) {
	var out LifecycleRule
	return &out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/lifecycle-rules/%s", ruleID)), p, &out)
}

func (s *LifecycleRuleService) Delete(ctx context.Context, orgID, ruleID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/lifecycle-rules/%s", ruleID)))
}

// ── SCIM push ──────────────────────────────────────────────────────────────────

// ScimPushService manages outbound SCIM provisioning targets.
type ScimPushService struct{ c *Client }

// CreateScimPushParams defines an outbound SCIM target.
type CreateScimPushParams struct {
	Name          string   `json:"name"`
	EndpointURL   string   `json:"endpoint_url"`
	BearerToken   string   `json:"bearer_token"`
	EnabledEvents []string `json:"enabled_events"`
}

// UpdateScimPushParams updates an outbound SCIM target.
type UpdateScimPushParams struct {
	Name          *string  `json:"name,omitempty"`
	EndpointURL   *string  `json:"endpoint_url,omitempty"`
	BearerToken   *string  `json:"bearer_token,omitempty"`
	EnabledEvents []string `json:"enabled_events,omitempty"`
	IsActive      *bool    `json:"is_active,omitempty"`
}

func (s *ScimPushService) List(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/scim-push"), &out)
}

func (s *ScimPushService) Create(ctx context.Context, orgID string, p CreateScimPushParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/scim-push"), p, &out)
}

func (s *ScimPushService) Update(ctx context.Context, orgID, id string, p UpdateScimPushParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/scim-push/%s", id)), p, &out)
}

func (s *ScimPushService) Delete(ctx context.Context, orgID, id string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/scim-push/%s", id)))
}

// ListDeliveries returns the delivery log for a SCIM push target.
func (s *ScimPushService) ListDeliveries(ctx context.Context, orgID, id string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/scim-push/%s/deliveries", id)), &out)
}

// RetryDelivery re-attempts a failed delivery.
func (s *ScimPushService) RetryDelivery(ctx context.Context, orgID, id, deliveryID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/scim-push/%s/deliveries/%s/retry", id, deliveryID)), nil, nil)
}

// ── SAML service providers ─────────────────────────────────────────────────────

// SamlSpService manages SAML service providers (Clavex as IdP).
type SamlSpService struct{ c *Client }

// CreateSamlSpParams registers a SAML service provider.
type CreateSamlSpParams struct {
	EntityID     string  `json:"entity_id"`
	Name         string  `json:"name"`
	ACSURL       string  `json:"acs_url"`
	SLOURL       *string `json:"slo_url,omitempty"`
	MetadataXML  *string `json:"metadata_xml,omitempty"`
	NameIDFormat string  `json:"name_id_format,omitempty"`
}

// SamlSP is a registered SAML service provider.
type SamlSP struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	EntityID     string    `json:"entity_id"`
	Name         string    `json:"name"`
	ACSURL       string    `json:"acs_url"`
	SLOURL       *string   `json:"slo_url,omitempty"`
	NameIDFormat string    `json:"name_id_format"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *SamlSpService) List(ctx context.Context, orgID string) ([]SamlSP, error) {
	var out []SamlSP
	return out, s.c.get(ctx, orgPath(orgID, "/saml/sps"), &out)
}

func (s *SamlSpService) Create(ctx context.Context, orgID string, p CreateSamlSpParams) (*SamlSP, error) {
	var out SamlSP
	return &out, s.c.post(ctx, orgPath(orgID, "/saml/sps"), p, &out)
}

func (s *SamlSpService) Delete(ctx context.Context, orgID, spID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/saml/sps/%s", spID)))
}

// ── WS-Federation relying parties ──────────────────────────────────────────────

// WsfedRpService manages WS-Federation relying parties.
type WsfedRpService struct{ c *Client }

// WsfedRpParams defines a WS-Fed relying party.
type WsfedRpParams struct {
	Name                 string            `json:"name"`
	Realm                string            `json:"realm"`
	WreplyURIs           []string          `json:"wreply_uris,omitempty"`
	TokenLifetimeSeconds int               `json:"token_lifetime_seconds,omitempty"`
	ClaimsMapping        map[string]string `json:"claims_mapping,omitempty"`
}

// WsfedRP is a WS-Federation relying party.
type WsfedRP struct {
	ID                   string            `json:"id"`
	OrgID                string            `json:"org_id"`
	Name                 string            `json:"name"`
	Realm                string            `json:"realm"`
	WreplyURIs           []string          `json:"wreply_uris"`
	TokenLifetimeSeconds int               `json:"token_lifetime_seconds"`
	ClaimsMapping        map[string]string `json:"claims_mapping"`
	IsActive             bool              `json:"is_active"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

func (s *WsfedRpService) List(ctx context.Context, orgID string) ([]WsfedRP, error) {
	var out []WsfedRP
	return out, s.c.get(ctx, orgPath(orgID, "/wsfed/relying-parties"), &out)
}

func (s *WsfedRpService) Get(ctx context.Context, orgID, rpID string) (*WsfedRP, error) {
	var out WsfedRP
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/wsfed/relying-parties/%s", rpID)), &out)
}

func (s *WsfedRpService) Create(ctx context.Context, orgID string, p WsfedRpParams) (*WsfedRP, error) {
	var out WsfedRP
	return &out, s.c.post(ctx, orgPath(orgID, "/wsfed/relying-parties"), p, &out)
}

func (s *WsfedRpService) Update(ctx context.Context, orgID, rpID string, p WsfedRpParams) (*WsfedRP, error) {
	var out WsfedRP
	return &out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/wsfed/relying-parties/%s", rpID)), p, &out)
}

func (s *WsfedRpService) Delete(ctx context.Context, orgID, rpID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/wsfed/relying-parties/%s", rpID)))
}

// ── Application families ───────────────────────────────────────────────────────

// AppFamilyService manages application families (grouped SSO clients).
type AppFamilyService struct{ c *Client }

// AppFamilyParams defines an application family.
type AppFamilyParams struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// AppFamily groups OIDC clients for cross-app SSO and coordinated logout.
type AppFamily struct {
	ID          string            `json:"id"`
	OrgID       string            `json:"org_id"`
	Name        string            `json:"name"`
	Description *string           `json:"description,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Members     []AppFamilyMember `json:"members,omitempty"`
}

// AppFamilyMember is a client that belongs to an application family.
type AppFamilyMember struct {
	FamilyID             string    `json:"family_id"`
	ClientID             string    `json:"client_id"`
	BackchannelLogoutURI *string   `json:"backchannel_logout_uri,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

func (s *AppFamilyService) List(ctx context.Context, orgID string) ([]AppFamily, error) {
	var out []AppFamily
	return out, s.c.get(ctx, orgPath(orgID, "/app-families"), &out)
}

func (s *AppFamilyService) Get(ctx context.Context, orgID, familyID string) (*AppFamily, error) {
	var out AppFamily
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/app-families/%s", familyID)), &out)
}

func (s *AppFamilyService) Create(ctx context.Context, orgID string, p AppFamilyParams) (*AppFamily, error) {
	var out AppFamily
	return &out, s.c.post(ctx, orgPath(orgID, "/app-families"), p, &out)
}

func (s *AppFamilyService) Update(ctx context.Context, orgID, familyID string, p AppFamilyParams) (*AppFamily, error) {
	var out AppFamily
	return &out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/app-families/%s", familyID)), p, &out)
}

func (s *AppFamilyService) Delete(ctx context.Context, orgID, familyID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/app-families/%s", familyID)))
}

// AddMember adds a client to an application family.
func (s *AppFamilyService) AddMember(ctx context.Context, orgID, familyID, clientID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/app-families/%s/members", familyID)), map[string]string{"client_id": clientID}, nil)
}

// RemoveMember removes a client from an application family.
func (s *AppFamilyService) RemoveMember(ctx context.Context, orgID, familyID, clientID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/app-families/%s/members/%s", familyID, clientID)))
}

// ── Agent tokens ───────────────────────────────────────────────────────────────

// AgentTokenService manages AI-agent access tokens (MCP).
type AgentTokenService struct{ c *Client }

// IssueAgentTokenParams issues a scoped agent token.
type IssueAgentTokenParams struct {
	UserID      string  `json:"user_id"`
	AgentID     string  `json:"agent_id"`
	AgentName   string  `json:"agent_name"`
	Scope       string  `json:"scope,omitempty"`
	TTLSeconds  int     `json:"ttl_seconds,omitempty"`
	MCPServerID *string `json:"mcp_server_id,omitempty"`
}

// AgentToken is an issued AI-agent (MCP) access token record.
type AgentToken struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	UserID      string     `json:"user_id"`
	AgentID     string     `json:"agent_id"`
	AgentName   string     `json:"agent_name"`
	Scope       string     `json:"scope"`
	IsRevoked   bool       `json:"is_revoked"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	MCPServerID *string    `json:"mcp_server_id,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// IssuedAgentToken carries the signed JWT (shown once) plus the record ID.
type IssuedAgentToken struct {
	Token     string `json:"token"`
	TokenID   string `json:"token_id"`
	ExpiresAt string `json:"expires_at"`
}

func (s *AgentTokenService) List(ctx context.Context, orgID string) ([]AgentToken, error) {
	var out []AgentToken
	return out, s.c.get(ctx, orgPath(orgID, "/agent-tokens"), &out)
}

// Issue creates a new agent token. The token is shown only once.
func (s *AgentTokenService) Issue(ctx context.Context, orgID string, p IssueAgentTokenParams) (*IssuedAgentToken, error) {
	var out IssuedAgentToken
	return &out, s.c.post(ctx, orgPath(orgID, "/agent-tokens"), p, &out)
}

func (s *AgentTokenService) Delete(ctx context.Context, orgID, id string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/agent-tokens/%s", id)))
}

// MCPScopes returns the available MCP scopes for agent tokens.
func (s *AgentTokenService) MCPScopes(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/agent-tokens/mcp-scopes"), &out)
}
