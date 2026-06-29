package clavex

import (
	"context"
	"encoding/json"
	"fmt"
)

// This file groups the access-governance and compliance services: access-review
// and entity-review campaigns, compliance/GDPR reporting, event actions, the AI
// copilot, and step-up (elevate) challenges.

// ── Access-review campaigns ────────────────────────────────────────────────────

// AccessReviewService manages periodic user access-review (certification) campaigns.
type AccessReviewService struct{ c *Client }

// CreateAccessReviewParams defines an access-review campaign.
type CreateAccessReviewParams struct {
	Name         string  `json:"name"`
	Description  *string `json:"description,omitempty"`
	Frequency    string  `json:"frequency"`
	StartsAt     string  `json:"starts_at"`
	EndsAt       string  `json:"ends_at"`
	ReminderDays []int   `json:"reminder_days,omitempty"`
	AutoRevoke   bool    `json:"auto_revoke"`
}

func (s *AccessReviewService) List(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/access-reviews"), &out)
}

func (s *AccessReviewService) Get(ctx context.Context, orgID, campaignID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/access-reviews/%s", campaignID)), &out)
}

func (s *AccessReviewService) Create(ctx context.Context, orgID string, p CreateAccessReviewParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/access-reviews"), p, &out)
}

func (s *AccessReviewService) Delete(ctx context.Context, orgID, campaignID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/access-reviews/%s", campaignID)))
}

func (s *AccessReviewService) Launch(ctx context.Context, orgID, campaignID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/access-reviews/%s/launch", campaignID)), nil, nil)
}

func (s *AccessReviewService) ListItems(ctx context.Context, orgID, campaignID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/access-reviews/%s/items", campaignID)), &out)
}

func (s *AccessReviewService) Report(ctx context.Context, orgID, campaignID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/access-reviews/%s/report", campaignID)), &out)
}

// ── Entity-review campaigns ────────────────────────────────────────────────────

// EntityReviewService manages reviews of non-user entities (clients, IdPs, ...).
type EntityReviewService struct{ c *Client }

// CreateEntityReviewParams defines an entity-review campaign.
type CreateEntityReviewParams struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	EntityType  string  `json:"entity_type"`
	ReviewerID  string  `json:"reviewer_id"`
}

func (s *EntityReviewService) List(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/entity-review-campaigns"), &out)
}

func (s *EntityReviewService) Get(ctx context.Context, orgID, campaignID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/entity-review-campaigns/%s", campaignID)), &out)
}

func (s *EntityReviewService) Create(ctx context.Context, orgID string, p CreateEntityReviewParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/entity-review-campaigns"), p, &out)
}

func (s *EntityReviewService) Delete(ctx context.Context, orgID, campaignID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/entity-review-campaigns/%s", campaignID)))
}

func (s *EntityReviewService) Activate(ctx context.Context, orgID, campaignID, reviewerID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/entity-review-campaigns/%s/activate", campaignID)), map[string]string{"reviewer_id": reviewerID}, &out)
}

func (s *EntityReviewService) ListItems(ctx context.Context, orgID, campaignID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/entity-review-campaigns/%s/items", campaignID)), &out)
}

// ── Compliance & GDPR ──────────────────────────────────────────────────────────

// ComplianceService exposes compliance scoring, processing records and GDPR ops.
type ComplianceService struct{ c *Client }

// ProcessingRecordParams is a GDPR Article 30 record of processing activity.
type ProcessingRecordParams struct {
	ActivityName    string      `json:"activity_name"`
	Purpose         string      `json:"purpose"`
	LegalBasis      string      `json:"legal_basis"`
	DataCategories  []string    `json:"data_categories,omitempty"`
	DataSubjects    string      `json:"data_subjects"`
	RetentionPeriod string      `json:"retention_period"`
	Recipients      interface{} `json:"recipients,omitempty"`
	Processors      interface{} `json:"processors,omitempty"`
}

// Score returns the current compliance score.
func (s *ComplianceService) Score(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/compliance/score"), &out)
}

// ScoreHistory returns the compliance score history.
func (s *ComplianceService) ScoreHistory(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/compliance/score/history"), &out)
}

// GDPRReport returns the GDPR compliance report.
func (s *ComplianceService) GDPRReport(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/compliance/gdpr"), &out)
}

// NIS2Report returns the NIS2 compliance report.
func (s *ComplianceService) NIS2Report(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/compliance/nis2"), &out)
}

// DSAR returns the data-subject-access report for a user.
func (s *ComplianceService) DSAR(ctx context.Context, orgID, userID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/compliance/dsar/%s", userID)), &out)
}

// ListProcessingRecords returns the records of processing activities.
func (s *ComplianceService) ListProcessingRecords(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/compliance/processing-records"), &out)
}

func (s *ComplianceService) CreateProcessingRecord(ctx context.Context, orgID string, p ProcessingRecordParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/compliance/processing-records"), p, &out)
}

func (s *ComplianceService) UpdateProcessingRecord(ctx context.Context, orgID, recordID string, p ProcessingRecordParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/compliance/processing-records/%s", recordID)), p, &out)
}

func (s *ComplianceService) DeleteProcessingRecord(ctx context.Context, orgID, recordID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/compliance/processing-records/%s", recordID)))
}

// AuditPack generates a signed compliance audit pack.
func (s *ComplianceService) AuditPack(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/compliance/audit-pack"), nil, &out)
}

// GDPRExport triggers a GDPR data export.
func (s *ComplianceService) GDPRExport(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/compliance/gdpr/export"), nil, &out)
}

// GDPRErasure erases a user's personal data (right to be forgotten).
func (s *ComplianceService) GDPRErasure(ctx context.Context, orgID, userID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/compliance/gdpr-erasure/%s", userID)))
}

// GdprService manages the GDPR data-retention policy.
type GdprService struct{ c *Client }

// RetentionPolicyParams configures inactive-data retention.
type RetentionPolicyParams struct {
	Enabled         bool     `json:"enabled"`
	RetentionDays   int      `json:"retention_days"`
	ActivityField   string   `json:"activity_field,omitempty"`
	ExemptRoleNames []string `json:"exempt_role_names,omitempty"`
}

func (s *GdprService) GetRetentionPolicy(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/gdpr/retention-policy"), &out)
}

func (s *GdprService) PutRetentionPolicy(ctx context.Context, orgID string, p RetentionPolicyParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.put(ctx, orgPath(orgID, "/gdpr/retention-policy"), p, &out)
}

func (s *GdprService) DeleteRetentionPolicy(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, orgPath(orgID, "/gdpr/retention-policy"))
}

// ── Event actions ──────────────────────────────────────────────────────────────

// ActionsService manages outbound action targets and event-triggered executions.
type ActionsService struct{ c *Client }

// UpsertActionTargetParams defines an action target (webhook/sandbox).
type UpsertActionTargetParams struct {
	TargetType    string  `json:"target_type"`
	URL           string  `json:"url"`
	SandboxCode   *string `json:"sandbox_code,omitempty"`
	TimeoutMs     int     `json:"timeout_ms,omitempty"`
	SigningSecret *string `json:"signing_secret,omitempty"`
	IsActive      *bool   `json:"is_active,omitempty"`
}

// CreateActionExecutionParams binds an action target to an event.
type CreateActionExecutionParams struct {
	TargetID  string          `json:"target_id"`
	Name      string          `json:"name"`
	EventType string          `json:"event_type"`
	Condition json.RawMessage `json:"condition,omitempty"`
	Mode      string          `json:"mode,omitempty"`
	IsActive  *bool           `json:"is_active,omitempty"`
}

func (s *ActionsService) ListTargets(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/actions/targets"), &out)
}

// UpsertTarget creates or replaces an action target identified by name.
func (s *ActionsService) UpsertTarget(ctx context.Context, orgID, name string, p UpsertActionTargetParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/actions/targets/%s", name)), p, &out)
}

func (s *ActionsService) DeleteTarget(ctx context.Context, orgID, targetID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/actions/targets/%s", targetID)))
}

func (s *ActionsService) ListExecutions(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/actions/executions"), &out)
}

func (s *ActionsService) CreateExecution(ctx context.Context, orgID string, p CreateActionExecutionParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/actions/executions"), p, &out)
}

func (s *ActionsService) UpdateExecution(ctx context.Context, orgID, executionID string, p CreateActionExecutionParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/actions/executions/%s", executionID)), p, &out)
}

func (s *ActionsService) DeleteExecution(ctx context.Context, orgID, executionID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/actions/executions/%s", executionID)))
}

// ── AI copilot ─────────────────────────────────────────────────────────────────

// AIService exposes the AI security copilot and suggestion endpoints.
type AIService struct{ c *Client }

// GetConfig returns the AI copilot configuration.
func (s *AIService) GetConfig(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, "/ai/config"), &out)
}

// PutConfig updates the AI copilot configuration.
func (s *AIService) PutConfig(ctx context.Context, orgID string, cfg map[string]interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.put(ctx, orgPath(orgID, "/ai/config"), cfg, &out)
}

// Suggest invokes an AI suggestion/analysis endpoint by kind, e.g. "suggest-policy",
// "suggest-dcql", "explain-anomaly", "audit-copilot", "nl-audit-query".
func (s *AIService) Suggest(ctx context.Context, orgID, kind string, body interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/ai/"+kind), body, &out)
}

// ── Step-up (elevate) ──────────────────────────────────────────────────────────

// ElevateService manages step-up authentication challenges for sensitive actions.
type ElevateService struct{ c *Client }

// CreateElevateParams starts a step-up challenge.
type CreateElevateParams struct {
	BearerToken    string   `json:"bearer_token"`
	Reason         string   `json:"reason"`
	AllowedMethods []string `json:"allowed_methods,omitempty"` // ["totp","webauthn"]; empty = all
}

// VerifyElevateParams completes a step-up challenge.
type VerifyElevateParams struct {
	Method     string          `json:"method"` // "totp"|"webauthn"
	Code       string          `json:"code,omitempty"`
	Credential json.RawMessage `json:"credential,omitempty"`
}

// Create starts a step-up challenge.
func (s *ElevateService) Create(ctx context.Context, orgID string, p CreateElevateParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, "/elevate"), p, &out)
}

// Get returns the status of a step-up challenge.
func (s *ElevateService) Get(ctx context.Context, orgID, challengeID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/elevate/%s", challengeID)), &out)
}

// Verify completes a step-up challenge.
func (s *ElevateService) Verify(ctx context.Context, orgID, challengeID string, p VerifyElevateParams) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/elevate/%s/verify", challengeID)), p, &out)
}

// WebAuthnBegin starts a WebAuthn step-up assertion.
func (s *ElevateService) WebAuthnBegin(ctx context.Context, orgID, challengeID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/elevate/%s/webauthn/begin", challengeID)), nil, &out)
}
