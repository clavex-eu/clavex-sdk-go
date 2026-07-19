package clavex

import (
	"context"
	"fmt"
	"time"
)

// UsageService provides tenant usage analytics for billing dashboards and
// security posture reports.
//
//	usage, err := client.Usage.Get(ctx, orgID)
//	fmt.Printf("MAU: %d, DAU: %d\n", usage.MAU, usage.DAU)
type UsageService struct{ c *Client }

// Get returns the usage statistics for orgID over the trailing 30 days.
func (s *UsageService) Get(ctx context.Context, orgID string) (*OrgUsage, error) {
	var out OrgUsage
	return &out, s.c.get(ctx, fmt.Sprintf("/api/v1/organizations/%s/usage", orgID), &out)
}

// SecurityPosture returns the security health summary for orgID.
//
//	posture, err := client.Usage.SecurityPosture(ctx, orgID)
//	fmt.Println(posture.Score, posture.Recommendations)
func (s *UsageService) SecurityPosture(ctx context.Context, orgID string) (*SecurityPosture, error) {
	var out SecurityPosture
	return &out, s.c.get(ctx, fmt.Sprintf("/api/v1/organizations/%s/security-posture", orgID), &out)
}

// ── Login History ─────────────────────────────────────────────────────────────

// LoginHistoryService provides read access to the immutable authentication
// event log.
type LoginHistoryService struct{ c *Client }

// ListByOrg returns login history for the entire org (cursor-paginated).
//
//	page, err := client.LoginHistory.ListByOrg(ctx, orgID, clavex.ListOptions{Limit: 100})
func (s *LoginHistoryService) ListByOrg(ctx context.Context, orgID string, opts ListOptions) (*Page[LoginHistoryEntry], error) {
	var out Page[LoginHistoryEntry]
	return &out, s.c.get(ctx, withQuery(orgPath(orgID, "/login-history"), opts), &out)
}

// ListByUser returns login history for a specific user (cursor-paginated).
func (s *LoginHistoryService) ListByUser(ctx context.Context, orgID, userID string, opts ListOptions) (*Page[LoginHistoryEntry], error) {
	var out Page[LoginHistoryEntry]
	path := orgPath(orgID, fmt.Sprintf("/users/%s/login-history", userID))
	return &out, s.c.get(ctx, withQuery(path, opts), &out)
}

// ── Rate limits ───────────────────────────────────────────────────────────────

// RateLimitService manages per-org login rate-limit configuration.
type RateLimitService struct{ c *Client }

// Get returns the current rate-limit settings for orgID.
func (s *RateLimitService) Get(ctx context.Context, orgID string) (*RateLimitConfig, error) {
	var out RateLimitConfig
	return &out, s.c.get(ctx, orgPath(orgID, "/rate-limits"), &out)
}

// Update replaces the rate-limit settings for orgID.
func (s *RateLimitService) Update(ctx context.Context, orgID string, cfg RateLimitConfig) (*RateLimitConfig, error) {
	var out RateLimitConfig
	return &out, s.c.put(ctx, orgPath(orgID, "/rate-limits"), cfg, &out)
}

// ReleaseManagedMarker clears the declarative-management marker on orgID's
// rate-limit config without changing its configured values. A declarative
// caller (the Kubernetes operator) calls this when it stops managing the
// section.
func (s *RateLimitService) ReleaseManagedMarker(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, orgPath(orgID, "/rate-limits/managed-marker"))
}

// ── Audit log extended ────────────────────────────────────────────────────────

// ListPage returns a cursor-paginated page of audit log entries.
//
//	page, err := client.AuditLog.ListPage(ctx, orgID, clavex.ListOptions{Limit: 200})
func (s *AuditService) ListPage(ctx context.Context, orgID string, opts ListOptions) (*Page[AuditLogEntry], error) {
	var out Page[AuditLogEntry]
	return &out, s.c.get(ctx, withQuery(orgPath(orgID, "/audit"), opts), &out)
}

// Export downloads audit log entries as NDJSON. The raw bytes are returned
// so callers can write them to a file or stream them to a SIEM.
func (s *AuditService) Export(ctx context.Context, orgID string, opts ListOptions) ([]byte, error) {
	// export returns a raw NDJSON response \u2014 use a custom request.
	token, err := s.c.bearerToken(ctx)
	if err != nil {
		return nil, err
	}
	path := withQuery(orgPath(orgID, "/audit/export"), opts)
	req, err := newGetRequest(ctx, s.c.base+path, token)
	if err != nil {
		return nil, err
	}
	resp, err := s.c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, &APIError{StatusCode: resp.StatusCode}
	}
	return readAll(resp)
}

// ── Audit sinks ───────────────────────────────────────────────────────────────

// CreateSinkParams defines the fields for an audit log sink.
type CreateSinkParams struct {
	// Type is the sink backend: "http" | "syslog" | "s3" | "splunk".
	Type   string            `json:"type"`
	Config map[string]string `json:"config"`
	// Events is the allow-list of event types to forward. Empty = all events.
	Events []string `json:"events,omitempty"`
}

// AuditSink is an outbound integration that forwards audit events.
type AuditSink struct {
	ID        string            `json:"id"`
	OrgID     string            `json:"org_id"`
	Type      string            `json:"type"`
	Config    map[string]string `json:"config,omitempty"`
	Events    []string          `json:"events,omitempty"`
	IsActive  bool              `json:"is_active"`
	CreatedAt time.Time         `json:"created_at"`
}

// ListSinks returns all audit sinks for orgID.
func (s *AuditService) ListSinks(ctx context.Context, orgID string) ([]AuditSink, error) {
	var out []AuditSink
	return out, s.c.get(ctx, orgPath(orgID, "/audit/sinks"), &out)
}

// CreateSink registers a new audit sink.
func (s *AuditService) CreateSink(ctx context.Context, orgID string, p CreateSinkParams) (*AuditSink, error) {
	var out AuditSink
	return &out, s.c.post(ctx, orgPath(orgID, "/audit/sinks"), p, &out)
}

// UpdateSink modifies an existing audit sink.
func (s *AuditService) UpdateSink(ctx context.Context, orgID, sinkID string, p CreateSinkParams) (*AuditSink, error) {
	var out AuditSink
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/audit/sinks/%s", sinkID)), p, &out)
}

// DeleteSink removes an audit sink.
func (s *AuditService) DeleteSink(ctx context.Context, orgID, sinkID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/audit/sinks/%s", sinkID)))
}

// TestSink fires a test event to a sink to verify connectivity.
func (s *AuditService) TestSink(ctx context.Context, orgID, sinkID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/audit/sinks/%s/test", sinkID)), nil, nil)
}
