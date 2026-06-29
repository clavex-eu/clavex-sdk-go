package clavex

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

// ── FGA (Fine-Grained Authorization, ReBAC) ───────────────────────────────────

// FGAService manages the relationship-based authorization store: the
// authorization model, relationship tuples, and authorization checks. The model
// is an OpenFGA-style DSL/JSON document handled as raw JSON.
//
//	allowed, err := client.FGA.Check(ctx, orgID, clavex.FGATuple{
//	    User: "user:alice", Relation: "viewer", Object: "doc:readme",
//	})
type FGAService struct{ c *Client }

// FGATuple is a relationship tuple (user, relation, object).
type FGATuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// FGAStoreInfo describes the org's FGA store.
type FGAStoreInfo struct {
	StoreID   string  `json:"store_id"`
	ModelID   *string `json:"model_id"`
	Message   string  `json:"message,omitempty"`
	CreatedAt *string `json:"created_at,omitempty"`
	UpdatedAt *string `json:"updated_at,omitempty"`
}

// FGAReadResult is a page of stored tuples.
type FGAReadResult struct {
	Tuples            []FGATuple `json:"tuples"`
	ContinuationToken string     `json:"continuation_token,omitempty"`
}

// FGAReadParams filters a tuple read. Empty fields are treated as wildcards.
type FGAReadParams struct {
	User              string
	Relation          string
	Object            string
	PageSize          int
	ContinuationToken string
}

// ── Store ──────────────────────────────────────────────────────────────────────

// InitStore creates (or returns the existing) FGA store for the org.
func (s *FGAService) InitStore(ctx context.Context, orgID string) (*FGAStoreInfo, error) {
	var out FGAStoreInfo
	return &out, s.c.post(ctx, orgPath(orgID, "/fga/stores"), nil, &out)
}

// GetStore returns the FGA store metadata for the org.
func (s *FGAService) GetStore(ctx context.Context, orgID string) (*FGAStoreInfo, error) {
	var out FGAStoreInfo
	return &out, s.c.get(ctx, orgPath(orgID, "/fga/stores"), &out)
}

// ── Model ──────────────────────────────────────────────────────────────────────

// GetModel returns the current authorization model as raw JSON.
func (s *FGAService) GetModel(ctx context.Context, orgID string) (json.RawMessage, error) {
	var out json.RawMessage
	return out, s.c.get(ctx, orgPath(orgID, "/fga/model"), &out)
}

// WriteModel replaces the authorization model. The model is an OpenFGA-style
// JSON document. Returns the new authorization model ID.
func (s *FGAService) WriteModel(ctx context.Context, orgID string, model json.RawMessage) (string, error) {
	var out struct {
		AuthorizationModelID string `json:"authorization_model_id"`
	}
	err := s.c.put(ctx, orgPath(orgID, "/fga/model"), model, &out)
	return out.AuthorizationModelID, err
}

// ── Checks & tuples ─────────────────────────────────────────────────────────────

// Check evaluates whether the tuple's user has the relation on the object.
func (s *FGAService) Check(ctx context.Context, orgID string, t FGATuple) (bool, error) {
	var out struct {
		Allowed bool `json:"allowed"`
	}
	err := s.c.post(ctx, orgPath(orgID, "/fga/check"), t, &out)
	return out.Allowed, err
}

// Write applies tuple writes and deletes in a single transaction.
func (s *FGAService) Write(ctx context.Context, orgID string, writes, deletes []FGATuple) error {
	body := map[string][]FGATuple{"writes": writes, "deletes": deletes}
	return s.c.post(ctx, orgPath(orgID, "/fga/write"), body, nil)
}

// Read returns stored tuples matching the (optional) filter.
func (s *FGAService) Read(ctx context.Context, orgID string, p FGAReadParams) (*FGAReadResult, error) {
	q := url.Values{}
	if p.User != "" {
		q.Set("user", p.User)
	}
	if p.Relation != "" {
		q.Set("relation", p.Relation)
	}
	if p.Object != "" {
		q.Set("object", p.Object)
	}
	if p.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(p.PageSize))
	}
	if p.ContinuationToken != "" {
		q.Set("continuation_token", p.ContinuationToken)
	}
	path := orgPath(orgID, "/fga/read")
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out FGAReadResult
	return &out, s.c.get(ctx, path, &out)
}

// ── Templates ────────────────────────────────────────────────────────────────--

// FGATemplate is a reusable authorization-model template.
type FGATemplate struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	UseCases    []string        `json:"use_cases,omitempty"`
	Model       json.RawMessage `json:"model,omitempty"`
}

// ListTemplates returns the available model templates.
func (s *FGAService) ListTemplates(ctx context.Context, orgID string) ([]FGATemplate, error) {
	var out struct {
		Templates []FGATemplate `json:"templates"`
	}
	err := s.c.get(ctx, orgPath(orgID, "/fga/templates"), &out)
	return out.Templates, err
}

// GetTemplate returns a single model template.
func (s *FGAService) GetTemplate(ctx context.Context, orgID, templateID string) (*FGATemplate, error) {
	var out FGATemplate
	return &out, s.c.get(ctx, orgPath(orgID, "/fga/templates/"+templateID), &out)
}

// ImportTemplate applies a template's model to the org's store. Returns the new
// authorization model ID.
func (s *FGAService) ImportTemplate(ctx context.Context, orgID, templateID string) (string, error) {
	var out struct {
		ModelID string `json:"model_id"`
	}
	err := s.c.post(ctx, orgPath(orgID, "/fga/templates/"+templateID+"/import"), nil, &out)
	return out.ModelID, err
}
