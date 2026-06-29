package clavex

import (
	"context"
	"fmt"
)

// UserService manages users within an organisation.
type UserService struct{ c *Client }

// CreateUserParams defines the fields for creating a user.
type CreateUserParams struct {
	Email      string            `json:"email"`
	Username   string            `json:"username,omitempty"`
	FirstName  string            `json:"first_name,omitempty"`
	LastName   string            `json:"last_name,omitempty"`
	Password   string            `json:"password,omitempty"`
	IsActive   *bool             `json:"is_active,omitempty"`
	RoleIDs    []string          `json:"role_ids,omitempty"`
	GroupIDs   []string          `json:"group_ids,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// UpdateUserParams are the mutable fields of a user.
type UpdateUserParams struct {
	Email      *string           `json:"email,omitempty"`
	Username   *string           `json:"username,omitempty"`
	FirstName  *string           `json:"first_name,omitempty"`
	LastName   *string           `json:"last_name,omitempty"`
	IsActive   *bool             `json:"is_active,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Create creates a new user inside orgID.
func (s *UserService) Create(ctx context.Context, orgID string, p CreateUserParams) (*User, error) {
	var out User
	return &out, s.c.post(ctx, orgPath(orgID, "/users"), p, &out)
}

// List returns every user in orgID.
func (s *UserService) List(ctx context.Context, orgID string) ([]User, error) {
	var out []User
	return out, s.c.get(ctx, orgPath(orgID, "/users"), &out)
}

// Get retrieves a single user.
func (s *UserService) Get(ctx context.Context, orgID, userID string) (*User, error) {
	var out User
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/users/%s", userID)), &out)
}

// Update modifies a user.
func (s *UserService) Update(ctx context.Context, orgID, userID string, p UpdateUserParams) (*User, error) {
	var out User
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/users/%s", userID)), p, &out)
}

// Delete permanently removes a user.
func (s *UserService) Delete(ctx context.Context, orgID, userID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/users/%s", userID)))
}

// SendPasswordReset sends a password-reset email to the user.
func (s *UserService) SendPasswordReset(ctx context.Context, orgID, userID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/password-reset", userID)), nil, nil)
}

// SetRequiredActions overwrites the list of actions the user must complete on
// next login (e.g. "VERIFY_EMAIL", "UPDATE_PASSWORD").
func (s *UserService) SetRequiredActions(ctx context.Context, orgID, userID string, actions []string) error {
	body := map[string][]string{"required_actions": actions}
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/required-actions", userID)), body, nil)
}

// PatchAttributes merges custom attributes into the user record.
func (s *UserService) PatchAttributes(ctx context.Context, orgID, userID string, attrs map[string]string) error {
	body := map[string]map[string]string{"attributes": attrs}
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/attributes", userID)), body, nil)
}

// Impersonate creates a short-lived session for the user and returns a JWT
// that can be used on behalf of that user.
func (s *UserService) Impersonate(ctx context.Context, orgID, userID string) (*LoginResponse, error) {
	var out LoginResponse
	return &out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/impersonate", userID)), nil, &out)
}

// ImportUsersParams carries the import request body.
type ImportUsersParams struct {
	// Users is the list of user records to import.
	Users []CreateUserParams `json:"users"`
	// SkipExisting silently ignores users whose email already exists.
	SkipExisting bool `json:"skip_existing,omitempty"`
}

// ImportUsers bulk-imports users into orgID.
func (s *UserService) ImportUsers(ctx context.Context, orgID string, p ImportUsersParams) error {
	return s.c.post(ctx, orgPath(orgID, "/users/import"), p, nil)
}

// ListSessions returns all active sessions for a user.
func (s *UserService) ListSessions(ctx context.Context, orgID, userID string) ([]ActiveSession, error) {
	var out []ActiveSession
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/sessions", userID)), &out)
}

// RevokeAllSessions terminates every active session for a user.
func (s *UserService) RevokeAllSessions(ctx context.Context, orgID, userID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/users/%s/sessions", userID)))
}
