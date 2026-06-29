package clavex

import (
	"context"
	"fmt"
)

// RoleService manages roles and role assignments within an organisation.
type RoleService struct{ c *Client }

// CreateRoleParams defines the fields for creating a role.
type CreateRoleParams struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Create creates a new role in orgID.
func (s *RoleService) Create(ctx context.Context, orgID string, p CreateRoleParams) (*Role, error) {
	var out Role
	return &out, s.c.post(ctx, orgPath(orgID, "/roles"), p, &out)
}

// List returns all roles in orgID.
func (s *RoleService) List(ctx context.Context, orgID string) ([]Role, error) {
	var out []Role
	return out, s.c.get(ctx, orgPath(orgID, "/roles"), &out)
}

// Delete removes a role.
func (s *RoleService) Delete(ctx context.Context, orgID, roleID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/roles/%s", roleID)))
}

// AssignToUser grants roleID to userID.
func (s *RoleService) AssignToUser(ctx context.Context, orgID, roleID, userID string) error {
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/roles/%s/users/%s", roleID, userID)), nil, nil)
}

// UnassignFromUser revokes roleID from userID.
func (s *RoleService) UnassignFromUser(ctx context.Context, orgID, roleID, userID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/roles/%s/users/%s", roleID, userID)))
}

// ListChildren returns the child roles of roleID.
func (s *RoleService) ListChildren(ctx context.Context, orgID, roleID string) ([]Role, error) {
	var out []Role
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/roles/%s/children", roleID)), &out)
}

// AddChild makes childID a child of roleID (composite role).
func (s *RoleService) AddChild(ctx context.Context, orgID, roleID, childID string) error {
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/roles/%s/children/%s", roleID, childID)), nil, nil)
}

// RemoveChild removes childID from the children of roleID.
func (s *RoleService) RemoveChild(ctx context.Context, orgID, roleID, childID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/roles/%s/children/%s", roleID, childID)))
}

// GroupService manages groups within an organisation.
type GroupService struct{ c *Client }

// CreateGroupParams defines the fields for creating a group.
type CreateGroupParams struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Create creates a new group in orgID.
func (s *GroupService) Create(ctx context.Context, orgID string, p CreateGroupParams) (*Group, error) {
	var out Group
	return &out, s.c.post(ctx, orgPath(orgID, "/groups"), p, &out)
}

// List returns all groups in orgID.
func (s *GroupService) List(ctx context.Context, orgID string) ([]Group, error) {
	var out []Group
	return out, s.c.get(ctx, orgPath(orgID, "/groups"), &out)
}

// Get retrieves a single group.
func (s *GroupService) Get(ctx context.Context, orgID, groupID string) (*Group, error) {
	var out Group
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s", groupID)), &out)
}

// Delete removes a group.
func (s *GroupService) Delete(ctx context.Context, orgID, groupID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s", groupID)))
}

// ListMembers returns all users in a group.
func (s *GroupService) ListMembers(ctx context.Context, orgID, groupID string) ([]User, error) {
	var out []User
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s/members", groupID)), &out)
}

// AddMember adds a user to a group.
func (s *GroupService) AddMember(ctx context.Context, orgID, groupID, userID string) error {
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s/members/%s", groupID, userID)), nil, nil)
}

// RemoveMember removes a user from a group.
func (s *GroupService) RemoveMember(ctx context.Context, orgID, groupID, userID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s/members/%s", groupID, userID)))
}

// ListRoles returns all roles assigned to a group.
func (s *GroupService) ListRoles(ctx context.Context, orgID, groupID string) ([]Role, error) {
	var out []Role
	return out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s/roles", groupID)), &out)
}

// AssignRole assigns a role to a group.
func (s *GroupService) AssignRole(ctx context.Context, orgID, groupID, roleID string) error {
	return s.c.put(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s/roles/%s", groupID, roleID)), nil, nil)
}

// RemoveRole unassigns a role from a group.
func (s *GroupService) RemoveRole(ctx context.Context, orgID, groupID, roleID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/groups/%s/roles/%s", groupID, roleID)))
}
