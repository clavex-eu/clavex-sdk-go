package clavex

import (
	"context"
	"fmt"
	"time"
)

// SSFService manages Shared Signals Framework (RFC 8935 / RFC 8936) streams.
//
// SSF lets your app receive real-time security events (session revocation,
// account compromise, credential changes) from Clavex via push or poll.
//
//	// Register a push stream
//	stream, err := client.SSF.Create(ctx, orgID, clavex.CreateSSFStreamParams{
//	    EventTypes:     []string{"session_revoked", "credential_changed"},
//	    DeliveryMethod: "https://schemas.openid.net/secevent/risc/delivery-method/push",
//	    EndpointURL:    "https://app.example.com/ssf/events",
//	})
type SSFService struct{ c *Client }

// CreateSSFStreamParams defines the fields for a new SSF stream.
type CreateSSFStreamParams struct {
	// EventTypes is the list of SET event URIs to subscribe to.
	// Example: "https://schemas.openid.net/secevent/risc/event-type/session-revoked"
	EventTypes []string `json:"event_types"`
	// DeliveryMethod is the RISC delivery method URI.
	// "push": https://schemas.openid.net/secevent/risc/delivery-method/push
	// "poll": https://schemas.openid.net/secevent/risc/delivery-method/poll
	DeliveryMethod string `json:"delivery_method"`
	// EndpointURL is the push receiver URL (required for push delivery).
	EndpointURL string `json:"endpoint_url,omitempty"`
	// Description is a human-readable label.
	Description string `json:"description,omitempty"`
}

// UpdateSSFStreamParams holds the mutable fields of an SSF stream.
type UpdateSSFStreamParams struct {
	EventTypes  []string `json:"event_types,omitempty"`
	EndpointURL *string  `json:"endpoint_url,omitempty"`
	Status      *string  `json:"status,omitempty"` // "enabled" | "paused" | "disabled"
	Description *string  `json:"description,omitempty"`
}

// Create registers a new SSF stream for orgID.
func (s *SSFService) Create(ctx context.Context, orgID string, p CreateSSFStreamParams) (*SSFStream, error) {
	var out SSFStream
	return &out, s.c.post(ctx, orgPath(orgID, "/ssf/streams"), p, &out)
}

// List returns all SSF streams for orgID.
func (s *SSFService) List(ctx context.Context, orgID string) ([]SSFStream, error) {
	var out []SSFStream
	return out, s.c.get(ctx, orgPath(orgID, "/ssf/streams"), &out)
}

// Get retrieves a single SSF stream.
func (s *SSFService) Get(ctx context.Context, orgID, streamID string) (*SSFStream, error) {
	var out SSFStream
	return &out, s.c.get(ctx, orgPath(orgID, fmt.Sprintf("/ssf/streams/%s", streamID)), &out)
}

// Update modifies an SSF stream (e.g. to pause or update event types).
func (s *SSFService) Update(ctx context.Context, orgID, streamID string, p UpdateSSFStreamParams) (*SSFStream, error) {
	var out SSFStream
	return &out, s.c.patch(ctx, orgPath(orgID, fmt.Sprintf("/ssf/streams/%s", streamID)), p, &out)
}

// Delete removes an SSF stream.
func (s *SSFService) Delete(ctx context.Context, orgID, streamID string) error {
	return s.c.delete(ctx, orgPath(orgID, fmt.Sprintf("/ssf/streams/%s", streamID)))
}

// Poll fetches pending SETs (Security Event Tokens) from a poll-delivery stream.
// Returns the raw SETs as compact JWTs. Call Acknowledge once processed.
//
//	sets, err := client.SSF.Poll(ctx, orgID, streamID, 100)
//	jtis := make([]string, len(sets))
//	for i, set := range sets { jtis[i] = set.JTI }
//	_ = client.SSF.Acknowledge(ctx, orgID, streamID, jtis)
func (s *SSFService) Poll(ctx context.Context, orgID, streamID string, maxEvents int) ([]SSFPendingEvent, error) {
	body := map[string]int{"max_events": maxEvents}
	var out []SSFPendingEvent
	return out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/ssf/streams/%s/poll", streamID)), body, &out)
}

// Acknowledge removes the given JTIs from the poll queue.
func (s *SSFService) Acknowledge(ctx context.Context, orgID, streamID string, jtis []string) error {
	body := map[string][]string{"jtis": jtis}
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/ssf/streams/%s/ack", streamID)), body, nil)
}

// Verify fires a test SET to verify push endpoint connectivity.
func (s *SSFService) Verify(ctx context.Context, orgID, streamID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/ssf/streams/%s/verify", streamID)), nil, nil)
}

// SSFStream represents a registered Shared Signals stream.
type SSFStream struct {
	ID             string     `json:"id"`
	OrgID          string     `json:"org_id"`
	Description    string     `json:"description,omitempty"`
	Status         string     `json:"status"` // "enabled" | "paused" | "disabled"
	DeliveryMethod string     `json:"delivery_method"`
	EndpointURL    *string    `json:"endpoint_url,omitempty"`
	EventTypes     []string   `json:"event_types"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastDeliveredAt *time.Time `json:"last_delivered_at,omitempty"`
}

// SSFPendingEvent is a SET waiting to be consumed from a poll stream.
type SSFPendingEvent struct {
	// JTI is the JWT ID — use it to acknowledge the event after processing.
	JTI       string    `json:"jti"`
	EventType string    `json:"event_type"`
	// Payload is the compact JWS of the Security Event Token.
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
