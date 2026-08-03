package clavex

import (
	"context"
	"fmt"
	"time"
)

// ── Device CA (mTLS device identity for IoT/machine fleets) ───────────────────

// DevicePKIService manages the Device CA: a Vault PKI-backed certificate
// authority that issues short-lived mTLS client certificates for non-human
// (device/machine) identities, distinct from the SSH CA above. Enrollment and
// renewal are device-facing operations (authenticated by a bootstrap secret
// or the device's current certificate, respectively) and are not exposed
// here — this service covers only the admin-facing lifecycle: CA
// configuration, per-device enrollment secrets, and revocation.
type DevicePKIService struct{ c *Client }

// DeviceCAParams configures the Device CA (HashiCorp Vault PKI-backed).
type DeviceCAParams struct {
	VaultAddr                 string `json:"vault_addr"`
	VaultToken                string `json:"vault_token"`
	VaultMount                string `json:"vault_mount,omitempty"`
	VaultRole                 string `json:"vault_role"`
	CertTTLSeconds            int    `json:"cert_ttl_seconds,omitempty"`
	RenewalWindowSeconds      int    `json:"renewal_window_seconds,omitempty"`
	BootstrapSecretTTLSeconds int    `json:"bootstrap_secret_ttl_seconds,omitempty"`
}

// DeviceCAConfig is the Device CA configuration (never includes the Vault token).
type DeviceCAConfig struct {
	OrgID                     string    `json:"org_id"`
	VaultAddr                 string    `json:"vault_addr"`
	VaultMount                string    `json:"vault_mount"`
	VaultRole                 string    `json:"vault_role"`
	CACertificatePEM          *string   `json:"ca_certificate_pem,omitempty"`
	CertTTLSeconds            int       `json:"cert_ttl_seconds"`
	RenewalWindowSeconds      int       `json:"renewal_window_seconds"`
	BootstrapSecretTTLSeconds int       `json:"bootstrap_secret_ttl_seconds"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// GetDeviceCA returns the Device CA configuration.
func (s *DevicePKIService) GetDeviceCA(ctx context.Context, orgID string) (*DeviceCAConfig, error) {
	var out DeviceCAConfig
	return &out, s.c.get(ctx, orgPath(orgID, "/devices/ca"), &out)
}

// UpsertDeviceCA creates or replaces the Device CA configuration. On first
// save this provisions the Vault PKI mount, root CA, and device signing role.
func (s *DevicePKIService) UpsertDeviceCA(ctx context.Context, orgID string, p DeviceCAParams) error {
	return s.c.put(ctx, orgPath(orgID, "/devices/ca"), p, nil)
}

// DeleteDeviceCA removes the Device CA configuration.
func (s *DevicePKIService) DeleteDeviceCA(ctx context.Context, orgID string) error {
	return s.c.delete(ctx, orgPath(orgID, "/devices/ca"))
}

// EnrollmentSecretResult carries the one-time plaintext bootstrap secret for
// a device's first enrollment. It is shown only once — store it securely and
// inject it into the device during physical provisioning.
type EnrollmentSecretResult struct {
	EnrollmentSecretID string    `json:"enrollment_secret_id"`
	DeviceID           string    `json:"device_id"`
	BootstrapSecret    string    `json:"bootstrap_secret"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// CreateEnrollmentSecret pre-registers a device and issues a fresh one-time
// bootstrap secret for it. deviceID is the external device identifier from
// your provisioning process (not a Clavex-assigned UUID); fleetID is optional.
func (s *DevicePKIService) CreateEnrollmentSecret(ctx context.Context, orgID, deviceID, fleetID string) (*EnrollmentSecretResult, error) {
	body := map[string]interface{}{}
	if fleetID != "" {
		body["fleet_id"] = fleetID
	}
	var out EnrollmentSecretResult
	return &out, s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/devices/%s/enrollment-secrets", deviceID)), body, &out)
}

// RevokeEnrollmentSecret revokes an unused (still-pending) bootstrap secret —
// e.g. an operator fat-fingered the provisioning run. Has no effect on an
// already-issued certificate; use RevokeCertificate or RevokeDevice for that.
func (s *DevicePKIService) RevokeEnrollmentSecret(ctx context.Context, orgID, secretID string) error {
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/devices/enrollment-secrets/%s/revoke", secretID)), nil, nil)
}

// RevokeCertificate revokes a single issued device certificate by its serial
// number, independent of CA rotation — the immediate response for a
// compromised device, since waiting for natural certificate expiry is not
// acceptable for stolen field hardware.
func (s *DevicePKIService) RevokeCertificate(ctx context.Context, orgID, deviceID, serial, reason string) error {
	body := map[string]interface{}{}
	if reason != "" {
		body["reason"] = reason
	}
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/devices/%s/certificates/%s/revoke", deviceID, serial)), body, nil)
}

// RevokeDevice revokes every currently-active certificate for a device and
// flags the device itself revoked — the "whole device stolen" path.
func (s *DevicePKIService) RevokeDevice(ctx context.Context, orgID, deviceID, reason string) error {
	body := map[string]interface{}{}
	if reason != "" {
		body["reason"] = reason
	}
	return s.c.post(ctx, orgPath(orgID, fmt.Sprintf("/devices/%s/revoke", deviceID)), body, nil)
}
