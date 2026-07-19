package clavex

import "time"

// ── Core types mirroring the server models ────────────────────────────────────

// Organization represents a Clavex tenant.
type Organization struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	LogoURL     *string           `json:"logo_url,omitempty"`
	Settings    map[string]string `json:"settings,omitempty"`
	IsActive    bool              `json:"is_active"`
	MFARequired bool              `json:"mfa_required"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// User represents a Clavex user account.
type User struct {
	ID              string                 `json:"id"`
	OrgID           string                 `json:"org_id"`
	Email           string                 `json:"email"`
	FirstName       *string                `json:"first_name,omitempty"`
	LastName        *string                `json:"last_name,omitempty"`
	AvatarURL       *string                `json:"avatar_url,omitempty"`
	IsActive        bool                   `json:"is_active"`
	IsEmailVerified bool                   `json:"is_email_verified"`
	MFARequired     bool                   `json:"mfa_required"`
	RequiredActions []string               `json:"required_actions,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	LastLoginAt     *time.Time             `json:"last_login_at,omitempty"`
}

// Role represents a named set of permissions within an org.
type Role struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

// Group represents a collection of users.
type Group struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// OIDCClient is an OIDC application registration.
type OIDCClient struct {
	ClientID               string    `json:"client_id"`
	OrgID                  string    `json:"org_id"`
	Name                   string    `json:"name"`
	RedirectURIs           []string  `json:"redirect_uris"`
	PostLogoutRedirectURIs []string  `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes             []string  `json:"grant_types,omitempty"`
	IsPublic               bool      `json:"is_public"`
	IsActive               bool      `json:"is_active"`
	LogoURL                *string   `json:"logo_url,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// CreateClientResponse is returned when creating a client. The plain-text
// secret is only present here and never exposed again.
type CreateClientResponse struct {
	Client       OIDCClient `json:"client"`
	ClientSecret *string    `json:"client_secret,omitempty"`
}

// ClientScope is a reusable scope definition.
type ClientScope struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	Protocol    string    `json:"protocol"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ProtocolMapper maps a claim from the token store to the issued JWT.
type ProtocolMapper struct {
	ID         string                 `json:"id"`
	ClientID   string                 `json:"client_id"`
	Name       string                 `json:"name"`
	Protocol   string                 `json:"protocol"`
	MapperType string                 `json:"mapper_type"`
	Config     map[string]interface{} `json:"config,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// IdentityProvider is an upstream OIDC/OAuth2 SSO provider.
type IdentityProvider struct {
	ID                string            `json:"id"`
	OrgID             string            `json:"org_id"`
	Name              string            `json:"name"`
	ProviderType      string            `json:"provider_type"`
	ClientID          string            `json:"client_id"`
	AuthorizationURL  string            `json:"authorization_url"`
	TokenURL          string            `json:"token_url"`
	UserinfoURL       *string           `json:"userinfo_url,omitempty"`
	Scopes            string            `json:"scopes"`
	EmailClaim        string            `json:"email_claim"`
	FirstNameClaim    string            `json:"first_name_claim"`
	LastNameClaim     string            `json:"last_name_claim"`
	IsActive          bool              `json:"is_active"`
	AllowJIT          bool              `json:"allow_jit"`
	RolesClaim        *string           `json:"roles_claim,omitempty"`
	RoleClaimMappings map[string]string `json:"role_claim_mappings,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// ActiveSession summarises a live refresh-token session.
type ActiveSession struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	ClientID   string     `json:"client_id"`
	UserID     *string    `json:"user_id,omitempty"`
	Scope      string     `json:"scope"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	IPAddress  *string    `json:"ip_address,omitempty"`
	DeviceName *string    `json:"device_name,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

// MFACredential holds a TOTP or WebAuthn credential for a user.
type MFACredential struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Type      string    `json:"type"` // "totp" | "webauthn"
	Name      string    `json:"name"`
	IsPrimary bool      `json:"is_primary"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditLogEntry is a single immutable audit event.
type AuditLogEntry struct {
	ID         string                 `json:"id"`
	OrgID      string                 `json:"org_id"`
	ActorID    *string                `json:"actor_id,omitempty"`
	ActorEmail *string                `json:"actor_email,omitempty"`
	Action     string                 `json:"action"`
	ResourceID *string                `json:"resource_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	IPAddress  *string                `json:"ip_address,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

// Branding holds org-level login-page customisation.
type Branding struct {
	OrgID           string  `json:"org_id"`
	PrimaryColor    *string `json:"primary_color,omitempty"`
	BackgroundColor *string `json:"background_color,omitempty"`
	LogoURL         *string `json:"logo_url,omitempty"`
	FaviconURL      *string `json:"favicon_url,omitempty"`
	CustomCSS       *string `json:"custom_css,omitempty"`
}

// PasswordPolicy defines complexity rules for an org.
type PasswordPolicy struct {
	OrgID          string `json:"org_id"`
	MinLength      int    `json:"min_length"`
	RequireUpper   bool   `json:"require_upper"`
	RequireLower   bool   `json:"require_lower"`
	RequireNumber  bool   `json:"require_number"`
	RequireSpecial bool   `json:"require_special"`
	MaxAgeDays     int    `json:"max_age_days"`
	HistoryCount   int    `json:"history_count"`
	// Declarative-management marker (server migration 000179). Nil when the
	// section is hand-managed. Read-only from the SDK's perspective — set it
	// via WithManagedBy on the request context, not on the payload.
	ManagedBy  *string `json:"managed_by,omitempty"`
	ManagedRef *string `json:"managed_ref,omitempty"`
}

// SMTPConfig holds outbound mail settings for an org.
type SMTPConfig struct {
	OrgID    string `json:"org_id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	UseTLS   bool   `json:"use_tls"`
	FromName string `json:"from_name"`
	FromAddr string `json:"from_addr"`
}

// CaptchaSettings holds bot-detection settings for an org.
type CaptchaSettings struct {
	OrgID    string `json:"org_id"`
	Provider string `json:"provider"` // "turnstile"|"hcaptcha"|"recaptcha"
	SiteKey  string `json:"site_key"`
	IsActive bool   `json:"is_active"`
}

// Webhook is an outbound HTTP subscription.
type Webhook struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Invitation is a pending email invite to join an org.
type Invitation struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email"`
	RoleIDs   []string  `json:"role_ids,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// LDAPConnection holds the configuration for an LDAP directory sync.
type LDAPConnection struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Name       string     `json:"name"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	UseTLS     bool       `json:"use_tls"`
	BindDN     *string    `json:"bind_dn,omitempty"`
	BaseDN     string     `json:"base_dn"`
	UserFilter string     `json:"user_filter"`
	IsActive   bool       `json:"is_active"`
	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// SCIMToken is a bearer credential that authorises inbound SCIM provisioning.
type SCIMToken struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginResponse is returned by AuthService.Login.
type LoginResponse struct {
	Token        string `json:"token"`
	ExpiresIn    int    `json:"expires_in"`
	OrgID        string `json:"org_id"`
	OrgSlug      string `json:"org_slug"`
	IsSuperAdmin bool   `json:"is_super_admin"`
}

// ── Policy types ──────────────────────────────────────────────────────────────

// PolicyConditions holds the optional match criteria for a policy rule.
// A nil/zero-value field means "no constraint on this signal".
type PolicyConditions struct {
	// IPCIDRs is an IP CIDR allowlist. Matches if the request IP is in any range.
	IPCIDRs []string `json:"ip_cidr,omitempty"`
	// Countries is an ISO 3166-1 alpha-2 allowlist.
	Countries []string `json:"country,omitempty"`
	// NotCountries is an ISO 3166-1 alpha-2 denylist.
	NotCountries []string `json:"country_not,omitempty"`
	// ClientIDs restricts the rule to specific OIDC client_ids.
	ClientIDs []string `json:"client_id,omitempty"`
	// MFAEnrolled matches users who have (true) or have not (false) enrolled MFA.
	MFAEnrolled *bool `json:"mfa_enrolled,omitempty"`
	// NewCountry matches when the request country is not in the 90-day baseline.
	NewCountry *bool `json:"new_country,omitempty"`
	// DaysOfWeek restricts to given UTC days ("Mon", "Tue", ...).
	DaysOfWeek []string `json:"day_of_week,omitempty"`
	// HourRange restricts to a UTC hour window (0–23).
	HourRange *HourRange `json:"hour_range,omitempty"`
	// LastLoginBefore matches when the last login was older than this duration
	// (Go duration string, e.g. "720h"). Absent LastLoginAt counts as infinite.
	LastLoginBefore string `json:"last_login_before,omitempty"`
}

// HourRange is a UTC time window [From, To] (inclusive, 0-23).
type HourRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// PolicyRule is a single named auth-flow policy rule.
type PolicyRule struct {
	ID         string           `json:"id"`
	OrgID      string           `json:"org_id"`
	Name       string           `json:"name"`
	Priority   int              `json:"priority"`
	Action     string           `json:"action"` // "allow"|"deny"|"require_mfa"|"step_up"
	Conditions PolicyConditions `json:"conditions"`
	Enabled    bool             `json:"enabled"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

// PolicyOutcome is the result of evaluating the policy engine.
type PolicyOutcome struct {
	Action    string `json:"action"`
	RuleName  string `json:"rule_name,omitempty"`
	Reason    string `json:"reason,omitempty"`
	MFAForced bool   `json:"mfa_forced,omitempty"`
}

// SimulateTraceItem describes one rule and whether it matched.
type SimulateTraceItem struct {
	RuleName string `json:"rule_name"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
	Matched  bool   `json:"matched"`
	Action   string `json:"action"`
}

// SimulateResult is the response from the policy dry-run endpoint.
type SimulateResult struct {
	Outcome     PolicyOutcome       `json:"outcome"`
	MFARequired bool                `json:"mfa_required"`
	Trace       []SimulateTraceItem `json:"trace"`
	EvaluatedAt time.Time           `json:"evaluated_at"`
}

// ── Usage analytics ───────────────────────────────────────────────────────────

// OrgUsage holds aggregated authentication metrics for a 30-day window.
type OrgUsage struct {
	OrgID          string         `json:"org_id"`
	WindowStart    time.Time      `json:"window_start"`
	WindowEnd      time.Time      `json:"window_end"`
	MAU            int            `json:"mau"`             // Monthly Active Users
	DAU            int            `json:"dau"`             // Daily Active Users (trailing 24h)
	TotalLogins    int            `json:"total_logins"`
	SuccessLogins  int            `json:"success_logins"`
	FailedLogins   int            `json:"failed_logins"`
	NewUsers       int            `json:"new_users"`
	LoginsByMethod map[string]int `json:"logins_by_method"` // e.g. {"password": 450, "google": 120}
	TopClients     []ClientUsage  `json:"top_clients,omitempty"`
}

// ClientUsage is the per-application slice of the usage breakdown.
type ClientUsage struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Logins     int    `json:"logins"`
}

// SecurityPosture is the org-level security health summary.
type SecurityPosture struct {
	OrgID           string                   `json:"org_id"`
	Score           int                      `json:"score"` // 0–100
	MFAAdoptionPct  float64                  `json:"mfa_adoption_pct"`
	UnverifiedEmails int                     `json:"unverified_emails"`
	InactiveUsers   int                      `json:"inactive_users"`
	Recommendations []PostureRecommendation  `json:"recommendations,omitempty"`
}

// PostureRecommendation is a single actionable security improvement.
type PostureRecommendation struct {
	Severity string `json:"severity"` // "critical"|"high"|"medium"|"low"
	Code     string `json:"code"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// ── Login history ─────────────────────────────────────────────────────────────

// LoginHistoryEntry is a single authentication event in the immutable log.
type LoginHistoryEntry struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	UserID     *string    `json:"user_id,omitempty"`
	Email      string     `json:"email,omitempty"`
	ClientID   string     `json:"client_id,omitempty"`
	Method     string     `json:"method"` // "password"|"totp"|"webauthn"|"oidc"|...
	Success    bool       `json:"success"`
	IPAddress  *string    `json:"ip_address,omitempty"`
	Country    *string    `json:"country,omitempty"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	FailReason *string    `json:"fail_reason,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ── Rate limits ───────────────────────────────────────────────────────────────

// RateLimitConfig defines per-org login rate-limit thresholds.
type RateLimitConfig struct {
	OrgID                string `json:"org_id,omitempty"`
	// MaxAttemptsPerMinute is the maximum login attempts per user per minute.
	MaxAttemptsPerMinute int    `json:"max_attempts_per_minute"`
	// LockoutDurationSeconds is how long a user is locked out after exceeding
	// the threshold.
	LockoutDurationSeconds int `json:"lockout_duration_seconds"`
	// IPMaxAttemptsPerMinute limits attempts per source IP (0 = disabled).
	IPMaxAttemptsPerMinute int `json:"ip_max_attempts_per_minute,omitempty"`
	// Declarative-management marker (server migration 000179). Nil when the
	// section is hand-managed. Set it via WithManagedBy on the request context,
	// not on the payload.
	ManagedBy  *string `json:"managed_by,omitempty"`
	ManagedRef *string `json:"managed_ref,omitempty"`
}
