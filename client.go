package clavex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── Options ───────────────────────────────────────────────────────────────────

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.hc = hc }
}

// WithCredentials configures automatic login (fetches + refreshes the JWT).
func WithCredentials(orgSlug, email, password string) Option {
	return func(c *Client) {
		c.orgSlug = orgSlug
		c.email = email
		c.password = password
		c.autoAuth = true
	}
}

// WithToken sets a pre-acquired admin JWT. The caller is responsible for
// renewal before the token expires.
func WithToken(token string) Option {
	return func(c *Client) {
		c.mu.Lock()
		c.token = token
		c.mu.Unlock()
	}
}

// WithAPIKey configures the client to authenticate via the X-API-Key header
// instead of a JWT bearer token. Use this for machine-to-machine callers
// holding an admin API key (see APIKeyService / clavex_api_key) — including
// org-scoped keys (org_id set at creation), which is the credential model
// used by the Clavex Kubernetes Operator's per-CR authSecretRef.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.mu.Lock()
		c.apiKey = key
		c.mu.Unlock()
	}
}

// ── Client ────────────────────────────────────────────────────────────────────

// Client is the root of the Clavex management SDK.
// All services are accessible as fields on this struct.
type Client struct {
	base string
	hc   *http.Client

	// resilience
	retry RetryPolicy
	cb    *circuitBreaker

	// auth state
	mu       sync.RWMutex
	token    string
	tokenExp time.Time
	autoAuth bool
	apiKey   string
	orgSlug  string
	email    string
	password string

	// Services — core
	Auth              *AuthService
	Organizations     *OrgService
	Users             *UserService
	Roles             *RoleService
	Groups            *GroupService
	Clients           *ClientService
	ClientScopes      *ClientScopeService
	ProtocolMappers   *ProtocolMapperService
	IdentityProviders *IDPService
	Sessions          *SessionService
	LDAP              *LDAPService
	MFA               *MFAService
	AuditLog          *AuditService
	Branding          *BrandingService
	PasswordPolicy    *PasswordPolicyService
	SMTP              *SMTPService
	CAPTCHA           *CaptchaService
	Webhooks          *WebhookService
	Invitations       *InvitationService
	SCIM              *SCIMService

	// Services — extended
	Policies      *PolicyService
	Usage         *UsageService
	LoginHistory  *LoginHistoryService
	RateLimits    *RateLimitService
	SSF           *SSFService
	AuthZen       *AuthZenService
	DeviceTrust   *DeviceTrustService
	CrossOrgTrust *CrossOrgTrustService
	APIKeys       *APIKeyService
	CIBA          *CIBAService

	// Services — EUDI wallet
	OID4VCI    *OID4VCIService
	OID4VP     *OID4VPService
	Mdoc       *MdocService
	Federation *FederationService

	// Services — authorization & privileged access
	FGA *FGAService
	PAM *PAMService

	// Services — governance & lifecycle
	ServiceAccounts *ServiceAccountService
	LoginFlows      *LoginFlowService
	LifecycleRules  *LifecycleRuleService
	ScimPush        *ScimPushService
	SamlSPs         *SamlSpService
	WsfedRPs        *WsfedRpService
	AppFamilies     *AppFamilyService
	AgentTokens     *AgentTokenService
	AccessReviews   *AccessReviewService
	EntityReviews   *EntityReviewService
	Compliance      *ComplianceService
	GDPR            *GdprService
	Actions         *ActionsService
	AI              *AIService
	Elevate         *ElevateService
}

// New creates a Clavex management client.
//
//	client, err := clavex.New("https://auth.example.com",
//	    clavex.WithCredentials("acme", "admin@acme.com", "s3cr3t"),
//	)
func New(baseURL string, opts ...Option) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	c := &Client{
		base: baseURL,
		hc:   &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}

	// Wire up all services.
	c.Auth = &AuthService{c: c}
	c.Organizations = &OrgService{c: c}
	c.Users = &UserService{c: c}
	c.Roles = &RoleService{c: c}
	c.Groups = &GroupService{c: c}
	c.Clients = &ClientService{c: c}
	c.ClientScopes = &ClientScopeService{c: c}
	c.ProtocolMappers = &ProtocolMapperService{c: c}
	c.IdentityProviders = &IDPService{c: c}
	c.Sessions = &SessionService{c: c}
	c.LDAP = &LDAPService{c: c}
	c.MFA = &MFAService{c: c}
	c.AuditLog = &AuditService{c: c}
	c.Branding = &BrandingService{c: c}
	c.PasswordPolicy = &PasswordPolicyService{c: c}
	c.SMTP = &SMTPService{c: c}
	c.CAPTCHA = &CaptchaService{c: c}
	c.Webhooks = &WebhookService{c: c}
	c.Invitations = &InvitationService{c: c}
	c.SCIM = &SCIMService{c: c}

	// extended services
	c.Policies = &PolicyService{c: c}
	c.Usage = &UsageService{c: c}
	c.LoginHistory = &LoginHistoryService{c: c}
	c.RateLimits = &RateLimitService{c: c}
	c.SSF = &SSFService{c: c}
	c.AuthZen = &AuthZenService{c: c}
	c.DeviceTrust = &DeviceTrustService{c: c}
	c.CrossOrgTrust = &CrossOrgTrustService{c: c}
	c.APIKeys = &APIKeyService{c: c}
	c.CIBA = &CIBAService{c: c}

	// EUDI wallet services
	c.OID4VCI = &OID4VCIService{c: c}
	c.OID4VP = &OID4VPService{c: c}
	c.Mdoc = &MdocService{c: c}
	c.Federation = &FederationService{c: c}

	// authorization & privileged access
	c.FGA = &FGAService{c: c}
	c.PAM = &PAMService{c: c}

	// governance & lifecycle
	c.ServiceAccounts = &ServiceAccountService{c: c}
	c.LoginFlows = &LoginFlowService{c: c}
	c.LifecycleRules = &LifecycleRuleService{c: c}
	c.ScimPush = &ScimPushService{c: c}
	c.SamlSPs = &SamlSpService{c: c}
	c.WsfedRPs = &WsfedRpService{c: c}
	c.AppFamilies = &AppFamilyService{c: c}
	c.AgentTokens = &AgentTokenService{c: c}
	c.AccessReviews = &AccessReviewService{c: c}
	c.EntityReviews = &EntityReviewService{c: c}
	c.Compliance = &ComplianceService{c: c}
	c.GDPR = &GdprService{c: c}
	c.Actions = &ActionsService{c: c}
	c.AI = &AIService{c: c}
	c.Elevate = &ElevateService{c: c}

	// default retry policy (1 attempt = no retry; override with WithRetry)
	if c.retry.MaxAttempts == 0 {
		c.retry.MaxAttempts = 1
	}

	// Eagerly authenticate if credentials are provided so callers get an error
	// immediately rather than on the first API call.
	if c.autoAuth {
		if err := c.refreshToken(context.Background()); err != nil {
			return nil, fmt.Errorf("initial authentication failed: %w", err)
		}
	}
	return c, nil
}

// ── Token management ──────────────────────────────────────────────────────────

func (c *Client) refreshToken(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{
		"org_slug": c.orgSlug,
		"email":    c.email,
		"password": c.password,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Body: string(b)}
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}
	c.mu.Lock()
	c.token = result.Token
	c.tokenExp = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	c.mu.Unlock()
	return nil
}

// bearerToken returns a valid token, refreshing if needed.
func (c *Client) bearerToken(ctx context.Context) (string, error) {
	c.mu.RLock()
	t, exp := c.token, c.tokenExp
	c.mu.RUnlock()

	if t == "" {
		return "", fmt.Errorf("no authentication token: call WithCredentials or WithToken")
	}
	// Refresh if within 60 s of expiry (or already expired).
	if c.autoAuth && !exp.IsZero() && time.Until(exp) < 60*time.Second {
		if err := c.refreshToken(ctx); err != nil {
			return "", err
		}
		c.mu.RLock()
		t = c.token
		c.mu.RUnlock()
	}
	return t, nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	// Serialize body once so it can be replayed across retries.
	var rawBody []byte
	if body != nil {
		var err error
		rawBody, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
	}

	var lastErr error
	for attempt := 0; attempt < c.retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			if err := c.retry.sleep(ctx, attempt-1); err != nil {
				return err
			}
		}

		// Circuit breaker check.
		if c.cb != nil && !c.cb.allow() {
			return ErrCircuitOpen{}
		}

		var token string
		if c.apiKey == "" {
			var err error
			token, err = c.bearerToken(ctx)
			if err != nil {
				return err
			}
		}

		var bodyReader io.Reader
		if rawBody != nil {
			bodyReader = bytes.NewReader(rawBody)
		}

		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bodyReader)
		if err != nil {
			return err
		}
		if c.apiKey != "" {
			req.Header.Set("X-API-Key", c.apiKey)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if rawBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.hc.Do(req)
		if err != nil {
			// Network error — counts as failure for circuit breaker.
			if c.cb != nil {
				c.cb.failure()
			}
			lastErr = err
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
			// Only retry on configured status codes.
			if c.retry.MaxAttempts > 1 && c.retry.shouldRetry(resp.StatusCode) {
				if c.cb != nil {
					c.cb.failure()
				}
				lastErr = apiErr
				continue
			}
			// Non-retryable error: record as success for circuit breaker
			// (the server is reachable; the error is the caller's fault).
			if resp.StatusCode < 500 {
				if c.cb != nil {
					c.cb.success()
				}
			} else if c.cb != nil {
				c.cb.failure()
			}
			return apiErr
		}

		if c.cb != nil {
			c.cb.success()
		}
		if out != nil && resp.StatusCode != http.StatusNoContent {
			return json.Unmarshal(respBody, out)
		}
		return nil
	}
	return lastErr
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) patch(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPatch, path, body, out)
}

func (c *Client) put(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPut, path, body, out)
}

func (c *Client) delete(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// orgPath returns the base path for an org-scoped resource.
func orgPath(orgID, suffix string) string {
	return fmt.Sprintf("/api/v1/organizations/%s%s", orgID, suffix)
}

// ── Error type ────────────────────────────────────────────────────────────────

// APIError is returned when the server responds with an HTTP 4xx/5xx status.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("clavex: API error %d: %s", e.StatusCode, e.Body)
}

// IsNotFound returns true if the error is a 404.
func IsNotFound(err error) bool {
	if e, ok := err.(*APIError); ok {
		return e.StatusCode == http.StatusNotFound
	}
	return false
}

// IsConflict returns true if the error is a 409 (resource already exists).
func IsConflict(err error) bool {
	if e, ok := err.(*APIError); ok {
		return e.StatusCode == http.StatusConflict
	}
	return false
}

// IsUnauthorized returns true if the error is a 401.
func IsUnauthorized(err error) bool {
	if e, ok := err.(*APIError); ok {
		return e.StatusCode == http.StatusUnauthorized
	}
	return false
}

// IsRateLimit returns true if the error is a 429 (too many requests).
func IsRateLimit(err error) bool {
	if e, ok := err.(*APIError); ok {
		return e.StatusCode == http.StatusTooManyRequests
	}
	return false
}

// newGetRequest builds an authenticated GET request.
func newGetRequest(ctx context.Context, url, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// readAll reads the full response body into a byte slice.
func readAll(resp *http.Response) ([]byte, error) {
	return io.ReadAll(resp.Body)
}
