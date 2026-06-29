package clavex

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
)

// MockServer is a test helper that simulates a Clavex management API.
// Use it in unit tests to avoid network calls to a real Clavex instance.
//
// # Quick start
//
//	ms := clavex.NewMockServer()
//	defer ms.Close()
//
//	// Register a canned response.
//	ms.Respond("GET", "/api/v1/organizations/org-1/users", 200, []clavex.User{
//	    {ID: "usr-1", Email: "alice@example.com"},
//	})
//
//	client, _ := clavex.New(ms.URL(), clavex.WithToken("test-token"))
//	users, _ := client.Users.List(ctx, "org-1")
//	fmt.Println(users[0].Email) // "alice@example.com"
//
//	// Verify calls.
//	calls := ms.Calls()
//	assert.Equal(t, 1, len(calls))
//	assert.Equal(t, "GET", calls[0].Method)
type MockServer struct {
	server *httptest.Server
	mux    *http.ServeMux

	mu    sync.Mutex
	calls []MockCall
}

// MockCall records a single HTTP request received by the MockServer.
type MockCall struct {
	Method string
	Path   string
	// Body is the raw request body (may be empty for GET/DELETE).
	Body []byte
}

// NewMockServer creates and starts a local HTTP test server.
// Call Close() when done.
func NewMockServer() *MockServer {
	ms := &MockServer{mux: http.NewServeMux()}
	ms.server = httptest.NewServer(ms)
	return ms
}

// ServeHTTP records the call and dispatches to registered handlers.
func (ms *MockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ms.mu.Lock()
	ms.calls = append(ms.calls, MockCall{
		Method: r.Method,
		Path:   r.URL.Path,
		Body:   body,
	})
	ms.mu.Unlock()
	ms.mux.ServeHTTP(w, r)
}

// HandleFunc registers a handler for the given method and path pattern.
// Pass an empty method string to match any method.
//
//	ms.HandleFunc("POST", "/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
//	    json.NewEncoder(w).Encode(clavex.LoginResponse{Token: "test", ExpiresIn: 3600})
//	})
func (ms *MockServer) HandleFunc(method, pattern string, fn func(http.ResponseWriter, *http.Request)) {
	ms.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if method != "" && r.Method != method {
			http.Error(w, fmt.Sprintf("expected %s, got %s", method, r.Method), http.StatusMethodNotAllowed)
			return
		}
		fn(w, r)
	})
}

// Respond registers a fixed JSON response for the given method and URL path.
// body may be any JSON-serialisable value or nil for empty bodies.
//
//	ms.Respond("GET", "/api/v1/organizations/org-1/users", 200, []clavex.User{...})
//	ms.Respond("DELETE", "/api/v1/organizations/org-1/users/usr-1", 204, nil)
func (ms *MockServer) Respond(method, path string, statusCode int, body any) {
	ms.HandleFunc(method, path, func(w http.ResponseWriter, r *http.Request) {
		if body != nil {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	})
}

// RespondError registers a JSON error response (mirrors the Clavex APIError format).
//
//	ms.RespondError("DELETE", "/api/v1/organizations/missing", 404, "organization not found")
func (ms *MockServer) RespondError(method, path string, statusCode int, message string) {
	ms.Respond(method, path, statusCode, map[string]string{"error": message})
}

// URL returns the base URL of the mock server (e.g. "http://127.0.0.1:PORT").
func (ms *MockServer) URL() string { return ms.server.URL }

// Close shuts down the mock server.
func (ms *MockServer) Close() { ms.server.Close() }

// Calls returns a snapshot of all HTTP requests received so far.
func (ms *MockServer) Calls() []MockCall {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := make([]MockCall, len(ms.calls))
	copy(out, ms.calls)
	return out
}

// CallsFor returns all recorded calls matching the given method and path.
func (ms *MockServer) CallsFor(method, path string) []MockCall {
	all := ms.Calls()
	var out []MockCall
	for _, c := range all {
		if c.Method == method && c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

// Reset clears the recorded call history. Does not affect registered handlers.
func (ms *MockServer) Reset() {
	ms.mu.Lock()
	ms.calls = nil
	ms.mu.Unlock()
}
