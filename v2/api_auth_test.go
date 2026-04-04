package tlsrouter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockAuthenticator implements the authenticator interface for testing
type MockAuthenticator struct {
	ValidUser  string
	ValidPass  string
	Perms      []string
	ShouldFail bool
}

func (m *MockAuthenticator) Authenticate(username, password string) (interface{ Permissions() []string }, error) {
	if m.ShouldFail {
		return nil, ErrNoCredentials
	}
	if username == m.ValidUser && password == m.ValidPass {
		return &MockPrinciple{Perms: m.Perms}, nil
	}
	return nil, ErrNoCredentials
}

type MockPrinciple struct {
	Perms []string
}

func (m *MockPrinciple) Permissions() []string {
	return m.Perms
}

func TestAPIAuthConfig_AuthenticatedHandler_NoAuth(t *testing.T) {
	// No auth configured - should pass through
	auth := &APIAuthConfig{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := auth.AuthenticatedHandler(handler)

	// When no auth is configured, the handler is returned unchanged
	// Test that it still works
	req := httptest.NewRequest("GET", "/api/connections", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestAPIAuthConfig_AuthenticatedHandler_BearerToken(t *testing.T) {
	auth := &APIAuthConfig{
		Authenticator: &MockAuthenticator{
			ValidUser: "",
			ValidPass: "test-token",
			Perms:     []string{"admin"},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := auth.AuthenticatedHandler(handler)

	// Test valid bearer token
	req := httptest.NewRequest("GET", "/api/connections", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}

	// Test invalid token
	req = httptest.NewRequest("GET", "/api/connections", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rec.Code)
	}
}

func TestAPIAuthConfig_AuthenticatedHandler_BasicAuth(t *testing.T) {
	auth := &APIAuthConfig{
		Authenticator: &MockAuthenticator{
			ValidUser: "admin",
			ValidPass: "secret",
			Perms:     []string{"admin"},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := auth.AuthenticatedHandler(handler)

	// Test valid basic auth
	req := httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("admin", "secret")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}

	// Test invalid basic auth
	req = httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("admin", "wrong")
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rec.Code)
	}
}

func TestAPIAuthConfig_AuthenticatedHandler_QueryParam(t *testing.T) {
	auth := &APIAuthConfig{
		Authenticator: &MockAuthenticator{
			ValidUser: "",
			ValidPass: "query-token",
			Perms:     []string{"admin"},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := auth.AuthenticatedHandler(handler)

	// Test valid query param
	req := httptest.NewRequest("GET", "/api/connections?access_token=query-token", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestAPIAuthConfig_AuthenticatedHandler_Permissions(t *testing.T) {
	auth := &APIAuthConfig{
		Authenticator: &MockAuthenticator{
			ValidUser: "user",
			ValidPass: "pass",
			Perms:     []string{"viewer"},
		},
		RequiredPermissions: []string{"admin"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := auth.AuthenticatedHandler(handler)

	// Test user without required permission
	req := httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("user", "pass")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", rec.Code)
	}

	// Test user with required permission
	auth.Authenticator = &MockAuthenticator{
		ValidUser: "admin",
		ValidPass: "secret",
		Perms:     []string{"admin"},
	}
	wrapped = auth.AuthenticatedHandler(handler)

	req = httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("admin", "secret")
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestAPIAuthConfig_AuthenticatedHandler_NoCredentials(t *testing.T) {
	auth := &APIAuthConfig{
		Authenticator: &MockAuthenticator{
			ValidUser: "admin",
			ValidPass: "secret",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := auth.AuthenticatedHandler(handler)

	// Test no credentials provided
	req := httptest.NewRequest("GET", "/api/connections", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rec.Code)
	}
}