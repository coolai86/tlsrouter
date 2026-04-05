package tlsrouter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/therootcompany/golib/auth"
)

// MockCredential implements auth.BasicPrinciple for testing
type MockCredential struct {
	id    string
	perms []string
}

func (m *MockCredential) ID() string {
	return m.id
}

func (m *MockCredential) Permissions() []string {
	return m.perms
}

// MockAuthenticator implements auth.BasicAuthenticator for testing
type MockAuthenticator struct {
	ValidUser string
	ValidPass string
	Perms     []string
}

func (m *MockAuthenticator) Authenticate(user, pass string) (auth.BasicPrinciple, error) {
	if user == m.ValidUser && pass == m.ValidPass {
		return &MockCredential{id: user, perms: m.Perms}, nil
	}
	return nil, ErrInvalidCredentials
}

// ErrInvalidCredentials is returned when authentication fails
var ErrInvalidCredentials = &AuthError{Message: "invalid credentials"}

// AuthError represents an authentication error
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}

func TestAPIAuthConfig_AuthenticatedHandler_RequiresAuth(t *testing.T) {
	// Auth is REQUIRED - nil config must panic
	t.Run("nil config panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic with nil config")
			}
		}()
		var authConfig *APIAuthConfig
		authConfig.AuthenticatedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	})

	// Nil authenticator must panic
	t.Run("nil authenticator panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic with nil authenticator")
			}
		}()
		authConfig := &APIAuthConfig{}
		authConfig.AuthenticatedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	})
}

func TestAPIAuthConfig_AuthenticatedHandler_BasicAuth(t *testing.T) {
	authConfig := MustAuth(&MockAuthenticator{
		ValidUser: "admin",
		ValidPass: "secret",
		Perms:     []string{"admin"},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := authConfig.AuthenticatedHandler(handler)

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

func TestAPIAuthConfig_AuthenticatedHandler_BearerToken(t *testing.T) {
	authConfig := MustAuth(&MockAuthenticator{
		ValidUser: "", // Bearer tokens authenticate with empty username
		ValidPass: "test-token",
		Perms:     []string{"admin"},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := authConfig.AuthenticatedHandler(handler)

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

func TestAPIAuthConfig_AuthenticatedHandler_QueryParam(t *testing.T) {
	authConfig := MustAuth(&MockAuthenticator{
		ValidUser: "",
		ValidPass: "query-token",
		Perms:     []string{"admin"},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := authConfig.AuthenticatedHandler(handler)

	// Test valid query param token
	req := httptest.NewRequest("GET", "/api/connections?access_token=query-token", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestAPIAuthConfig_AuthenticatedHandler_Permissions(t *testing.T) {
	authConfig := MustAuth(&MockAuthenticator{
		ValidUser: "viewer",
		ValidPass: "pass",
		Perms:     []string{"viewer"},
	}, "admin") // require admin permission

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := authConfig.AuthenticatedHandler(handler)

	// Test user without required permission
	req := httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("viewer", "pass")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", rec.Code)
	}

	// Test user with required permission
	authConfig = MustAuth(&MockAuthenticator{
		ValidUser: "admin",
		ValidPass: "secret",
		Perms:     []string{"admin"},
	}, "admin")

	wrapped = authConfig.AuthenticatedHandler(handler)

	req = httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("admin", "secret")
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestAPIAuthConfig_AuthenticatedHandler_NoCredentials(t *testing.T) {
	authConfig := MustAuth(&MockAuthenticator{
		ValidUser: "admin",
		ValidPass: "secret",
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := authConfig.AuthenticatedHandler(handler)

	// Test no credentials provided
	req := httptest.NewRequest("GET", "/api/connections", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rec.Code)
	}

	// Check WWW-Authenticate header is set
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("Expected WWW-Authenticate header to be set")
	}
}

func TestMustAuth(t *testing.T) {
	// MustAuth with valid authenticator
	authConfig := MustAuth(&MockAuthenticator{
		ValidUser: "admin",
		ValidPass: "secret",
	})
	if authConfig == nil {
		t.Error("Expected non-nil config")
	}

	// MustAuth with nil authenticator must panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil authenticator")
		}
	}()
	MustAuth(nil)
}

func TestAPIAuthConfig_Validate(t *testing.T) {
	// Nil config
	var nilConfig *APIAuthConfig
	if err := nilConfig.Validate(); err == nil {
		t.Error("Expected error for nil config")
	}

	// Nil authenticator
	config := &APIAuthConfig{}
	if err := config.Validate(); err == nil {
		t.Error("Expected error for nil authenticator")
	}

	// Valid config
	config = MustAuth(&MockAuthenticator{})
	if err := config.Validate(); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}