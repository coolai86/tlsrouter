package tlsrouter

import (
	"net/http"
	"slices"
	"strings"
)

// APIAuthConfig configures authentication for the stats API.
type APIAuthConfig struct {
	// Authenticator is the csvauth.Auth instance for credential verification.
	// If nil, no authentication is required (not recommended for production).
	Authenticator interface {
		Authenticate(username, password string) (interface{ Permissions() []string }, error)
	}

	// Permissions required to access the API. If empty, any authenticated user can access.
	RequiredPermissions []string
}

// AuthenticatedHandler wraps an http.Handler with authentication.
func (c *APIAuthConfig) AuthenticatedHandler(next http.Handler) http.Handler {
	if c == nil || c.Authenticator == nil {
		// No auth configured - pass through
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principle, err := c.authenticateRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check permissions if required
		if len(c.RequiredPermissions) > 0 {
			perms := principle.Permissions()
			hasPerm := false
			for _, required := range c.RequiredPermissions {
				if slices.Contains(perms, required) {
					hasPerm = true
					break
				}
			}
			if !hasPerm {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// authenticateRequest extracts credentials from the request and validates them.
func (c *APIAuthConfig) authenticateRequest(r *http.Request) (interface{ Permissions() []string }, error) {
	// Try Bearer token first
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		return c.Authenticator.Authenticate("", token)
	}

	// Try Basic auth
	if user, pass, ok := r.BasicAuth(); ok {
		return c.Authenticator.Authenticate(user, pass)
	}

	// Try query parameter
	if token := r.URL.Query().Get("access_token"); token != "" {
		return c.Authenticator.Authenticate("", token)
	}

	return nil, ErrNoCredentials
}

// ErrNoCredentials is returned when no credentials are provided.
var ErrNoCredentials = &AuthError{Message: "no credentials provided"}

// AuthError represents an authentication error.
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}