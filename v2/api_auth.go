package tlsrouter

import (
	"net/http"
	"slices"
	"strings"

	"github.com/therootcompany/golib/auth"
)

// APIAuthConfig configures authentication for the stats API.
type APIAuthConfig struct {
	// Authenticator is the credential store (e.g., *csvauth.Auth).
	// If nil, no authentication is required (not recommended for production).
	Authenticator auth.BasicAuthenticator

	// Permissions required to access the API. If empty, any authenticated user can access.
	RequiredPermissions []string

	// Realm for WWW-Authenticate header (default: "Basic")
	Realm string
}

// AuthenticatedHandler wraps an http.Handler with authentication.
func (c *APIAuthConfig) AuthenticatedHandler(next http.Handler) http.Handler {
	if c == nil || c.Authenticator == nil {
		// No auth configured - pass through
		return next
	}

	realm := c.Realm
	if realm == "" {
		realm = "Basic"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := c.authenticateRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check permissions if required
		if len(c.RequiredPermissions) > 0 {
			perms := principal.Permissions()
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

// authenticateRequest extracts credentials from HTTP request and authenticates.
// Supports: Bearer token, Basic auth, and ?access_token= query param.
func (c *APIAuthConfig) authenticateRequest(r *http.Request) (auth.BasicPrinciple, error) {
	// Bearer token
	if token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found && token != "" {
		return c.Authenticator.Authenticate("", token)
	}

	// Basic auth
	if user, pass, ok := r.BasicAuth(); ok {
		return c.Authenticator.Authenticate(user, pass)
	}

	// Query param access_token
	if token := r.URL.Query().Get("access_token"); token != "" {
		return c.Authenticator.Authenticate("", token)
	}

	return nil, auth.ErrNoCredentials
}