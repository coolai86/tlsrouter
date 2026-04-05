package tlsrouter

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/therootcompany/golib/auth"
)

// APIAuthConfig configures authentication for the stats API.
// Authenticator is required - the stats API exposes sensitive connection data.
type APIAuthConfig struct {
	// Authenticator is the credential store (e.g., *csvauth.Auth).
	// Required - must not be nil.
	Authenticator auth.BasicAuthenticator

	// Permissions required to access the API. If empty, any authenticated user can access.
	RequiredPermissions []string

	// Realm for WWW-Authenticate header (default: "Basic")
	Realm string
}

// AuthenticatedHandler wraps an http.Handler with authentication.
// Panics if Authenticator is nil - auth is required for security.
func (c *APIAuthConfig) AuthenticatedHandler(next http.Handler) http.Handler {
	if c == nil {
		panic("APIAuthConfig: configuration is required (stats API exposes sensitive data)")
	}
	if c.Authenticator == nil {
		panic("APIAuthConfig: Authenticator is required (stats API exposes sensitive data)")
	}

	realm := c.Realm
	if realm == "" {
		realm = "Basic"
	}

	ra := auth.NewBasicRequestAuthenticator(c.Authenticator)
	ra.BasicRealm = realm

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := ra.Authenticate(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", ra.BasicRealm)
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

// MustAuth creates an APIAuthConfig with the given authenticator.
// Convenience function to ensure auth is always configured.
func MustAuth(authenticator auth.BasicAuthenticator, permissions ...string) *APIAuthConfig {
	if authenticator == nil {
		panic("MustAuth: authenticator is required")
	}
	return &APIAuthConfig{
		Authenticator:       authenticator,
		RequiredPermissions: permissions,
	}
}

// WithRealm sets the WWW-Authenticate realm.
func (c *APIAuthConfig) WithRealm(realm string) *APIAuthConfig {
	c.Realm = realm
	return c
}

// WithPermissions sets required permissions.
func (c *APIAuthConfig) WithPermissions(permissions ...string) *APIAuthConfig {
	c.RequiredPermissions = permissions
	return c
}

// Validate checks that the config is valid.
func (c *APIAuthConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("APIAuthConfig: configuration is required")
	}
	if c.Authenticator == nil {
		return fmt.Errorf("APIAuthConfig: Authenticator is required")
	}
	return nil
}