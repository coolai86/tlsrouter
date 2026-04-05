package tlsrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPRedirectServer_Redirect(t *testing.T) {
	server := NewHTTPRedirectServer(":80")

	// Test basic redirect
	req := httptest.NewRequest("GET", "http://example.com/foo?bar=baz", nil)
	rec := httptest.NewRecorder()
	server.handleRedirect(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("Expected 301, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	expected := "https://example.com/foo?bar=baz"
	if location != expected {
		t.Errorf("Expected location %q, got %q", expected, location)
	}
}

func TestHTTPRedirectServer_RedirectNonStandardPort(t *testing.T) {
	server := NewHTTPRedirectServer(":80").WithHTTPSAddr(":8443")

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rec := httptest.NewRecorder()
	server.handleRedirect(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("Expected 301, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	expected := "https://example.com:8443/foo"
	if location != expected {
		t.Errorf("Expected location %q, got %q", expected, location)
	}
}

func TestHTTPRedirectServer_ACMEChallenge(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		handler    func(string) string
		wantStatus int
		wantBody   string
	}{
		{
			name:  "valid challenge",
			token: "abc123",
			handler: func(token string) string {
				if token == "abc123" {
					return "abc123.key-auth-value"
				}
				return ""
			},
			wantStatus: http.StatusOK,
			wantBody:   "abc123.key-auth-value",
		},
		{
			name:  "invalid challenge",
			token: "notfound",
			handler: func(token string) string {
				if token == "abc123" {
					return "abc123.key-auth-value"
				}
				return ""
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "no handler",
			token:      "abc123",
			handler:    nil,
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewHTTPRedirectServer(":80")
			if tt.handler != nil {
				server = server.WithACMEHandler(tt.handler)
			}

			req := httptest.NewRequest("GET", "/.well-known/acme-challenge/"+tt.token, nil)
			rec := httptest.NewRecorder()
			server.handleACME(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rec.Code)
			}

			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("Expected body %q, got %q", tt.wantBody, rec.Body.String())
			}
		})
	}
}

func TestHTTPRedirectServer_ACMEPaths(t *testing.T) {
	server := NewHTTPRedirectServer(":80").WithACMEHandler(func(token string) string {
		return "response"
	})

	tests := []struct {
		path       string
		wantStatus int
	}{
		{"/.well-known/acme-challenge/token", http.StatusOK},
		{"/.well-known/acme-challenge/", http.StatusBadRequest},
		{"/other", http.StatusMovedPermanently},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()

			// Use the full handler
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/acme-challenge/", server.handleACME)
			mux.HandleFunc("/", server.handleRedirect)
			mux.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Path %q: expected status %d, got %d", tt.path, tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestHTTPRedirectServer_Shutdown(t *testing.T) {
	server := NewHTTPRedirectServer(":0") // Random port

	err := server.ListenAndServe()
	if err != nil {
		t.Fatalf("ListenAndServe failed: %v", err)
	}

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Shutdown with context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestHTTPRedirectServer_Close(t *testing.T) {
	server := NewHTTPRedirectServer(":0")

	err := server.ListenAndServe()
	if err != nil {
		t.Fatalf("ListenAndServe failed: %v", err)
	}

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Close immediately
	err = server.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}