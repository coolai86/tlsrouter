package tlsrouter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthRateLimiter_Check(t *testing.T) {
	limiter := NewAuthRateLimiter()
	limiter.MaxAttempts = 3
	limiter.Window = time.Minute
	limiter.BlockDuration = 5 * time.Minute

	ip := "192.168.1.1"

	// First few attempts should succeed
	for i := 0; i < 3; i++ {
		if err := limiter.Check(ip); err != nil {
			t.Errorf("Attempt %d should succeed, got error: %v", i+1, err)
		}
		limiter.RecordFailure(ip)
	}

	// After 3 failures, should be blocked
	if err := limiter.Check(ip); err == nil {
		t.Error("Should be rate limited after 3 failures")
	}
}

func TestAuthRateLimiter_SuccessClears(t *testing.T) {
	limiter := NewAuthRateLimiter()
	limiter.MaxAttempts = 3

	ip := "192.168.1.2"

	// 2 failures
	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	// Should still be allowed
	if err := limiter.Check(ip); err != nil {
		t.Errorf("Should be allowed after 2 failures: %v", err)
	}

	// Success clears history
	limiter.RecordSuccess(ip)

	// Should still be allowed
	if err := limiter.Check(ip); err != nil {
		t.Errorf("Should be allowed after success: %v", err)
	}
}

func TestAuthRateLimiter_BlockExpiration(t *testing.T) {
	limiter := &AuthRateLimiter{
		MaxAttempts:   2,
		Window:        time.Minute,
		BlockDuration: 100 * time.Millisecond,
		attempts:      make(map[string]*attemptRecord),
	}

	ip := "192.168.1.3"

	// Trigger block
	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	if err := limiter.Check(ip); err == nil {
		t.Error("Should be blocked")
	}

	// Wait for block to expire
	time.Sleep(150 * time.Millisecond)

	if err := limiter.Check(ip); err != nil {
		t.Errorf("Should be unblocked after expiration: %v", err)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff       string
		xri       string
		trustProxy bool
		want       string
	}{
		{
			name:       "direct connection",
			remoteAddr: "192.168.1.1:12345",
			trustProxy: false,
			want:       "192.168.1.1",
		},
		{
			name:       "x-forwarded-for trusted",
			remoteAddr: "10.0.0.1:12345",
			xff:        "1.2.3.4, 10.0.0.1",
			trustProxy: true,
			want:       "1.2.3.4",
		},
		{
			name:       "x-real-ip trusted",
			remoteAddr: "10.0.0.1:12345",
			xri:        "5.6.7.8",
			trustProxy: true,
			want:       "5.6.7.8",
		},
		{
			name:       "headers ignored when not trusting proxy",
			remoteAddr: "192.168.1.1:12345",
			xff:        "1.2.3.4",
			trustProxy: false,
			want:       "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			got := extractIP(req, tt.trustProxy)
			if got != tt.want {
				t.Errorf("extractIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAPIAuthConfig_WithRateLimiter(t *testing.T) {
	authConfig := MustAuth(&MockAuthenticator{
		ValidUser: "admin",
		ValidPass: "secret",
	})

	limiter := NewAuthRateLimiter()
	limiter.MaxAttempts = 1

	authConfig = authConfig.WithRateLimiter(limiter)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := authConfig.AuthenticatedHandler(handler)

	// First attempt with wrong password
	req := httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rec.Code)
	}

	// Second attempt should be rate limited (max 1 failure)
	req = httptest.NewRequest("GET", "/api/connections", nil)
	req.SetBasicAuth("admin", "wrong")
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 (rate limited), got %d", rec.Code)
	}
}