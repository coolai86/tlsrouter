package tlsrouter

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// AuthRateLimiter limits authentication attempts per IP to prevent
// timing attacks and credential stuffing.
type AuthRateLimiter struct {
	// MaxAttempts is the maximum failed attempts before blocking
	MaxAttempts int

	// Window is the time window for counting attempts
	Window time.Duration

	// BlockDuration is how long to block after exceeding max attempts
	BlockDuration time.Duration

	mu      sync.Mutex
	attempts map[string]*attemptRecord
}

type attemptRecord struct {
	count    int
	firstTry time.Time
	blocked  time.Time
}

// NewAuthRateLimiter creates a rate limiter with sensible defaults:
// - 5 failed attempts per minute
// - 5 minute block
func NewAuthRateLimiter() *AuthRateLimiter {
	return &AuthRateLimiter{
		MaxAttempts:    5,
		Window:         time.Minute,
		BlockDuration:  5 * time.Minute,
		attempts:      make(map[string]*attemptRecord),
	}
}

// Check returns an error if the IP is rate-limited.
// Call this BEFORE attempting authentication.
func (r *AuthRateLimiter) Check(ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	record, exists := r.attempts[ip]

	if exists {
		// Check if block has expired
		if !record.blocked.IsZero() && now.Sub(record.blocked) > r.BlockDuration {
			delete(r.attempts, ip)
			return nil // Block expired
		}

		// Check if still blocked
		if !record.blocked.IsZero() {
			remaining := r.BlockDuration - now.Sub(record.blocked)
			if remaining > 0 {
				return &RateLimitError{
					Remaining: remaining,
					Message:   "too many failed attempts",
				}
			}
		}

		// Check if window has expired
		if now.Sub(record.firstTry) > r.Window {
			delete(r.attempts, ip)
			return nil // Window expired, start fresh
		}

		// Check attempt count
		if record.count >= r.MaxAttempts {
			record.blocked = now
			return &RateLimitError{
				Remaining: r.BlockDuration,
				Message:   "too many failed attempts",
			}
		}
	}

	return nil
}

// RecordFailure records a failed authentication attempt.
func (r *AuthRateLimiter) RecordFailure(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	record, exists := r.attempts[ip]
	if !exists {
		record = &attemptRecord{firstTry: now}
		r.attempts[ip] = record
	}

	record.count++

	// If max attempts reached, block the IP
	if record.count >= r.MaxAttempts {
		record.blocked = now
	}
}

// RecordSuccess clears the attempt history for an IP.
func (r *AuthRateLimiter) RecordSuccess(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, ip)
}

// Cleanup removes expired records. Call periodically.
func (r *AuthRateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for ip, record := range r.attempts {
		// Remove if window expired and not blocked
		if now.Sub(record.firstTry) > r.Window && record.blocked.IsZero() {
			delete(r.attempts, ip)
		}
		// Remove if block expired
		if !record.blocked.IsZero() && now.Sub(record.blocked) > r.BlockDuration {
			delete(r.attempts, ip)
		}
	}
}

// RateLimitError is returned when rate limited.
type RateLimitError struct {
	Remaining time.Duration
	Message   string
}

func (e *RateLimitError) Error() string {
	return e.Message
}

// extractIP extracts the client IP from a request.
// It handles X-Forwarded-For, X-Real-IP, and falls back to RemoteAddr.
func extractIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// Check X-Forwarded-For (first IP is the original client)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ips := parseIPList(xff); len(ips) > 0 {
				return ips[0]
			}
		}
		// Check X-Real-IP
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func parseIPList(s string) []string {
	var ips []string
	for _, ip := range splitByComma(s) {
		ip = trimSpace(ip)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

func splitByComma(s string) []string {
	// Simple comma split without importing strings
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	// Simple trim without importing strings
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}