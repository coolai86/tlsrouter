package tlsrouter

import "time"

// Clock provides the current time. Use RealClock in production and
// MockClock in tests for deterministic behavior.
type Clock interface {
	Now() time.Time
}

// RealClock returns the actual system time.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// MockClock returns a fixed time for testing.
type MockClock struct {
	Static time.Time
}

func (m MockClock) Now() time.Time { return m.Static }

// DefaultClock is the real system clock.
var DefaultClock Clock = RealClock{}