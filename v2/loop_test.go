package tlsrouter

import (
	"testing"
)

func TestListenerRegistry_IsSelf(t *testing.T) {
	reg := NewListenerRegistry()

	// Register some listeners
	reg.Register("127.0.0.1:443")
	reg.Register("0.0.0.0:8443")
	reg.Register("[::]:443")

	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{"exact match", "127.0.0.1:443", true},
		{"different port", "127.0.0.1:8443", false},
		{"not registered", "192.168.1.1:443", false},
		{"zero addr match", "0.0.0.0:8443", true},
		{"ipv6 match", "[::]:443", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reg.IsSelf(tt.addr); got != tt.expected {
				t.Errorf("IsSelf(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestListenerRegistry_IsSelfHost(t *testing.T) {
	reg := NewListenerRegistry()
	reg.Register("127.0.0.1:443")
	reg.Register("10.0.0.1:8443")

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"same host different port", "127.0.0.1", true},
		{"different host", "192.168.1.1", false},
		{"same host", "10.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reg.IsSelfHost(tt.host); got != tt.expected {
				t.Errorf("IsSelfHost(%q) = %v, want %v", tt.host, got, tt.expected)
			}
		})
	}
}

func TestListenerRegistry_CheckLoop(t *testing.T) {
	reg := NewListenerRegistry()
	reg.Register("127.0.0.1:443")
	reg.Register("10.0.0.1:8443")

	tests := []struct {
		name       string
		backend    string
		incomingID InstanceID
		incomingHops int
		wantLoop   bool
	}{
		{"direct loop", "127.0.0.1:443", "", 0, true},
		{"same host different port", "127.0.0.1:8080", "", 0, true},
		{"no loop different host", "192.168.1.1:443", "", 0, false},
		{"chain loop same instance", "192.168.1.1:443", reg.instance, 1, true},
		{"chain loop max hops", "192.168.1.1:443", "other-id", MaxHops, true},
		{"valid proxy chain", "192.168.1.1:443", "other-id", 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reg.CheckLoop(tt.backend, tt.incomingID, tt.incomingHops)
			gotLoop := err != nil
			if gotLoop != tt.wantLoop {
				t.Errorf("CheckLoop(%q, %q, %d) = %v, want loop=%v", tt.backend, tt.incomingID, tt.incomingHops, err, tt.wantLoop)
			}
		})
	}
}

func TestParseHopInfo(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		wantID   InstanceID
		wantHops int
		wantVia  int
	}{
		{"no headers", map[string][]string{}, "", 0, 0},
		{"with ID", map[string][]string{
			HeaderTLSrouterID: {"test-instance-id"},
		}, "test-instance-id", 0, 0},
		{"with hops", map[string][]string{
			HeaderTLSrouterHops: {"5"},
		}, "", 5, 0},
		{"with via", map[string][]string{
			HeaderTLSrouterVia: {"id1,id2,id3"},
		}, "", 0, 3},
		{"full headers", map[string][]string{
			HeaderTLSrouterID:   {"my-id"},
			HeaderTLSrouterHops: {"3"},
			HeaderTLSrouterVia:  {"prev1,prev2"},
		}, "my-id", 3, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ParseHopInfo(tt.headers)
			if info.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", info.ID, tt.wantID)
			}
			if info.Hops != tt.wantHops {
				t.Errorf("Hops = %d, want %d", info.Hops, tt.wantHops)
			}
			if len(info.Via) != tt.wantVia {
				t.Errorf("Via count = %d, want %d", len(info.Via), tt.wantVia)
			}
		})
	}
}

func TestAddHopHeaders(t *testing.T) {
	instance := InstanceID("test-instance")
	incoming := HopInfo{
		ID:   "prev-instance",
		Hops: 2,
		Via:  []InstanceID{"instance-1", "instance-2"},
	}

	headers := AddHopHeaders(nil, instance, incoming)

	if headers[HeaderTLSrouterID][0] != string(instance) {
		t.Errorf("TLSrouter-ID = %q, want %q", headers[HeaderTLSrouterID][0], instance)
	}
	if headers[HeaderTLSrouterHops][0] != "3" {
		t.Errorf("TLSrouter-Hops = %q, want 3", headers[HeaderTLSrouterHops][0])
	}
	// Via should contain: previous instances + incoming ID + us
	// instance-1, instance-2, prev-instance, test-instance
	expectedVia := "instance-1,instance-2,prev-instance,test-instance"
	if headers[HeaderTLSrouterVia][0] != expectedVia {
		t.Errorf("TLSrouter-Via = %q, want %q", headers[HeaderTLSrouterVia][0], expectedVia)
	}
}

func TestInstanceID(t *testing.T) {
	id1 := NewInstanceID()
	id2 := NewInstanceID()

	// IDs should be unique
	if id1 == id2 {
		t.Error("Instance IDs should be unique")
	}

	// IDs should not be empty
	if id1 == "" {
		t.Error("Instance ID should not be empty")
	}
}

func TestLoopError(t *testing.T) {
	err := &LoopError{
		Backend:  "127.0.0.1:443",
		Instance: "test-id",
		Reason:   "backend address matches local listener",
	}

	if err.Error() != "loop detected: backend address matches local listener" {
		t.Errorf("Error message = %q, want loop detected message", err.Error())
	}

	if !IsLoopError(err) {
		t.Error("IsLoopError should return true for LoopError")
	}

	if IsLoopError(nil) {
		t.Error("IsLoopError should return false for nil")
	}
}