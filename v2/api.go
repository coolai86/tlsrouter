package tlsrouter

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// APIServer provides HTTP endpoints for connection stats.
type APIServer struct {
	Stats *StatsRegistry
}

// NewAPIServer creates a new API server.
func NewAPIServer(stats *StatsRegistry) *APIServer {
	return &APIServer{Stats: stats}
}

// ServeHTTP implements http.Handler.
func (a *APIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set JSON content type
	w.Header().Set("Content-Type", "application/json")

	// Route based on path
	switch r.URL.Path {
	case "/api/connections":
		a.listConnections(w, r)
	case "/api/routes":
		a.listRoutes(w, r)
	case "/api/stats/stream":
		a.streamStats(w, r)
	default:
		// Check for /api/connections/:id pattern
		if len(r.URL.Path) > 17 && r.URL.Path[:18] == "/api/connections/" {
			a.getConnection(w, r)
			return
		}
		// Check for /api/connections/:id/close pattern
		if len(r.URL.Path) > 23 && r.URL.Path[:24] == "/api/connections/" && r.URL.Path[len(r.URL.Path)-5:] == "/close" {
			a.closeConnection(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

// listConnections returns all active connections.
// GET /api/connections
func (a *APIServer) listConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	connections := a.Stats.ListConnections()

	response := struct {
		Connections []*ConnectionStats `json:"connections"`
		Total       int               `json:"total"`
	}{
		Connections: connections,
		Total:       len(connections),
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(response)
}

// getConnection returns a single connection by ID.
// GET /api/connections/:id
func (a *APIServer) getConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from path
	id := r.URL.Path[18:] // Skip "/api/connections/"
	if id == "" {
		http.Error(w, "missing connection id", http.StatusBadRequest)
		return
	}

	stats := a.Stats.GetConnection(id)
	if stats == nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(stats)
}

// closeConnection closes a connection by ID.
// POST /api/connections/:id/close
func (a *APIServer) closeConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from path
	// Path format: /api/connections/:id/close
	path := r.URL.Path[18:] // Skip "/api/connections/"
	id := path[:len(path)-5] // Remove "/close"
	if id == "" {
		http.Error(w, "missing connection id", http.StatusBadRequest)
		return
	}

	stats := a.Stats.GetConnection(id)
	if stats == nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	// Mark as closed by admin
	a.Stats.CloseConnection(id, CloseReasonAdmin)

	response := struct {
		Status string `json:"status"`
		ID     string `json:"id"`
	}{
		Status: "closed",
		ID:     id,
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(response)
}

// listRoutes returns all route aggregates.
// GET /api/routes
func (a *APIServer) listRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	routes := a.Stats.ListRoutes()

	response := struct {
		Routes []*RouteAggregate `json:"routes"`
		Total  int               `json:"total"`
	}{
		Routes: routes,
		Total:  len(routes),
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(response)
}

// streamStats sends SSE events for real-time updates.
// GET /api/stats/stream
func (a *APIServer) streamStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Flush headers
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Subscribe to events
	id, ch, err := a.Stats.Subscribe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer a.Stats.Unsubscribe(id)

	// Send initial state
	a.sendInitialStats(w, r)

	// Stream events
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}
			a.sendEvent(w, event)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

// sendInitialStats sends the current connection state.
func (a *APIServer) sendInitialStats(w http.ResponseWriter, r *http.Request) {
	// Send current connections
	connections := a.Stats.ListConnections()
	for _, conn := range connections {
		data, _ := json.Marshal(conn)
		a.sendEvent(w, StatsEvent{
			Type:      "connect",
			Timestamp: conn.Started,
			Data:      data,
		})
	}

	// Send route aggregates
	routes := a.Stats.ListRoutes()
	for _, route := range routes {
		data, _ := json.Marshal(route)
		a.sendEvent(w, StatsEvent{
			Type:      "route",
			Timestamp: route.lastUpdate,
			Data:      data,
		})
	}
}

// sendEvent sends an SSE event.
func (a *APIServer) sendEvent(w http.ResponseWriter, event StatsEvent) {
	// Write event type
	_, _ = w.Write([]byte("event: " + event.Type + "\n"))

	// Write data
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(event.Data)
	_, _ = w.Write([]byte("\n\n"))
}

// MarshalJSON implements json.Marshaler for RouteAggregate.
func (r *RouteAggregate) MarshalJSON() ([]byte, error) {
	type Alias RouteAggregate
	return json.Marshal(&struct {
		*Alias
		RouteTypeStr string `json:"route_type,omitempty"`
	}{
		Alias: (*Alias)(r),
	})
}

// parseUintParam parses a uint parameter from query string.
func parseUintParam(r *http.Request, name string, def uint64) uint64 {
	val := r.URL.Query().Get(name)
	if val == "" {
		return def
	}
	n, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return def
	}
	return n
}