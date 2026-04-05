package tlsrouter

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/starfederation/datastar-go/datastar"
)

// Vendored frontend assets (downloaded via vendor/*/download.sh)
//go:embed vendor/datastar.js
//go:embed vendor/oat.min.css
//go:embed vendor/oat.min.js
var vendorAssets embed.FS

// DashboardServer provides a real-time dashboard using Datastar.
type DashboardServer struct {
	Stats *StatsRegistry

	mu      sync.Mutex
	scripts string // Embedded Datastar script
}

// NewDashboardServer creates a new dashboard server.
func NewDashboardServer(stats *StatsRegistry) *DashboardServer {
	return &DashboardServer{
		Stats: stats,
	}
}

// ServeHTTP implements http.Handler.
func (d *DashboardServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/dashboard", "/dashboard/":
		d.serveDashboard(w, r)
	case "/dashboard/datastar.js":
		d.serveStatic(w, r, "vendor/datastar.js", "application/javascript")
	case "/dashboard/oat.min.css":
		d.serveStatic(w, r, "vendor/oat.min.css", "text/css")
	case "/dashboard/oat.min.js":
		d.serveStatic(w, r, "vendor/oat.min.js", "application/javascript")
	case "/dashboard/stream":
		d.streamUpdates(w, r)
	case "/dashboard/connections":
		d.listConnections(w, r)
	case "/dashboard/routes":
		d.listRoutes(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveStatic serves a file from the embedded vendor assets.
func (d *DashboardServer) serveStatic(w http.ResponseWriter, r *http.Request, name, contentType string) {
	data, err := vendorAssets.ReadFile(name)
	if err != nil {
		http.Error(w, "file not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType+"; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000") // 1 year
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// serveDashboard serves the HTML dashboard.
func (d *DashboardServer) serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(dashboardHTML))
}

// streamUpdates sends real-time updates via Datastar SSE.
func (d *DashboardServer) streamUpdates(w http.ResponseWriter, r *http.Request) {
	sse := datastar.NewSSE(w, r)

	// Send initial state
	d.sendConnections(sse)
	d.sendRoutes(sse)
	d.sendStats(sse)

	// Stream updates
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			d.sendConnections(sse)
			d.sendRoutes(sse)
			d.sendStats(sse)
		}
	}
}

// sendConnections sends the connections table.
func (d *DashboardServer) sendConnections(sse *datastar.ServerSentEventGenerator) {
	connections := d.Stats.ListConnections()

	html := `<table>
<thead>
<tr><th>ID</th><th>SNI</th><th>ALPN</th><th>Backend</th><th>Bytes In</th><th>Bytes Out</th><th>Rate In</th><th>Rate Out</th><th>Age</th></tr>
</thead>
<tbody>`

	for _, c := range connections {
		age := time.Since(c.Started).Round(time.Second)
		html += fmt.Sprintf(`<tr>
<td class="id">%s</td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td class="bytes">%s</td>
<td class="bytes">%s</td>
<td class="rate">%s/s</td>
<td class="rate">%s/s</td>
<td class="age">%s</td>
</tr>`,
			c.ID[:8],
			c.SNI,
			c.ALPN,
			c.BackendAddr,
			formatBytes(int64(c.BytesIn)),
			formatBytes(int64(c.BytesOut)),
			formatBytes(int64(c.RateInBps)),
			formatBytes(int64(c.RateOutBps)),
			age,
		)
	}

	if len(connections) == 0 {
		html += `<tr><td colspan="9" class="empty">No active connections</td></tr>`
	}

	html += `</tbody></table>`

	sse.PatchElements(`<div id="connections-table">` + html + `</div>`)
}

// sendRoutes sends the routes summary.
func (d *DashboardServer) sendRoutes(sse *datastar.ServerSentEventGenerator) {
	routes := d.Stats.ListRoutes()

	html := `<table>
<thead>
<tr><th>Backend</th><th>Connections</th><th>Bytes In</th><th>Bytes Out</th></tr>
</thead>
<tbody>`

	for _, r := range routes {
		html += fmt.Sprintf(`<tr>
<td>%s</td>
<td>%d</td>
<td class="bytes">%s</td>
<td class="bytes">%s</td>
</tr>`,
			r.RouteKey,
			r.ActiveConns,
			formatBytes(int64(r.TotalBytesIn)),
			formatBytes(int64(r.TotalBytesOut)),
		)
	}

	if len(routes) == 0 {
		html += `<tr><td colspan="4" class="empty">No routes</td></tr>`
	}

	html += `</tbody></table>`

	sse.PatchElements(`<div id="routes-table">` + html + `</div>`)
}

// sendStats sends the summary stats.
func (d *DashboardServer) sendStats(sse *datastar.ServerSentEventGenerator) {
	connections := d.Stats.ListConnections()

	var totalIn, totalOut uint64
	var totalInRate, totalOutRate uint64
	for _, c := range connections {
		totalIn += c.BytesIn
		totalOut += c.BytesOut
		totalInRate += c.RateInBps
		totalOutRate += c.RateOutBps
	}

	html := fmt.Sprintf(`<div id="stats-summary" class="stats-grid">
<div class="stat-card">
<span class="stat-label">Active Connections</span>
<span class="stat-value">%d</span>
</div>
<div class="stat-card">
<span class="stat-label">Total In</span>
<span class="stat-value">%s</span>
</div>
<div class="stat-card">
<span class="stat-label">Total Out</span>
<span class="stat-value">%s</span>
</div>
<div class="stat-card">
<span class="stat-label">In Rate</span>
<span class="stat-value">%s/s</span>
</div>
<div class="stat-card">
<span class="stat-label">Out Rate</span>
<span class="stat-value">%s/s</span>
</div>
</div>`,
		len(connections),
		formatBytes(int64(totalIn)),
		formatBytes(int64(totalOut)),
		formatBytes(int64(totalInRate)),
		formatBytes(int64(totalOutRate)),
	)

	sse.PatchElements(html)
}

// listConnections returns connections as JSON (for non-Datastar clients).
func (d *DashboardServer) listConnections(w http.ResponseWriter, r *http.Request) {
	connections := d.Stats.ListConnections()

	response := struct {
		Connections []*ConnectionStats `json:"connections"`
		Total       int                 `json:"total"`
	}{
		Connections: connections,
		Total:       len(connections),
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(response)
}

// listRoutes returns routes as JSON (for non-Datastar clients).
func (d *DashboardServer) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes := d.Stats.ListRoutes()

	response := struct {
		Routes []*RouteAggregate `json:"routes"`
	}{
		Routes: routes,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(response)
}

// formatBytes formats bytes in human-readable form.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}