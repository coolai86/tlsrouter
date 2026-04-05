package tlsrouter

// dashboardHTML is the embedded dashboard HTML.
// No external dependencies - all CSS/JS embedded.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TLSrouter Dashboard</title>
<!-- Datastar for reactive SSE (vendored separately) -->
<script type="module" src="/dashboard/datastar.js"></script>
<style>
/* Minimal semantic CSS - zero dependencies */
:root {
  --bg: #0f1419;
  --bg-alt: #192734;
  --border: #38444d;
  --text: #e7e9ea;
  --text-muted: #71767b;
  --accent: #1d9bf0;
  --success: #00ba7c;
  --danger: #f4212e;
  --radius: 8px;
  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --mono: 'SF Mono', 'Fira Code', 'Consolas', monospace;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff;
    --bg-alt: #f7f9fa;
    --border: #cfd9de;
    --text: #0f1419;
    --text-muted: #536471;
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  line-height: 1.5;
}
.container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
h1 { margin-bottom: 1.5rem; font-size: 1.5rem; }
h2 { margin: 1.5rem 0 1rem; color: var(--text-muted); font-size: 1rem; font-weight: 600; }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.stat-card {
  background: var(--bg-alt);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1rem;
}
.stat-label { color: var(--text-muted); font-size: 0.8rem; display: block; }
.stat-value { font-size: 1.5rem; font-weight: 700; font-variant-numeric: tabular-nums; }
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg-alt);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
th, td { padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
th { background: var(--bg); font-weight: 600; color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.02); }
.id, .bytes, .rate { font-family: var(--mono); font-size: 0.85rem; }
.bytes, .rate { text-align: right; }
.age { color: var(--text-muted); }
.empty { text-align: center; color: var(--text-muted); padding: 2rem; font-style: italic; }
</style>
</head>
<body>
<div class="container">
<h1>TLSrouter Dashboard</h1>

<div id="stats-summary" class="stats-grid" data-on:load="@get('/dashboard/stream')">
<div class="stat-card">
<span class="stat-label">Active Connections</span>
<span class="stat-value">--</span>
</div>
<div class="stat-card">
<span class="stat-label">Total In</span>
<span class="stat-value">--</span>
</div>
<div class="stat-card">
<span class="stat-label">Total Out</span>
<span class="stat-value">--</span>
</div>
<div class="stat-card">
<span class="stat-label">In Rate</span>
<span class="stat-value">--</span>
</div>
<div class="stat-card">
<span class="stat-label">Out Rate</span>
<span class="stat-value">--</span>
</div>
</div>

<h2>Active Connections</h2>
<div id="connections-table">
<table>
<thead>
<tr><th>ID</th><th>SNI</th><th>ALPN</th><th>Backend</th><th>Bytes In</th><th>Bytes Out</th><th>Rate In</th><th>Rate Out</th><th>Age</th></tr>
</thead>
<tbody>
<tr><td colspan="9" class="empty">Loading...</td></tr>
</tbody>
</table>
</div>

<h2>Routes Summary</h2>
<div id="routes-table">
<table>
<thead>
<tr><th>Backend</th><th>Connections</th><th>Bytes In</th><th>Bytes Out</th></tr>
</thead>
<tbody>
<tr><td colspan="4" class="empty">Loading...</td></tr>
</tbody>
</table>
</div>
</div>
</body>
</html>`