package tlsrouter

// dashboardHTML is the embedded dashboard HTML.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TLSrouter Dashboard</title>
<!-- Oat.ink - Ultra-lightweight semantic UI (8KB) -->
<link rel="stylesheet" href="https://cdn.oat.ink/oat@0.1.0.css">
<script defer src="https://cdn.oat.ink/oat@0.1.0.js"></script>
<!-- Datastar for reactive SSE -->
<script type="module" src="https://cdn.jsdelivr.net/gh/starfederation/datastar@1.0.0-RC.8/bundles/datastar.js"></script>
<style>
/* Oat provides semantic styling, we just need layout tweaks */
:root {
  --oat-color-bg: #0f1419;
  --oat-color-bg-alt: #192734;
  --oat-color-border: #38444d;
  --oat-color-text: #e7e9ea;
  --oat-color-text-muted: #71767b;
  --oat-color-accent: #1d9bf0;
  --oat-color-success: #00ba7c;
  --oat-color-danger: #f4212e;
  --oat-radius: 8px;
}
body {
  background: var(--oat-color-bg);
  color: var(--oat-color-text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.5;
  margin: 0;
}
.container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
h1 { margin-bottom: 1.5rem; }
h2 { margin: 1.5rem 0 1rem; color: var(--oat-color-text-muted); font-size: 1.1rem; font-weight: 500; }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.stat-card {
  background: var(--oat-color-bg-alt);
  border: 1px solid var(--oat-color-border);
  border-radius: var(--oat-radius);
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.stat-label { color: var(--oat-color-text-muted); font-size: 0.85rem; }
.stat-value { font-size: 1.5rem; font-weight: 600; font-variant-numeric: tabular-nums; }
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--oat-color-bg-alt);
  border: 1px solid var(--oat-color-border);
  border-radius: var(--oat-radius);
  overflow: hidden;
}
th, td { padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--oat-color-border); }
th { background: var(--oat-color-bg); font-weight: 600; color: var(--oat-color-text-muted); font-size: 0.85rem; }
tr:last-child td { border-bottom: none; }
.id, .bytes, .rate { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; }
.bytes, .rate { text-align: right; }
.age { color: var(--oat-color-text-muted); }
.empty { text-align: center; color: var(--oat-color-text-muted); padding: 2rem; }
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