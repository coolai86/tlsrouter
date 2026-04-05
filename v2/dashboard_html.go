package tlsrouter

// dashboardHTML is the embedded dashboard HTML.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TLSrouter Dashboard</title>
<script type="module" src="https://cdn.jsdelivr.net/gh/starfederation/datastar@1.0.0-RC.8/bundles/datastar.js"></script>
<style>
:root {
  --bg: #0f1419;
  --card: #192734;
  --border: #38444d;
  --text: #e7e9ea;
  --muted: #71767b;
  --accent: #1d9bf0;
  --success: #00ba7c;
  --danger: #f4212e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
.container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
h1 { margin-bottom: 1.5rem; font-size: 1.75rem; }
h2 { margin: 1.5rem 0 1rem; font-size: 1.25rem; color: var(--muted); }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.stat-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.stat-label { color: var(--muted); font-size: 0.875rem; }
.stat-value { font-size: 1.5rem; font-weight: 600; }
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
th { background: var(--bg); font-weight: 600; color: var(--muted); }
tr:last-child td { border-bottom: none; }
.id { font-family: monospace; font-size: 0.875rem; }
.bytes, .rate { font-family: monospace; text-align: right; }
.age { color: var(--muted); }
.empty { text-align: center; color: var(--muted); padding: 2rem; }
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
<table class="connections-table">
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
<table class="routes-table">
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