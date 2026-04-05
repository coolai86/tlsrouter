package tlsrouter

// dashboardHTML is the embedded dashboard HTML.
// No external dependencies - all assets vendored and embedded.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TLSrouter Dashboard</title>
<!-- Oat.ink - Semantic UI (vendored) -->
<link rel="stylesheet" href="/dashboard/oat.min.css">
<script defer src="/dashboard/oat.min.js"></script>
<!-- Datastar for reactive SSE (vendored) -->
<script type="module" src="/dashboard/datastar.js"></script>
<style>
/* Dashboard-specific styles (Oat provides base semantic styling) */
.id, .bytes, .rate { font-family: var(--font-mono, monospace); text-align: right; }
.age { color: var(--muted-foreground, #71717a); }
.empty { text-align: center; color: var(--muted-foreground, #71717a); padding: 2rem; font-style: italic; }
</style>
</head>
<body>
<main class="container">
<h1>TLSrouter Dashboard</h1>

<div id="stats-summary" class="row" style="gap:1rem;margin-bottom:2rem" data-on:load="@get('/dashboard/stream')">
<div class="card" style="flex:1;min-width:160px">
<div class="text-light" style="font-size:0.875rem">Active Connections</div>
<div style="font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums">--</div>
</div>
<div class="card" style="flex:1;min-width:160px">
<div class="text-light" style="font-size:0.875rem">Total In</div>
<div style="font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums">--</div>
</div>
<div class="card" style="flex:1;min-width:160px">
<div class="text-light" style="font-size:0.875rem">Total Out</div>
<div style="font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums">--</div>
</div>
<div class="card" style="flex:1;min-width:160px">
<div class="text-light" style="font-size:0.875rem">In Rate</div>
<div style="font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums">--/s</div>
</div>
<div class="card" style="flex:1;min-width:160px">
<div class="text-light" style="font-size:0.875rem">Out Rate</div>
<div style="font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums">--/s</div>
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
</main>
</body>
</html>`