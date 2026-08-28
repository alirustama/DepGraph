/* DepGraph frontend — no build step, no framework.
   Hash-based router + fetch() against the FastAPI JSON API + vis-network
   for the dependency graph panels. */

const view = document.getElementById('view');
const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// ---------------------------------------------------------------------
// tiny helpers
// ---------------------------------------------------------------------

function el(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstChild;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function skeleton(rows = 4) {
  return `<div>${Array.from({ length: rows }).map((_, i) => `<div class="skeleton" style="width:${90 - i * 10}%"></div>`).join('')}</div>`;
}

function errorBlock(message) {
  return `<div class="state-block error">Couldn't load this view.<div class="hint">${esc(message)}</div></div>`;
}

function emptyBlock(message, hint = '') {
  return `<div class="state-block">${esc(message)}${hint ? `<div class="hint">${esc(hint)}</div>` : ''}</div>`;
}

async function api(path) {
  let res;
  try {
    res = await fetch(path);
  } catch (netErr) {
    const e = new Error('Network error reaching DepGraph API.');
    e.isNetwork = true;
    throw e;
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      msg = body.message || body.detail || msg;
    } catch (_) {}
    const e = new Error(msg);
    e.status = res.status;
    throw e;
  }
  return res.json();
}

function severityBadge(sev) {
  return `<span class="badge ${esc(sev)}">${esc(sev)}</span>`;
}

// ---------------------------------------------------------------------
// health check pill
// ---------------------------------------------------------------------

async function pollHealth() {
  const pill = document.getElementById('health-pill');
  const text = document.getElementById('health-text');
  try {
    const data = await api('/api/health');
    pill.className = 'health-pill ' + (data.ok ? 'ok' : 'down');
    text.textContent = data.ok ? 'CognoDB connected' : 'CognoDB unreachable';
  } catch (_) {
    pill.className = 'health-pill down';
    text.textContent = 'CognoDB unreachable';
  }
}
pollHealth();
setInterval(pollHealth, 20000);

// ---------------------------------------------------------------------
// router
// ---------------------------------------------------------------------

const routes = [];
function route(pattern, handler) { routes.push({ pattern, handler }); }

function matchRoute(hash) {
  const path = hash.replace(/^#/, '') || '/projects';
  for (const r of routes) {
    const m = path.match(r.pattern);
    if (m) return { handler: r.handler, params: m.slice(1).map(decodeURIComponent) };
  }
  return null;
}

async function render() {
  const match = matchRoute(location.hash);
  document.querySelectorAll('nav.sidenav a').forEach((a) => a.classList.remove('active'));
  const top = (location.hash.replace('#/', '').split('/')[0]) || 'projects';
  document.querySelector(`nav.sidenav a[data-route="${top}"]`)?.classList.add('active');

  if (!match) {
    view.innerHTML = emptyBlock('Nothing here.', 'Try Projects from the left nav.');
    return;
  }
  view.innerHTML = skeleton(6);
  try {
    await match.handler(...match.params);
  } catch (err) {
    view.innerHTML = errorBlock(err.message || 'Unexpected error.');
  }
}

window.addEventListener('hashchange', render);
window.addEventListener('DOMContentLoaded', render);

// ---------------------------------------------------------------------
// global search
// ---------------------------------------------------------------------

document.getElementById('global-search').addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const q = e.target.value.trim();
  if (!q) return;
  if (/^CVE-/i.test(q)) location.hash = `#/vulnerabilities/${encodeURIComponent(q)}`;
  else location.hash = `#/packages/${encodeURIComponent(q)}`;
});

// ---------------------------------------------------------------------
// PROJECTS
// ---------------------------------------------------------------------

route(/^\/projects$/, async () => {
  const projects = await api('/api/projects');
  view.innerHTML = `
    <div class="page-eyebrow">Internal services</div>
    <h1 class="page-title">Projects</h1>
    <p class="page-sub">Everything your org ships. Open one to trace its full transitive dependency tree and see which disclosed vulnerabilities it's exposed to — directly or several packages deep.</p>
    ${projects.length ? `<div class="grid cols-3" id="proj-grid"></div>` : emptyBlock('No projects yet.', 'Run scripts/seed.py to load the demo dataset.')}
  `;
  const grid = document.getElementById('proj-grid');
  if (!grid) return;
  projects.forEach((p) => {
    grid.appendChild(el(`
      <a class="card card-link" href="#/projects/${encodeURIComponent(p.name)}">
        <h3>${esc(p.name)}</h3>
        <p class="desc">${esc(p.description || '')}</p>
        <div class="stat-row">
          <div class="stat"><b>${p.directDependencies}</b>direct deps</div>
          <div class="stat"><b>${esc(p.owner || '—')}</b>owner</div>
        </div>
      </a>
    `));
  });
});

route(/^\/projects\/([^/]+)$/, async (name) => {
  const detail = await api(`/api/projects/${encodeURIComponent(name)}`);
  const vulnRows = detail.vulnerabilities.length
    ? detail.vulnerabilities.map((v) => `
        <tr class="clickable" onclick="location.hash='#/vulnerabilities/${encodeURIComponent(v.cveId)}'">
          <td class="mono">${esc(v.cveId)}</td>
          <td>${severityBadge(v.severity)}</td>
          <td class="mono">${v.cvss}</td>
          <td class="mono">${esc(v.vulnerableVersion)}</td>
          <td><span class="badge hops">${v.hops} hop${v.hops === 1 ? '' : 's'}</span></td>
        </tr>`).join('')
    : '';

  view.innerHTML = `
    <div class="breadcrumb"><a href="#/projects">Projects</a> / ${esc(detail.name)}</div>
    <div class="page-eyebrow">Project</div>
    <h1 class="page-title">${esc(detail.name)}</h1>
    <p class="page-sub">${esc(detail.description || '')} ${detail.owner ? `· owned by ${esc(detail.owner)}` : ''}</p>

    <div class="detail-columns">
      <div>
        <div class="panel-header"><h2>Dependency graph</h2><span class="count">direct + transitive, up to 6 hops shown</span></div>
        <div class="legend">
          <span><i style="background:#4fd1c5"></i>Project</span>
          <span><i style="background:#8592ac"></i>Package</span>
          <span><i style="background:#172238;border:1px solid #24324a"></i>Version</span>
        </div>
        <div id="graph-canvas"></div>
      </div>
      <div>
        <div class="panel-header"><h2>Vulnerability exposure</h2><span class="count">${detail.vulnerabilities.length}</span></div>
        ${detail.vulnerabilities.length ? `
          <table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Version</th><th>Depth</th></tr></thead>
          <tbody>${vulnRows}</tbody></table>
        ` : emptyBlock('No known vulnerabilities in this project\'s dependency tree.', 'That\'s a good thing — nothing to trace right now.')}
      </div>
    </div>

    <div class="section-title">All dependencies (direct + transitive)</div>
    <table>
      <thead><tr><th>Package</th><th>Hops from project</th></tr></thead>
      <tbody>
        ${detail.transitiveDependencies.map((d) => `
          <tr class="clickable" onclick="location.hash='#/packages/${encodeURIComponent(d.package)}'">
            <td class="mono">${esc(d.package)}</td>
            <td>${d.hops === 0 ? '<span class="badge hops">direct</span>' : `<span class="badge hops">${d.hops} hops</span>`}</td>
          </tr>`).join('')}
      </tbody>
    </table>
  `;
  drawGraph('graph-canvas', await api(`/api/graph/project/${encodeURIComponent(name)}`));
});

// ---------------------------------------------------------------------
// PACKAGES
// ---------------------------------------------------------------------

route(/^\/packages$/, async () => {
  const packages = await api('/api/packages');
  view.innerHTML = `
    <div class="page-eyebrow">Open-source dependencies</div>
    <h1 class="page-title">Packages</h1>
    <p class="page-sub">Every package used somewhere in the graph, sorted by known-vulnerability count. Open one to see its versions, maintainers, and — critically — which packages and projects transitively depend on it.</p>
    ${packages.length ? `
      <table>
        <thead><tr><th>Package</th><th>Ecosystem</th><th>Description</th><th>Vulnerabilities</th></tr></thead>
        <tbody>
          ${packages.map((p) => `
            <tr class="clickable" onclick="location.hash='#/packages/${encodeURIComponent(p.name)}'">
              <td class="mono">${esc(p.name)}</td>
              <td class="mono">${esc(p.ecosystem)}</td>
              <td>${esc(p.description || '')}</td>
              <td>${p.vulnerabilityCount > 0 ? `<span class="badge CRITICAL">${p.vulnerabilityCount}</span>` : '<span class="badge LOW">0</span>'}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    ` : emptyBlock('No packages yet.', 'Run scripts/seed.py to load the demo dataset.')}
  `;
});

route(/^\/packages\/([^/]+)$/, async (name) => {
  const detail = await api(`/api/packages/${encodeURIComponent(name)}`);
  view.innerHTML = `
    <div class="breadcrumb"><a href="#/packages">Packages</a> / ${esc(detail.name)}</div>
    <div class="page-eyebrow">${esc(detail.ecosystem)} package</div>
    <h1 class="page-title">${esc(detail.name)}</h1>
    <p class="page-sub">${esc(detail.description || '')}</p>

    <div class="grid cols-2">
      <div class="card">
        <div class="panel-header"><h2>Versions</h2><span class="count">${detail.versions.length}</span></div>
        <table>
          <thead><tr><th>Version</th><th>Released</th><th>CVEs</th></tr></thead>
          <tbody>
            ${detail.versions.map((v) => `
              <tr>
                <td class="mono">${esc(v.number)}${v.deprecated ? ' <span class="badge MEDIUM">deprecated</span>' : ''}</td>
                <td class="mono">${esc(v.releaseDate || '—')}</td>
                <td>${v.cves.filter(Boolean).map((c) => `<a class="badge CRITICAL" href="#/vulnerabilities/${encodeURIComponent(c)}">${esc(c)}</a>`).join(' ') || '—'}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
      <div class="card">
        <div class="panel-header"><h2>Maintainers</h2><span class="count">${detail.maintainers.length}</span></div>
        ${detail.maintainers.length ? `
          <table><tbody>
            ${detail.maintainers.map((m) => `<tr><td>${esc(m.name)}</td><td class="mono">${esc(m.email)}</td></tr>`).join('')}
          </tbody></table>
        ` : emptyBlock('No maintainer on record.')}
      </div>
    </div>

    <div class="section-title">Packages that transitively depend on this one</div>
    ${detail.dependents.length ? `
      <div class="grid cols-3">
        ${detail.dependents.map((d) => `<a class="card card-link" href="#/packages/${encodeURIComponent(d.package)}"><h3 class="mono" style="font-size:13.5px">${esc(d.package)}</h3></a>`).join('')}
      </div>
    ` : emptyBlock('Nothing depends on this package.', 'It sits at the edge of the graph.')}

    <div class="section-title">Projects exposed to this package (any depth)</div>
    ${detail.exposedProjects.length ? `
      <div class="grid cols-3">
        ${detail.exposedProjects.map((p) => `<a class="card card-link" href="#/projects/${encodeURIComponent(p.project)}"><h3 style="font-size:13.5px">${esc(p.project)}</h3></a>`).join('')}
      </div>
    ` : emptyBlock('No internal projects currently depend on this package.')}
  `;
});

// ---------------------------------------------------------------------
// VULNERABILITIES
// ---------------------------------------------------------------------

route(/^\/vulnerabilities$/, async () => {
  const vulns = await api('/api/vulnerabilities');
  vulns.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  view.innerHTML = `
    <div class="page-eyebrow">Disclosed CVEs</div>
    <h1 class="page-title">Vulnerabilities</h1>
    <p class="page-sub">Open one to compute its full blast radius — every internal project exposed to it, no matter how many packages deep the vulnerable dependency sits.</p>
    ${vulns.length ? `
      <table>
        <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Summary</th><th>Affects</th></tr></thead>
        <tbody>
          ${vulns.map((v) => `
            <tr class="clickable" onclick="location.hash='#/vulnerabilities/${encodeURIComponent(v.cveId)}'">
              <td class="mono">${esc(v.cveId)}</td>
              <td>${severityBadge(v.severity)}</td>
              <td class="mono">${v.cvss}</td>
              <td>${esc(v.summary)}</td>
              <td class="mono">${v.affectedPackages.map(esc).join(', ')}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    ` : emptyBlock('No vulnerabilities on record.', 'Run scripts/seed.py to load the demo dataset.')}
  `;
});

route(/^\/vulnerabilities\/([^/]+)$/, async (cve) => {
  const detail = await api(`/api/vulnerabilities/${encodeURIComponent(cve)}`);
  view.innerHTML = `
    <div class="breadcrumb"><a href="#/vulnerabilities">Vulnerabilities</a> / ${esc(detail.cveId)}</div>
    <div class="page-eyebrow">${severityBadge(detail.severity)} &nbsp;CVSS ${detail.cvss} &nbsp;· published ${esc(detail.publishedDate)}</div>
    <h1 class="page-title">${esc(detail.cveId)}</h1>
    <p class="page-sub">${esc(detail.summary)}</p>

    <div class="detail-columns">
      <div>
        <div class="panel-header"><h2>Blast radius graph</h2><span class="count">projects → … → vulnerable package</span></div>
        <div class="legend">
          <span><i style="background:#e5484d"></i>Vulnerability</span>
          <span><i style="background:#8592ac"></i>Vulnerable package</span>
          <span><i style="background:#4fd1c5"></i>Exposed project</span>
        </div>
        <div id="graph-canvas"></div>
      </div>
      <div>
        <div class="panel-header"><h2>Affected package versions</h2><span class="count">${detail.affectedPackages.length}</span></div>
        <table><thead><tr><th>Package</th><th>Version</th><th>Patched in</th></tr></thead>
          <tbody>
            ${detail.affectedPackages.map((p) => `
              <tr class="clickable" onclick="location.hash='#/packages/${encodeURIComponent(p.package)}'">
                <td class="mono">${esc(p.package)}</td>
                <td class="mono">${esc(p.version)}</td>
                <td class="mono">${esc(p.patchedInVersion || '—')}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="section-title">Exposed projects &amp; example path</div>
    ${detail.exposedProjects.length ? detail.exposedProjects.map((p) => `
      <div class="card" style="margin-bottom:10px">
        <div class="panel-header"><h2>${esc(p.project)}</h2><span class="badge hops">${p.hops} hop${p.hops === 1 ? '' : 's'}</span></div>
        <div class="path-chain">
          ${p.examplePath.map((n, i) => `${i > 0 ? '<span class="arrow">→</span>' : ''}<span class="node">${esc(n)}</span>`).join('')}
        </div>
      </div>
    `).join('') : emptyBlock('No internal projects are currently exposed to this CVE.', 'Every dependency chain leading here has already been upgraded, or none exists.')}
  `;
  drawGraph('graph-canvas', await api(`/api/graph/vulnerability/${encodeURIComponent(cve)}`));
});

// ---------------------------------------------------------------------
// BLAST RADIUS EXPLORER (ad-hoc: pick any package)
// ---------------------------------------------------------------------

route(/^\/blast-radius$/, async () => {
  const packages = await api('/api/packages');
  view.innerHTML = `
    <div class="page-eyebrow">What-if analysis</div>
    <h1 class="page-title">Blast radius explorer</h1>
    <p class="page-sub">Pick any package and see everything upstream of it — every package that transitively depends on it, and every internal project that would feel the impact if it were deprecated or compromised.</p>
    <div class="field-row">
      <div class="field">
        <label for="br-select">Package</label>
        <select id="br-select">
          <option value="">Choose a package…</option>
          ${packages.map((p) => `<option value="${esc(p.name)}">${esc(p.name)}</option>`).join('')}
        </select>
      </div>
      <button class="primary" id="br-run">Compute blast radius</button>
    </div>
    <div id="br-result"></div>
  `;
  document.getElementById('br-run').addEventListener('click', async () => {
    const pkg = document.getElementById('br-select').value;
    const out = document.getElementById('br-result');
    if (!pkg) { out.innerHTML = emptyBlock('Choose a package first.'); return; }
    out.innerHTML = skeleton(4);
    try {
      const result = await api(`/api/blast-radius/${encodeURIComponent(pkg)}`);
      out.innerHTML = `
        <div class="grid cols-2">
          <div class="card">
            <div class="panel-header"><h2>Dependent packages</h2><span class="count">${result.dependentPackageCount}</span></div>
            ${result.dependentPackages.length ? `<div class="path-chain">${result.dependentPackages.map((p) => `<a class="node" href="#/packages/${encodeURIComponent(p)}">${esc(p)}</a>`).join('')}</div>` : emptyBlock('No packages depend on this one.')}
          </div>
          <div class="card">
            <div class="panel-header"><h2>Exposed projects</h2><span class="count">${result.exposedProjectCount}</span></div>
            ${result.exposedProjects.length ? `<div class="path-chain">${result.exposedProjects.map((p) => `<a class="node" href="#/projects/${encodeURIComponent(p)}">${esc(p)}</a>`).join('')}</div>` : emptyBlock('No internal project currently depends on this package.')}
          </div>
        </div>
      `;
    } catch (err) {
      out.innerHTML = errorBlock(err.message);
    }
  });
});

// ---------------------------------------------------------------------
// MAINTAINER RISK
// ---------------------------------------------------------------------

route(/^\/maintainer-risk$/, async () => {
  const rows = await api('/api/maintainer-risk');
  view.innerHTML = `
    <div class="page-eyebrow">Single-point-of-failure analysis</div>
    <h1 class="page-title">Maintainer concentration risk</h1>
    <p class="page-sub">If a maintainer's publishing credentials were compromised, every project that transitively depends on anything they maintain is at risk. Ranked by projects exposed — a graph-native question that has no clean relational equivalent.</p>
    ${rows.length ? `
      <table>
        <thead><tr><th>Maintainer</th><th>Email</th><th>Packages maintained</th><th>Projects exposed</th></tr></thead>
        <tbody>
          ${rows.map((r) => `
            <tr>
              <td>${esc(r.maintainer)}</td>
              <td class="mono">${esc(r.email)}</td>
              <td class="mono">${r.packagesMaintained.map(esc).join(', ')}</td>
              <td><span class="badge ${r.projectsExposed >= 3 ? 'CRITICAL' : r.projectsExposed >= 1 ? 'MEDIUM' : 'LOW'}">${r.projectsExposed}</span></td>
            </tr>`).join('')}
        </tbody>
      </table>
    ` : emptyBlock('No maintainer risk data yet.', 'Run scripts/seed.py to load the demo dataset.')}
  `;
});

// ---------------------------------------------------------------------
// graph drawing (vis-network)
// ---------------------------------------------------------------------

function drawGraph(containerId, graph) {
  const container = document.getElementById(containerId);
  if (!container || typeof vis === 'undefined') return;
  if (!graph.nodes.length) {
    container.outerHTML = emptyBlock('No graph to show for this node yet.');
    return;
  }
  const colors = { Project: '#4fd1c5', Package: '#8592ac', Version: '#3a4a68', Vulnerability: '#e5484d' };
  const nodes = new vis.DataSet(graph.nodes.map((n) => ({
    id: n.id,
    label: n.label,
    shape: 'dot',
    size: n.group === 'Project' || n.group === 'Vulnerability' ? 16 : 10,
    color: { background: colors[n.group] || '#8592ac', border: '#0b1220' },
    font: { color: '#e8ecf3', size: 12, face: 'JetBrains Mono' },
  })));
  const edges = new vis.DataSet(graph.edges.map((e) => ({
    from: e.from, to: e.to,
    arrows: 'to',
    color: { color: '#24324a', highlight: '#4fd1c5' },
    width: 1,
  })));
  new vis.Network(container, { nodes, edges }, {
    physics: { stabilization: true, barnesHut: { gravitationalConstant: -6000, springLength: 110 } },
    interaction: { hover: true, tooltipDelay: 100 },
    layout: { improvedLayout: true },
  });
}
