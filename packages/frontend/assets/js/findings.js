// ─── FINDINGS PAGE ────────────────────────────────────────────────────────────

let _allFindings = [];

function buildFindingCard(f) {
    const impacts = f.quantified_impact || {};
    const hasImpact = Object.keys(impacts).length > 0;

    const data = typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA : {};
    const pending = data.summary?.pending_hitl_actions || [];
    const isPending = pending.some(p => String(p.finding_id) === String(f.finding_id));

    const evidenceHtml = (f.evidence_path || []).map((e, i, arr) => `
        <span>${e}</span>${i < arr.length - 1 ? '<span class="arrow">→</span>' : ''}
    `).join('');

    return `
    <div class="finding-card severity-${f.severity} ${isPending ? 'pending-approval' : ''}" 
         data-agent="${f.agent_source}" data-severity="${f.severity}"
         onclick="openFindingModal('${f.finding_id}')" style="cursor:pointer">
        <div class="card-header">
            ${severityBadge(f.severity)}
            <span class="badge badge-${f.agent_source}">${f.agent_source}</span>
            ${isPending ? '<span class="sfr-tag pending" style="margin-left:auto;">⏳ Pending Approval</span>' : ''}
            ${f.cis_rule    ? `<span class="badge badge-cis">${f.cis_rule}</span>` : ''}
            ${f.mitre_technique ? `<span class="badge badge-mitre">${f.mitre_technique}</span>` : ''}
            ${f.agent_source === 'secops' ? `<span class="badge badge-owasp">OWASP</span>` : ''}
        </div>
        <div class="card-body">
            <p class="plain-english">${f.plain_english}</p>
            <span class="affected-node">${f.affected_node}</span>
        </div>
        <div class="card-footer">
            ${confidenceBar(f.confidence)}
            <div style="display:flex;gap:8px;align-items:center;font-size:12px;">
                ${refLinks(f)}
            </div>
            <button class="accordion-toggle" onclick="toggleAccordion(this)">▼ Show Details</button>
        </div>
        <div class="accordion-content">
            <strong>Technical Description:</strong><br>${f.description}<br><br>
            <strong>Evidence Path:</strong>
            <div class="evidence-path">${evidenceHtml}</div>
            ${hasImpact ? `
            <br><strong>Quantified Impact:</strong><br>
            Monthly Cost: <b>${usd(impacts.monthly_cost_usd)}</b> &nbsp;|&nbsp;
            Wasted: <b>${usd(impacts.wasted_cost_usd)}</b> &nbsp;|&nbsp;
            Resize Savings: <b>${usd(impacts.resize_savings_usd_month)}</b><br>
            CO₂/month: <b>${co2(impacts.kg_co2_per_month)}</b> &nbsp;|&nbsp;
            Grid Intensity: <b>${impacts.region_carbon_intensity} gCO₂/kWh</b>
            ` : ''}
            <br><br>
            ${f.cis_rule ? `<a class="ext-link" href="${CIS_URL}" target="_blank">→ View CIS Benchmark</a>&nbsp;&nbsp;` : ''}
            ${f.mitre_technique ? `<a class="ext-link" href="${MITRE_URL}${f.mitre_technique}/" target="_blank">→ View MITRE ${f.mitre_technique}</a>&nbsp;&nbsp;` : ''}
            ${f.agent_source === 'secops' ? `<a class="ext-link" href="${OWASP_URL}" target="_blank">→ OWASP Cloud Security</a>` : ''}
        </div>
    </div>`;

    if (window.lucide) setTimeout(lucide.createIcons, 0);
    return card;
}

function renderFindings(findings) {
    const grid = document.getElementById('findings-grid');
    if (!grid) return;
    if (!findings.length) {
        grid.innerHTML = '<div class="empty-state"><h3>No findings match your filters.</h3></div>';
        return;
    }
    grid.innerHTML = findings.map(buildFindingCard).join('');
    if (window.lucide) lucide.createIcons();
}

function applyFilters() {
    const agent    = document.getElementById('filter-agent')?.value    || 'all';
    const severity = document.getElementById('filter-severity')?.value || 'all';
    const search   = (document.getElementById('filter-search')?.value  || '').toLowerCase();

    const filtered = _allFindings.filter(f => {
        const matchAgent    = agent    === 'all' || f.agent_source === agent;
        const matchSeverity = severity === 'all' || f.severity     === severity;
        const matchSearch   = !search  || f.plain_english.toLowerCase().includes(search)
                                       || f.affected_node.toLowerCase().includes(search);
        return matchAgent && matchSeverity && matchSearch;
    });

    renderFindings(filtered);
    document.getElementById('findings-count').textContent = `${filtered.length} finding(s)`;
}

function initFindings() {
    const data = typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA : {};
    _allFindings = [...(data.findings || [])].sort((a, b) =>
        (SEVERITY_ORDER[a.severity] || 9) - (SEVERITY_ORDER[b.severity] || 9)
    );

    document.getElementById('findings-count').textContent = `${_allFindings.length} finding(s)`;
    renderFindings(_allFindings);

    document.getElementById('filter-agent')?.addEventListener('change', applyFilters);
    document.getElementById('filter-severity')?.addEventListener('change', applyFilters);
    document.getElementById('filter-search')?.addEventListener('input', applyFilters);
}

document.addEventListener('page:loaded', e => {
    if (e.detail.page === 'findings') initFindings();
});
