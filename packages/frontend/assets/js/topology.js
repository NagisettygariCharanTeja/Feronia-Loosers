// ─── TOPOLOGY MAP PAGE ───────────────────────────────────────────────────────
// Uses vis.js Network (loaded from CDN in index.html)
// Data source: INFRASTRUCTURE_DATA (Option B — static mock)
// To switch to Option A: replace the data source with fetch('/api/infrastructure')

const NODE_TYPE_COLORS = {
    ec2_instance:   { bg: 'rgba(34,197,94,0.9)', border: '#22c55e', label: 'EC2' },
    s3_bucket:      { bg: 'rgba(13,148,136,0.9)', border: '#0d9488', label: 'S3' },
    rds_database:   { bg: 'rgba(168,85,247,0.9)', border: '#a855f7', label: 'RDS' },
    security_group: { bg: 'rgba(249,115,22,0.9)', border: '#f97316', label: 'SG' },
    iam_role:       { bg: 'rgba(253,224,71,0.9)', border: '#fde047', label: 'IAM' },
    load_balancer:  { bg: 'rgba(236,72,153,0.9)', border: '#ec4899', label: 'LB' },
    ebs_volume:     { bg: 'rgba(148,163,184,0.9)', border: '#94a3b8', label: 'EBS' },
    vpc:            { bg: 'rgba(56,189,248,0.9)', border: '#38bdf8', label: 'VPC' },
};

const SEVERITY_HEX = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#fde047',
    low: '#22c55e'
};

const RELATION_LABELS = {
    protects:          'protects',
    connects_to:       'connects_to',
    has_permission:    'has_permission',
    attached_to:       'attached_to',
    routes_traffic_to: 'routes_traffic_to',
};

function initTopology() {
    const infra    = typeof INFRASTRUCTURE_DATA !== 'undefined' ? INFRASTRUCTURE_DATA : {};
    const findings = (typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA.findings : null) || [];
    const resources    = infra.resources    || [];
    const relationships = infra.relationships || [];

    const affectedMap = {};
    findings.forEach(f => {
        const cur = affectedMap[f.affected_node];
        if (!cur || (SEVERITY_ORDER[f.severity] || 9) < (SEVERITY_ORDER[cur] || 9)) {
            affectedMap[f.affected_node] = f.severity;
        }
    });

    const nodes = new vis.DataSet(resources.map(r => {
        const scheme = NODE_TYPE_COLORS[r.type] || { bg: 'rgba(134,239,172,0.9)', border: '#86efac', label: r.type };
        const sev = affectedMap[r.id];
        const isAffected = !!sev;
        
        let radius = 18;
        if (r.type === 'vpc') radius = 28;
        else if (r.type === 'eks_cluster' || r.type === 'rds_database') radius = 22;

        return {
            id:    r.id,
            label: `${scheme.label}: ${r.name || r.id}`,
            color: {
                background: scheme.bg,
                border:     isAffected ? SEVERITY_HEX[sev] : scheme.border,
                highlight:  { background: scheme.bg, border: isAffected ? SEVERITY_HEX[sev] : '#fff' },
            },
            borderWidth: isAffected ? 5 : 0,
            font:        { face: '"Space Grotesk", sans-serif', size: 12, color: '#f0fdf4', multi: false },
            shape:       'dot',
            size:        radius,
            _raw:        r,  
        };
    }));

    const edges = new vis.DataSet(relationships.map((rel, i) => ({
        id:     i,
        from:   rel.source,
        to:     rel.target,
        label:  RELATION_LABELS[rel.relation] || rel.relation,
        arrows: 'to',
        font:   { size: 11, align: 'middle', color: '#ffffff', face: '"Space Mono", monospace', strokeWidth: 3, strokeColor: '#061209' },
        color:  { color: 'rgba(34,197,94,0.3)', highlight: 'rgba(34,197,94,0.8)' },
    })));

    const container = document.getElementById('topology-canvas');
    const network = new vis.Network(container, { nodes, edges }, {
        layout:  { improvedLayout: true },
        physics: { 
            stabilization: { iterations: 150 },
            barnesHut: { gravitationalConstant: -3000, centralGravity: 0.1, springLength: 150 }
        },
        edges: {
            smooth: { type: 'continuous' },
        },
        interaction: { tooltipDelay: 200, hover: true },
    });

    // ── Node click → detail panel ─────────────────────────────────────────────
    network.on('click', params => {
        if (!params.nodes.length) return;
        const nodeId  = params.nodes[0];
        const nodeData = nodes.get(nodeId);
        openDetailPanel(nodeId, nodeData._raw, findings);
    });

    // Close panel on background click
    network.on('click', params => {
        if (!params.nodes.length) {
            document.getElementById('node-detail-panel')?.classList.remove('open');
        }
    });
}

function openDetailPanel(nodeId, resource, findings) {
    const panel = document.getElementById('node-detail-panel');
    if (!panel) return;

    const nodeFindings = findings.filter(f => f.affected_node === nodeId);

    // Build property rows (skip internal keys)
    const skipKeys = ['tags'];
    const props = Object.entries(resource)
        .filter(([k]) => !skipKeys.includes(k) && k !== 'id')
        .map(([k, v]) => `
            <div class="prop-row">
                <span class="prop-label">${k}</span>
                <span class="prop-value">${v === null ? '—' : v === true ? '✓ Yes' : v === false ? '✗ No' : v}</span>
            </div>`).join('');

    const findingsHtml = nodeFindings.length
        ? nodeFindings.map(f => `
            <div class="mini-finding">
                ${severityBadge(f.severity)}&nbsp;
                <strong>${actionToLabel(f.recommended_action)}</strong><br>
                <span style="font-size:11px;">${f.plain_english}</span>
            </div>`).join('')
        : `<p style="font-size:12px;color:#aaa;">No findings for this resource.</p>`;

    panel.innerHTML = `
        <button class="panel-close" onclick="document.getElementById('node-detail-panel').classList.remove('open')">✕</button>
        <p style="font-size:11px;color:var(--text-secondary);margin-bottom:4px;">${resource.type}</p>
        <h3>${resource.name || resource.id}</h3>
        <p style="font-family:monospace;font-size:11px;color:#aaa;margin-bottom:16px;">${resource.id}</p>
        ${props}
        <div class="panel-findings">
            <h4>Associated Findings (${nodeFindings.length})</h4>
            ${findingsHtml}
        </div>`;

    panel.classList.add('open');
}

document.addEventListener('page:loaded', e => {
    if (e.detail.page === 'topology') initTopology();
});
