// ─── DASHBOARD, SCAN, AND PIPELINE FLOW ─────────────────────────────────────

window.DASHBOARD_FILTER = window.DASHBOARD_FILTER || 'all';
window.SCAN_LOGS        = window.SCAN_LOGS        || [];

// ─── Log formatting ──────────────────────────────────────────────────────────
// Maps SSE node names → descriptive agent-prefixed log messages + CSS type.

function buildLogEntry(data) {
    const node = data.node || '';
    const map = {
        'ingest':          { msg: '[System] Ingesting CloudTrail & Config logs',                         logType: 'system'   },
        'build_graph':     { msg: '[System] Building infrastructure topology graph',                     logType: 'system'   },
        'router':          { msg: '[Router] Routing to SecOps & GreenOps agents',                       logType: 'system'   },
        'secops_agent':    { msg: '[SecOps] Running CIS AWS Foundations v3.0 & MITRE ATT\u0026CK',      logType: 'error'    },
        'greenops_agent':  { msg: '[GreenOps] Scanning zombie resources & carbon intensity',             logType: 'success'  },
        'gatekeeper':      { msg: 'Gatekeeper: Validating findings against infrastructure graph',        logType: 'system'   },
        'synthesizer':     { msg: 'Synthesizer: Building prioritized action plan',                       logType: 'system'   },
        'hitl_gate':       { msg: 'Gatekeeper: HITL gate reached \u2014 awaiting human approval',       logType: 'approval' },
        'execute_actions': { msg: '\u2713 Executing approved actions against AWS',                       logType: 'success'  },
        'final_report':    { msg: '\u2713 Generating final report',                                      logType: 'success'  },
    };
    if (node && map[node]) return map[node];
    return { msg: data.status || 'Pipeline update', logType: 'system' };
}

// ─── Sidebar helpers ─────────────────────────────────────────────────────────

function dashboardFindings() {
    const data = typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA : {};
    const findings = data.findings || [];
    if (window.DASHBOARD_FILTER === 'all') return findings;
    return findings.filter(f => f.agent_source === window.DASHBOARD_FILTER);
}

function setDashboardFilter(agent) {
    window.DASHBOARD_FILTER = agent;
    document.querySelectorAll('.filter-pill[data-agent]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.agent === agent);
    });
    renderSidebarFindings();
}

function getPendingFindingIds() {
    const data = typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA : {};
    const pending = data.summary?.pending_hitl_actions || [];
    return new Set(pending.map(p => String(p.finding_id)));
}

function renderSidebarFindings() {
    const list = document.getElementById('sidebar-findings');
    if (!list) return;

    const pendingIds = getPendingFindingIds();
    const findings = [...dashboardFindings()].sort((a, b) =>
        (SEVERITY_ORDER[a.severity] || 9) - (SEVERITY_ORDER[b.severity] || 9)
    );

    if (!findings.length) {
        list.innerHTML = '<div class="empty-state" style="padding:40px 14px;"><h3>No findings</h3><p>Run a scan to populate this dashboard.</p></div>';
        return;
    }

    list.innerHTML = findings.map(f => {
        const isPending = pendingIds.has(String(f.finding_id));
        const pendingTag = isPending ? '<span class="sfr-tag pending">\u23f3 Pending Approval</span>' : '';
        const title = f.description || actionToLabel(f.recommended_action || '');
        return `
        <div class="sidebar-finding-row${isPending ? ' pending-approval' : ''}"
             onclick="openFindingModal('${f.finding_id}')"
             id="sfr-${f.finding_id}">
            <div class="sfr-topline">
                ${severityBadge(f.severity)}
                <span class="badge badge-${f.agent_source}">${f.agent_source}</span>
                ${pendingTag}
            </div>
            <div class="sfr-title">${title}</div>
            <div class="sfr-resource">${f.affected_node}</div>
        </div>`;
    }).join('');
}

// ─── Finding detail modal ────────────────────────────────────────────────────

function openFindingModal(findingId) {
    const data   = typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA : {};
    const findings   = data.findings   || [];
    const plan       = data.action_plan || [];
    const pendingHitl = data.summary?.pending_hitl_actions || [];

    const finding = findings.find(f => f.finding_id === findingId);
    if (!finding) return;

    // ── Approval check: look up ActionPlanStep.requires_approval by finding_id
    // (per schemas/models.py: requires_approval lives on ActionPlanStep, not Finding)
    const step = plan.find(s => String(s.finding_id) === String(findingId));
    const isPending = !!(
        step &&
        step.requires_approval &&
        pendingHitl.some(p => String(p.finding_id) === String(findingId))
    );

    const overlay = document.getElementById('finding-modal-overlay');
    const modal   = document.getElementById('finding-modal');
    if (!overlay || !modal) return;

    // Evidence path chain
    const evidenceHtml = (finding.evidence_path || []).map((e, i, arr) =>
        `<span>${e}</span>${i < arr.length - 1 ? '<span class="arrow">\u2192</span>' : ''}`
    ).join('');

    // MITRE + CIS meta row (only if fields exist — no CVSS per design spec §5)
    const hasMeta = finding.mitre_technique || finding.cis_rule;
    const metaHtml = hasMeta ? `
        <div class="finding-meta-row">
            ${finding.mitre_technique ? `
                <div class="finding-meta-cell finding-mitre-cell">
                    <span>MITRE ATT&amp;CK</span>
                    <strong>
                        <a href="https://attack.mitre.org/techniques/${finding.mitre_technique}/"
                           target="_blank" rel="noopener"
                           style="color:inherit;text-decoration:none;">${finding.mitre_technique}</a>
                    </strong>
                </div>` : ''}
            ${finding.cis_rule ? `
                <div class="finding-meta-cell">
                    <span>CIS Control</span>
                    <strong>${finding.cis_rule}</strong>
                </div>` : ''}
        </div>` : '';

    // Destructive-action warning — only when step actually requires approval
    const warningHtml = isPending ? `
        <div class="finding-modal-warning">
            &#9888;&nbsp; This is a destructive action and requires your explicit approval before execution.
        </div>` : '';

    // Approve / Deny footer — only for pending destructive steps
    const footerHtml = isPending ? `
        <div class="finding-modal-footer">
            <button class="btn-cancel" onclick="closeFindingModal()">Cancel</button>
            <button class="btn-reject" id="fm-deny-btn"
                    onclick="submitApprovalDecision('reject', '${finding.finding_id}')">Deny</button>
            <button class="btn-approve" id="fm-approve-btn"
                    style="animation:glow-green 2.5s ease-in-out infinite;"
                    onclick="submitApprovalDecision('approve', '${finding.finding_id}')">Approve &amp; Execute</button>
        </div>` : '';

    const actionLabel = step
        ? (step.human_label || actionToLabel(finding.recommended_action))
        : actionToLabel(finding.recommended_action);

    modal.innerHTML = `
        <div class="finding-modal-header">
            <div class="finding-modal-badges">
                ${severityBadge(finding.severity)}
                <span class="badge badge-${finding.agent_source}">${finding.agent_source}</span>
            </div>
            <button class="finding-modal-close" onclick="closeFindingModal()" aria-label="Close">&#x2715;</button>
        </div>

        <div class="finding-modal-title" id="finding-modal-title">${finding.description || 'Finding Detail'}</div>
        <code class="finding-modal-resource">${finding.affected_node}</code>

        <div class="finding-modal-section">
            <div class="finding-modal-section-label">What's happening</div>
            <p>${finding.plain_english}</p>
        </div>

        <div class="finding-modal-section">
            <div class="finding-modal-section-label">Recommended Action</div>
            <p>${actionLabel}</p>
        </div>

        ${(finding.evidence_path || []).length ? `
        <div class="finding-modal-section">
            <div class="finding-modal-section-label">Evidence Path</div>
            <div class="evidence-chain">${evidenceHtml}</div>
        </div>` : ''}

        ${metaHtml}
        ${warningHtml}
        <p class="modal-error" id="finding-modal-error"></p>
        ${footerHtml}
    `;

    overlay.classList.remove('hidden');
    // Close on backdrop click
    overlay.onclick = e => { if (e.target === overlay) closeFindingModal(); };
}

function closeFindingModal() {
    const overlay = document.getElementById('finding-modal-overlay');
    if (overlay) overlay.classList.add('hidden');
}

async function submitApprovalDecision(decision, findingId) {
    const buttons = document.querySelectorAll('#finding-modal button');
    buttons.forEach(b => b.disabled = true);
    const errEl = document.getElementById('finding-modal-error');
    if (errEl) errEl.textContent = '';

    try {
        const res = await fetch('/api/pipeline/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, finding_id: findingId }),
        });
        if (res.status === 409) {
            if (errEl) {
                errEl.style.color = 'var(--muted)';
                errEl.textContent = 'This action has already been resolved.';
            }
            const footer = document.querySelector('.finding-modal-footer');
            if (footer) footer.style.display = 'none';
            if (typeof fetchGlobalData === 'function') await fetchGlobalData();
            setTimeout(() => {
                closeFindingModal();
                if (document.querySelector('.dashboard-v2')) initDashboard();
                if (document.querySelector('.findings-grid') && typeof initFindings === 'function') initFindings();
            }, 1500);
            return;
        }
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || 'Approval request failed');
        }
        const payload = await res.json();
        if (payload.dashboard) {
            window.DASHBOARD_DATA = payload.dashboard;
        } else if (typeof fetchGlobalData === 'function') {
            await fetchGlobalData();
        }
        closeFindingModal();
        if (document.querySelector('.dashboard-v2')) initDashboard();
        if (document.querySelector('.findings-grid') && typeof initFindings === 'function') initFindings();
    } catch (err) {
        if (errEl) errEl.textContent = err.message;
        buttons.forEach(b => b.disabled = false);
    }
}

// ─── Dashboard graph canvas (settled state) ──────────────────────────────────

let _dashGraphAnim   = null;
let _dashGraphActive = false;

function initDashboardGraph() {
    const cv = document.getElementById('feronia-graph-cv');
    if (!cv) return;

    _dashGraphActive = false;
    if (_dashGraphAnim) { cancelAnimationFrame(_dashGraphAnim); _dashGraphAnim = null; }

    requestAnimationFrame(() => {
        const W = cv.offsetWidth;
        const H = cv.offsetHeight;
        if (!W || !H) { setTimeout(initDashboardGraph, 80); return; }
        cv.width  = W * window.devicePixelRatio;
        cv.height = H * window.devicePixelRatio;
        const ctx = cv.getContext('2d');
        ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

        const infra    = typeof INFRASTRUCTURE_DATA !== 'undefined' ? INFRASTRUCTURE_DATA : {};
        const findings = (typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA.findings : null) || [];
        const resources = infra.resources || [];
        const relationships = infra.relationships || [];

        const affectedMap = {};
        findings.forEach(f => {
            const cur = affectedMap[f.affected_node];
            if (!cur || (SEVERITY_ORDER[f.severity] || 9) < (SEVERITY_ORDER[cur] || 9)) {
                affectedMap[f.affected_node] = f.severity;
            }
        });

        const typeColors = {
            ec2_instance:   [34, 197, 94],
            s3_bucket:      [13, 148, 136],
            rds_database:   [168, 85, 247],
            security_group: [249, 115, 22],
            iam_role:       [253, 224, 71],
            load_balancer:  [236, 72, 153],
            ebs_volume:     [148, 163, 184],
            vpc:            [56, 189, 248]
        };

        function severityColor(sev, base) {
            if (sev === 'critical') return [239, 68, 68];
            if (sev === 'high')     return [249, 115, 22];
            if (sev === 'medium')   return [253, 224, 71];
            if (sev)                return [34, 197, 94];
            return base;
        }

        let nodes = [];
        let nodeMap = {};

        if (resources.length) {
            resources.forEach(r => {
                const t = r.type || 'unknown';
                const sev = affectedMap[r.id] || null;
                const base = typeColors[t] || [134, 239, 172];
                
                let radius = 12;
                if (t === 'vpc') radius = 28;
                else if (t === 'eks_cluster' || t === 'rds_database') radius = 22;
                else if (t === 'ec2_instance' || t === 'iam_role' || t === 'security_group' || t === 'load_balancer') radius = 18;

                let abbr = t.split('_').map(w => w[0]).join('').substring(0, 2).toUpperCase();
                if (abbr.length < 2) abbr = t.substring(0, 2).toUpperCase();

                const prefix = t.split('_')[0].toUpperCase();
                const nameStr = r.name || r.id;
                const shortLabel = `${prefix}: ${nameStr.length > 14 ? nameStr.substring(0,12)+'...' : nameStr}`;

                const n = {
                    id: r.id, label: r.name || r.id, type: t, region: r.region || '',
                    x: W / 2 + (Math.random() - 0.5) * W * 0.5,
                    y: H / 2 + (Math.random() - 0.5) * H * 0.5,
                    vx: 0, vy: 0,
                    r: radius,
                    color: severityColor(sev, base),
                    severity: sev,
                    phase: Math.random() * Math.PI * 2,
                    abbr, shortLabel
                };
                nodes.push(n);
                nodeMap[r.id] = n;
            });
        } else {
            const types = ['ec2_instance', 's3_bucket', 'iam_role', 'security_group', 'rds_database'];
            for (let i = 0; i < 20; i++) {
                const t = types[i % types.length];
                let abbr = t.split('_').map(w => w[0]).join('').substring(0, 2).toUpperCase();
                const n = {
                    id: `p${i}`, label: `mock-${i}`, type: t, region: '',
                    x: W / 2 + (Math.random() - 0.5) * W * 0.5,
                    y: H / 2 + (Math.random() - 0.5) * H * 0.5,
                    vx: 0, vy: 0, r: 10, color: [34, 197, 94], severity: null, phase: Math.random() * Math.PI * 2,
                    abbr, shortLabel: `${t.split('_')[0].toUpperCase()}: mock-${i}`
                };
                nodes.push(n);
                nodeMap[n.id] = n;
            }
        }

        let edges = [];
        relationships.forEach(rel => {
            if (nodeMap[rel.source] && nodeMap[rel.target]) {
                edges.push({ source: nodeMap[rel.source], target: nodeMap[rel.target], type: rel.type });
            }
        });

        let hoveredNode = null;
        cv.onmousemove = e => {
            const rect = cv.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;
            hoveredNode = null;
            for (const n of nodes) {
                const dx = n.x - mx, dy = n.y - my;
                if (dx * dx + dy * dy < (n.r + 10) * (n.r + 10)) { hoveredNode = n; break; }
            }
            cv.style.cursor = hoveredNode ? 'pointer' : 'default';
        };
        cv.onmouseleave = () => { hoveredNode = null; cv.style.cursor = 'default'; };

        const kRepel = 2500;
        const kSpring = 0.04;
        const springLength = 140;
        const kCenter = 0.003;
        const damping = 0.85;

        _dashGraphActive = true;

        (function drawFrame() {
            if (!_dashGraphActive) return;
            _dashGraphAnim = requestAnimationFrame(drawFrame);
            
            // Physics step
            for(let i=0; i<nodes.length; i++) {
                for(let j=i+1; j<nodes.length; j++) {
                    let dx = nodes[i].x - nodes[j].x;
                    let dy = nodes[i].y - nodes[j].y;
                    let distsq = dx*dx + dy*dy;
                    if(distsq > 0.1 && distsq < 30000) {
                        let dist = Math.sqrt(distsq);
                        let f = kRepel / distsq;
                        let fx = (dx / dist) * f;
                        let fy = (dy / dist) * f;
                        nodes[i].vx += fx; nodes[i].vy += fy;
                        nodes[j].vx -= fx; nodes[j].vy -= fy;
                    }
                }
            }
            for(let e of edges) {
                let dx = e.target.x - e.source.x;
                let dy = e.target.y - e.source.y;
                let dist = Math.sqrt(dx*dx + dy*dy) || 0.1;
                let f = (dist - springLength) * kSpring;
                let fx = (dx / dist) * f;
                let fy = (dy / dist) * f;
                e.source.vx += fx; e.source.vy += fy;
                e.target.vx -= fx; e.target.vy -= fy;
            }
            for(let n of nodes) {
                n.vx += (W/2 - n.x) * kCenter;
                n.vy += (H/2 - n.y) * kCenter;
                n.vx *= damping;
                n.vy *= damping;
                n.x += n.vx;
                n.y += n.vy;
            }

            ctx.clearRect(0, 0, W, H);

            // Draw real edges
            if (edges.length) {
                ctx.beginPath();
                for (let e of edges) {
                    ctx.moveTo(e.source.x, e.source.y);
                    ctx.lineTo(e.target.x, e.target.y);
                }
                ctx.strokeStyle = 'rgba(34,197,94,0.18)';
                ctx.lineWidth = 1.2;
                ctx.stroke();
            }

            // Draw nodes
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            
            for (const n of nodes) {
                n.phase += 0.022;
                const pulse = Math.sin(n.phase) * 0.5 + 0.5;
                const [dr, dg, db] = n.color;
                const isHovered = n === hoveredNode;
                const nodeR = n.r * (isHovered ? 1.4 : 1);

                // Glow for affected nodes
                if (n.severity) {
                    const gr = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, nodeR * 5);
                    gr.addColorStop(0, `rgba(${dr},${dg},${db},${pulse * 0.35})`);
                    gr.addColorStop(1, `rgba(${dr},${dg},${db},0)`);
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, nodeR * 5, 0, Math.PI * 2);
                    ctx.fillStyle = gr;
                    ctx.fill();
                }

                ctx.beginPath();
                ctx.arc(n.x, n.y, nodeR, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(${dr},${dg},${db},.9)`;
                ctx.fill();

                // 2-char type abbreviation
                ctx.fillStyle = '#050f0a';
                ctx.font = 'bold 11px "Space Mono", monospace';
                ctx.fillText(n.abbr, n.x, n.y);

                // Persistent small label below node
                if (!isHovered) {
                    ctx.fillStyle = 'rgba(134,239,172,.8)';
                    ctx.font = '11px "Space Grotesk", sans-serif';
                    ctx.fillText(n.shortLabel, n.x, n.y + nodeR + 14);
                }
            }

            // Tooltip on top
            if (hoveredNode && hoveredNode.label) {
                const n = hoveredNode;
                const nodeR = n.r * 1.4;
                const lines = [
                    n.type.replace(/_/g, ' '),
                    n.label,
                    n.severity ? `Issue: ${n.severity}` : 'Healthy',
                    n.region || null,
                ].filter(Boolean);

                const pad = 10, lineH = 16;
                const boxW = Math.max(...lines.map(l => l.length)) * 6.5 + pad * 2;
                const boxH = lines.length * lineH + pad * 2;
                let tx = n.x + nodeR + 12;
                let ty = n.y - boxH / 2;
                if (tx + boxW > W - 4) tx = n.x - nodeR - 12 - boxW;
                ty = Math.max(4, Math.min(ty, H - boxH - 4));

                ctx.fillStyle = 'rgba(5,15,10,.94)';
                ctx.strokeStyle = 'rgba(34,197,94,.4)';
                ctx.lineWidth = 1;
                ctx.beginPath();
                if (ctx.roundRect) ctx.roundRect(tx, ty, boxW, boxH, 6);
                else ctx.rect(tx, ty, boxW, boxH);
                ctx.fill();
                ctx.stroke();

                ctx.font = '10px "Space Mono", monospace';
                ctx.textAlign = 'left';
                lines.forEach((line, idx) => {
                    if (idx === 0)          ctx.fillStyle = 'rgba(134,239,172,.65)';
                    else if (idx === 1)     ctx.fillStyle = '#f0fdf4';
                    else if (line.startsWith('Issue:')) {
                        ctx.fillStyle = n.severity === 'critical' ? '#fca5a5'
                                      : n.severity === 'high'     ? '#fdba74'
                                      :                             '#86efac';
                    } else                  ctx.fillStyle = 'rgba(134,239,172,.5)';
                    ctx.fillText(line, tx + pad, ty + pad + lineH * idx + 11);
                });
            }
        })();
    });
}

// ─── Scanning graph canvas (animated node-by-node reveal) ────────────────────

let _scanGraphAnim   = null;
let _scanGraphActive = false;

function initScanningGraph() {
    const cv = document.getElementById('feronia-graph-cv');
    if (!cv) return;

    _scanGraphActive = false;
    if (_scanGraphAnim) { cancelAnimationFrame(_scanGraphAnim); _scanGraphAnim = null; }

    const W = cv.offsetWidth  || cv.parentElement.clientWidth  || 800;
    const H = cv.offsetHeight || cv.parentElement.clientHeight || 600;
    if (!W || !H) { setTimeout(initScanningGraph, 80); return; }
    cv.width  = W;
    cv.height = H;
    const ctx = cv.getContext('2d');

    const infra    = typeof INFRASTRUCTURE_DATA !== 'undefined' ? INFRASTRUCTURE_DATA : {};
    const findings = (typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA.findings : null) || [];
    let   resources = (infra.resources || []).slice(0, 60);

    // Severity map
    const affectedMap = {};
    findings.forEach(f => {
        const cur = affectedMap[f.affected_node];
        if (!cur || (SEVERITY_ORDER[f.severity] || 9) < (SEVERITY_ORDER[cur] || 9)) {
            affectedMap[f.affected_node] = f.severity;
        }
    });

    const typeColors = {
        ec2_instance:   [34, 197, 94],
        s3_bucket:      [13, 148, 136],
        rds_database:   [168, 85, 247],
        security_group: [249, 115, 22],
        iam_role:       [253, 224, 71],
        load_balancer:  [236, 72, 153],
        ebs_volume:     [148, 163, 184],
    };

    // Fallback generic nodes if no real infrastructure yet
    if (!resources.length) {
        const fallbackTypes = ['ec2_instance', 's3_bucket', 'rds_database', 'security_group', 'iam_role'];
        for (let i = 0; i < 28; i++) {
            resources.push({ id: `node-${i}`, type: fallbackTypes[i % fallbackTypes.length], name: `resource-${i}` });
        }
    }

    // Pre-compute ring target positions grouped by type
    const groups = {};
    resources.forEach(r => { const t = r.type || 'unknown'; (groups[t] = groups[t] || []).push(r); });
    const groupKeys = Object.keys(groups);
    const cx = W / 2, cy = H / 2;
    const ringR = Math.min(W, H) * 0.28;
    const targets = {};

    groupKeys.forEach((type, gi) => {
        const gAngle = (gi / groupKeys.length) * Math.PI * 2 - Math.PI / 2;
        const gx = cx + Math.cos(gAngle) * ringR;
        const gy = cy + Math.sin(gAngle) * ringR;
        const spread = groups[type].length > 1 ? 36 : 0;
        groups[type].forEach((r, ni) => {
            const lAngle = (ni / Math.max(1, groups[type].length)) * Math.PI * 2;
            targets[r.id] = { tx: gx + Math.cos(lAngle) * spread, ty: gy + Math.sin(lAngle) * spread };
        });
    });

    const activeNodes = [];
    let   revealIdx   = 0;

    function revealNext() {
        if (!_scanGraphActive || revealIdx >= resources.length) return;
        const r   = resources[revealIdx++];
        const tgt = targets[r.id] || { tx: cx, ty: cy };
        const sev = affectedMap[r.id] || null;
        const base = typeColors[r.type] || [134, 239, 172];

        activeNodes.push({
            x: tgt.tx + (Math.random() - 0.5) * 100,
            y: tgt.ty + (Math.random() - 0.5) * 100,
            tx: tgt.tx, ty: tgt.ty,
            r: 4.5 + Math.random() * 3,
            color: sev === 'critical' ? [239, 68, 68]
                 : sev === 'high'     ? [249, 115, 22]
                 : sev               ? [34, 197, 94]
                 : base,
            severity: sev, phase: Math.random() * Math.PI * 2, alpha: 0,
        });
        if (revealIdx < resources.length) setTimeout(revealNext, 280);
    }

    _scanGraphActive = true;
    revealNext();

    (function drawFrame() {
        if (!_scanGraphActive) return;
        _scanGraphAnim = requestAnimationFrame(drawFrame);
        ctx.clearRect(0, 0, W, H);

        // Edges between nearby nodes
        for (let i = 0; i < activeNodes.length; i++) {
            for (let j = i + 1; j < activeNodes.length; j++) {
                const a = activeNodes[i], b = activeNodes[j];
                const dx = a.x - b.x, dy = a.y - b.y;
                const d2 = dx * dx + dy * dy;
                if (d2 < 85 * 85) {
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                    ctx.strokeStyle = `rgba(34,197,94,${0.1 * (1 - d2 / (85 * 85)) * Math.min(a.alpha, b.alpha)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }

        // Nodes
        for (const n of activeNodes) {
            // Ease toward target, fade in
            n.x    += (n.tx - n.x) * 0.06;
            n.y    += (n.ty - n.y) * 0.06;
            n.alpha = Math.min(1, n.alpha + 0.06);
            n.phase += 0.04;
            const pulse = Math.sin(n.phase) * 0.5 + 0.5;
            const [dr, dg, db] = n.color;

            if (n.severity) {
                const gr = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 6);
                gr.addColorStop(0, `rgba(${dr},${dg},${db},${pulse * 0.3 * n.alpha})`);
                gr.addColorStop(1, `rgba(${dr},${dg},${db},0)`);
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.r * 6, 0, Math.PI * 2);
                ctx.fillStyle = gr;
                ctx.fill();
            }

            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${dr},${dg},${db},${0.85 * n.alpha})`;
            ctx.fill();
        }
    })();
}

// ─── Dashboard init ──────────────────────────────────────────────────────────

function initDashboard() {
    const data    = typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA : {};
    const findings = data.findings    || [];
    const plan     = data.action_plan || [];
    const summary  = data.summary     || {};

    const critical  = findings.filter(f => f.severity === 'critical').length;
    const high      = findings.filter(f => f.severity === 'high').length;
    const savings   = summary.total_savings_usd_month
                    ?? plan.reduce((s, p) => s + (p.savings_usd_month || 0), 0);
    const co2Total  = summary.total_co2_reduction_kg
                    ?? plan.reduce((s, p) => s + (p.co2_reduction_kg  || 0), 0);
    const pipeState = summary.pipeline_status || (findings.length ? 'complete' : 'idle');

    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setText('db-critical',      critical || '0');
    setText('db-high',          high || '0');
    setText('db-savings',       usd(savings));
    setText('db-co2',           `${Number(co2Total).toFixed(1)} kg`);
    setText('db-pipeline-state', pipeState);

    // Status dot color
    const dot = document.getElementById('db-status-dot');
    if (dot) {
        dot.style.background = pipeState === 'approval_required' ? 'var(--orange)'
                             : pipeState === 'complete'           ? 'var(--green)'
                             : 'rgba(134,239,172,.4)';
    }

    document.querySelectorAll('.filter-pill[data-agent]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.agent === window.DASHBOARD_FILTER);
    });

    renderSidebarFindings();
    initDashboardGraph();
    if (window.lucide) lucide.createIcons();
}

// ─── Landing init ────────────────────────────────────────────────────────────

function initLanding() {
    const data    = typeof DASHBOARD_DATA !== 'undefined' ? DASHBOARD_DATA : {};
    const findings = data.findings    || [];
    const plan     = data.action_plan || [];

    const critical = findings.filter(f => f.severity === 'critical').length;
    const savings  = plan.reduce((s, p) => s + (p.savings_usd_month || 0), 0);
    const co2Total = plan.reduce((s, p) => s + (p.co2_reduction_kg  || 0), 0);

    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setText('landing-critical', critical || '-');
    setText('landing-savings',  savings   ? `${usd(savings)}/mo`              : '-');
    setText('landing-co2',      co2Total  ? `${Number(co2Total).toFixed(1)} kg/mo` : '-');
    // canvas-fx.js owns the hero canvas — no duplicate init here
}

// ─── Scan init ───────────────────────────────────────────────────────────────

function initScan() {
    if (window.lucide) lucide.createIcons();
}

// ─── Scanning init ───────────────────────────────────────────────────────────

function initScanning() {
    window.SCAN_LOGS = [];
    renderScanLog('[System] Pipeline started');
    initScanningGraph();
    runPipelineLive();
}

// ─── Scan log rendering ──────────────────────────────────────────────────────

function renderScanLog(message, type = 'system') {
    window.SCAN_LOGS.push({ message, type });
    const log = document.getElementById('feronia-log');
    if (!log) return;
    log.innerHTML = window.SCAN_LOGS.map((entry, i) => `
        <div class="log-line log-${entry.type}">
            <span>+${(i * 1.4).toFixed(1)}s</span>
            <code>${entry.message}</code>
        </div>`).join('');
    log.scrollTop = log.scrollHeight;
}

function setScanProgress(value, label) {
    const bar  = document.getElementById('scan-progress-bar');
    const text = document.getElementById('scan-progress-text');
    if (bar)  bar.style.width   = `${value}%`;
    if (text) text.textContent  = label || `${Math.round(value)}%`;
}

// ─── Live pipeline SSE ───────────────────────────────────────────────────────

window.runPipelineLive = function () {
    const source = new EventSource('/api/pipeline/stream');
    let tick = 8;
    setScanProgress(tick, 'Starting');

    source.onmessage = async function (event) {
        const data = JSON.parse(event.data);

        if (data.type === 'error') {
            source.close();
            renderScanLog(`[Error] ${data.status || 'Pipeline failed'}`, 'error');
            setScanProgress(100, 'Failed');
            return;
        }

        if (data.type === 'approval_required') {
            source.close();
            const count = data.pending_actions?.length || 0;
            renderScanLog(
                `Gatekeeper: HITL gate — ${count} destructive action(s) require approval`,
                'approval'
            );
            setScanProgress(96, 'Awaiting approval');
            if (typeof fetchGlobalData === 'function') await fetchGlobalData();
            setTimeout(() => navigate('dashboard'), 900);
            return;
        }

        if (data.type === 'done' || data.status === 'done') {
            source.close();
            renderScanLog('\u2713 Pipeline complete \u2014 dashboard updated', 'success');
            setScanProgress(100, 'Complete');
            if (typeof fetchGlobalData === 'function') await fetchGlobalData();
            setTimeout(() => navigate('dashboard'), 700);
            return;
        }

        tick = Math.min(92, tick + 10);
        const { msg, logType } = buildLogEntry(data);
        renderScanLog(msg, logType);
        setScanProgress(tick, data.node ? data.node.replaceAll('_', ' ') : 'Running');
    };

    source.onerror = function () {
        source.close();
        renderScanLog('[Error] Pipeline connection failed. Check backend console.', 'error');
        setScanProgress(100, 'Connection failed');
    };
};

window.handleScheduleChange = function () {
    const mode = document.getElementById('schedule-toggle')?.value || 'manual';
    fetch('/api/pipeline/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
    }).catch(err => console.log('Schedule update failed', err));
};

// ─── Lifecycle ───────────────────────────────────────────────────────────────

document.addEventListener('page:loaded', e => {
    // Stop canvas animations on every navigation
    _scanGraphActive = false;
    _dashGraphActive = false;
    if (_scanGraphAnim) { cancelAnimationFrame(_scanGraphAnim); _scanGraphAnim = null; }
    if (_dashGraphAnim) { cancelAnimationFrame(_dashGraphAnim); _dashGraphAnim = null; }

    const page = e.detail.page;
    if (page === 'landing')   initLanding();
    if (page === 'scan')      initScan();
    if (page === 'scanning')  initScanning();
    if (page === 'dashboard') initDashboard();
});
