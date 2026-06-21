const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const MITRE_URL = 'https://attack.mitre.org/techniques/';
const CIS_URL = 'https://www.cisecurity.org/benchmark/amazon_web_services';
const OWASP_URL = 'https://owasp.org/Top10/2025/';

function actionToLabel(action) {
    return String(action || '')
        .split('_')
        .filter(Boolean)
        .map(w => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
}

function severityBadge(severity) {
    return `<span class="badge badge-${severity}">${severity}</span>`;
}

function confidenceBar(confidence, label = true) {
    const pct = Math.round((confidence || 0) * 100);
    return `
        <div class="confidence-bar-wrap" title="AI confidence: ${pct}%">
            <div class="confidence-bar"><div class="confidence-fill" style="width:${pct}%"></div></div>
            ${label ? `<span>${pct}%</span>` : ''}
        </div>`;
}

function refLinks(finding) {
    const links = [];
    if (finding.cis_rule) {
        links.push(`<a class="ext-link" href="${CIS_URL}" target="_blank" title="View CIS Benchmark">${finding.cis_rule}</a>`);
    }
    if (finding.mitre_technique) {
        const tid = finding.mitre_technique.replace('T', '');
        links.push(`<a class="ext-link" href="${MITRE_URL}T${tid}/" target="_blank" title="View MITRE ATT&CK">${finding.mitre_technique}</a>`);
    }
    if (finding.agent_source === 'secops') {
        links.push(`<a class="ext-link" href="${OWASP_URL}" target="_blank" title="OWASP Cloud Security">OWASP</a>`);
    }
    return links.join(' ');
}

function usd(value) {
    return value != null ? `$${Number(value).toFixed(2)}` : '-';
}

function co2(value) {
    return value != null ? `${Number(value).toFixed(2)} kg` : '-';
}

function toggleAccordion(btn) {
    const content = btn.closest('.finding-card').querySelector('.accordion-content');
    const isOpen = content.classList.toggle('open');
    btn.textContent = isOpen ? 'Hide Details' : 'Show Details';
}

async function navigate(page) {
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    const activeLink = document.querySelector(`.nav-link[data-page="${page}"]`);
    if (activeLink) activeLink.classList.add('active');

    try {
        const html = await fetch(`pages/${page}.html`).then(r => {
            if (!r.ok) throw new Error();
            return r.text();
        });
        
        document.getElementById('app').innerHTML = html;
        document.dispatchEvent(new CustomEvent('page:loaded', { detail: { page } }));
        if (window.lucide) setTimeout(lucide.createIcons, 50);
    } catch (err) {
        document.getElementById('app').innerHTML = `<p class="empty-state">Could not load page: ${page}</p>`;
    }
}
