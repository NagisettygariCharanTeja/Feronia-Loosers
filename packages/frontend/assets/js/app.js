// â”€â”€â”€ APP INIT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Entry point. Bootstraps the SPA, sets the default page, and wires nav links.

window.DASHBOARD_DATA = { findings: [], action_plan: [], summary: {} };
window.INFRASTRUCTURE_DATA = {};

async function fetchGlobalData() {
    try {
        const dashRes = await fetch('/api/dashboard');
        if (dashRes.ok) window.DASHBOARD_DATA = await dashRes.json();
        
        const infraRes = await fetch('/api/infrastructure');
        if (infraRes.ok) window.INFRASTRUCTURE_DATA = await infraRes.json();
    } catch (e) {
        console.error("Failed to fetch global data:", e);
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    // Wire sidebar nav
    document.querySelectorAll('.nav-link[data-page]').forEach(link => {
        link.addEventListener('click', () => navigate(link.dataset.page));
    });

    await fetchGlobalData();

    // Load default page
    navigate('landing');
});
