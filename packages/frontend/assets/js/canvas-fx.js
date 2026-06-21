// assets/js/canvas-fx.js
// Particle-network background for the landing hero canvas.
// Ported from the design reference's _hero() method — framework-free.
// Include via <script src="assets/js/canvas-fx.js"></script> in index.html
// (after utils.js), or merge into an existing assets/js file.

(function () {
  let heroAnim = null;
  let heroNodes = [];
  let heroEdges = [];
  let active = false;

  function initHeroCanvas() {
    const cv = document.getElementById('feronia-hero-cv');
    if (!cv) return;
    destroyHeroCanvas(); // guard against double-init on fast nav

    const tryInit = (attempts) => {
      const W = cv.offsetWidth, H = cv.offsetHeight;
      if (!W || !H) {
        if (attempts < 40) setTimeout(() => tryInit(attempts + 1), 50);
        return;
      }
      cv.width = W;
      cv.height = H;
      const ctx = cv.getContext('2d');

      const types = ['EC2', 'S3', 'RDS', 'Lambda', 'VPC', 'IAM', 'EKS', 'SG', 'CF', 'KMS'];
      const stats = ['healthy', 'healthy', 'healthy', 'healthy', 'critical', 'warning', 'teal'];
      heroNodes = Array.from({ length: 60 }, (_, i) => ({
        x: Math.random() * W, y: Math.random() * H,
        vx: (Math.random() - 0.5) * 0.22, vy: (Math.random() - 0.5) * 0.22,
        r: 2.5 + Math.random() * 5.5,
        type: types[i % types.length],
        status: stats[Math.floor(Math.random() * stats.length)],
        phase: Math.random() * Math.PI * 2,
        lbl: Math.random() < 0.28,
      }));

      heroEdges = [];
      for (let i = 0; i < heroNodes.length; i++) {
        for (let j = i + 1; j < heroNodes.length; j++) {
          const dx = heroNodes[i].x - heroNodes[j].x;
          const dy = heroNodes[i].y - heroNodes[j].y;
          if (dx * dx + dy * dy < 165 * 165 && Math.random() < 0.2) {
            const p = Math.random() < 0.35 ? [{ t: Math.random(), s: 0.0018 + Math.random() * 0.004 }] : [];
            heroEdges.push({ from: i, to: j, p });
          }
        }
      }

      let mx = W / 2, my = H / 2;
      cv.onmousemove = (e) => {
        const r = cv.getBoundingClientRect();
        mx = (e.clientX - r.left) * (W / r.width);
        my = (e.clientY - r.top) * (H / r.height);
      };

      active = true;
      const draw = () => {
        if (!active) return;
        heroAnim = requestAnimationFrame(draw);
        ctx.clearRect(0, 0, W, H);

        for (const e of heroEdges) {
          const a = heroNodes[e.from], b = heroNodes[e.to];
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = 'rgba(34,197,94,.08)';
          ctx.lineWidth = 0.5;
          ctx.stroke();
          for (const p of e.p) {
            p.t = (p.t + p.s) % 1;
            ctx.beginPath();
            ctx.arc(a.x + (b.x - a.x) * p.t, a.y + (b.y - a.y) * p.t, 1.5, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(74,222,128,.75)';
            ctx.fill();
          }
        }

        for (const n of heroNodes) {
          const dx = n.x - mx, dy = n.y - my;
          const md = Math.sqrt(dx * dx + dy * dy) || 1;
          if (md < 125) {
            const f = ((125 - md) / 125) * 0.38;
            n.vx += (dx / md) * f;
            n.vy += (dy / md) * f;
          }
          n.vx *= 0.984; n.vy *= 0.984;
          n.x += n.vx; n.y += n.vy;
          if (n.x < 0 || n.x > W) { n.vx *= -1; n.x = Math.max(0, Math.min(W, n.x)); }
          if (n.y < 0 || n.y > H) { n.vy *= -1; n.y = Math.max(0, Math.min(H, n.y)); }
          n.phase += 0.02;
          const p = Math.sin(n.phase) * 0.5 + 0.5;
          const [r, g, b] = n.status === 'critical' ? [239, 68, 68]
            : n.status === 'warning' ? [245, 158, 11]
            : n.status === 'teal' ? [13, 148, 136]
            : [34, 197, 94];
          if (n.status !== 'healthy') {
            const gr = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 5);
            gr.addColorStop(0, `rgba(${r},${g},${b},${p * 0.32})`);
            gr.addColorStop(1, `rgba(${r},${g},${b},0)`);
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r * 5, 0, Math.PI * 2);
            ctx.fillStyle = gr;
            ctx.fill();
          }
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(${r},${g},${b},.82)`;
          ctx.fill();
          if (n.lbl && n.r > 3.8) {
            ctx.font = '9px Space Mono, monospace';
            ctx.fillStyle = `rgba(${r},${g},${b},.62)`;
            ctx.fillText(n.type, n.x + n.r + 3, n.y + 3);
          }
        }
      };
      heroAnim = requestAnimationFrame(draw);
    };
    tryInit(0);
  }

  function destroyHeroCanvas() {
    active = false;
    if (heroAnim) cancelAnimationFrame(heroAnim);
    heroAnim = null;
  }

  // Hook into the SPA's fragment-router lifecycle (utils.js dispatches
  // 'page:loaded' with { page } on every navigate()).
  document.addEventListener('page:loaded', (e) => {
    if (e.detail && e.detail.page === 'landing') {
      initHeroCanvas();
    } else {
      destroyHeroCanvas();
    }
  });

  // Cover the very first load if landing is the default route.
  document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('feronia-hero-cv')) initHeroCanvas();
  });
})();
