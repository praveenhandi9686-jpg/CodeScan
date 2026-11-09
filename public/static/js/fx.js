(() => {
  const c = document.getElementById("net"), x = c.getContext("2d"), N = 80; let w, h;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const rs = () => { w = c.width = innerWidth; h = c.height = innerHeight; }; addEventListener("resize", rs); rs();
  const P = Array.from({ length: N }, () => ({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .5, vy: (Math.random() - .5) * .5 }));
  function draw() {
    x.clearRect(0, 0, w, h);
    for (const p of P) { if (!still) { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > w) p.vx *= -1; if (p.y < 0 || p.y > h) p.vy *= -1; } x.fillStyle = "rgba(34,211,238,.9)"; x.fillRect(p.x, p.y, 2, 2); }
    for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) { const dx = P[i].x - P[j].x, dy = P[i].y - P[j].y, d = dx * dx + dy * dy;
      if (d < 16900) { x.strokeStyle = `rgba(124,92,255,${.45 * (1 - d / 16900)})`; x.beginPath(); x.moveTo(P[i].x, P[i].y); x.lineTo(P[j].x, P[j].y); x.stroke(); } }
  }
  (function loop() { if (!document.body.classList.contains("auth-mode") && !document.hidden) draw(); requestAnimationFrame(loop); })();
})();
