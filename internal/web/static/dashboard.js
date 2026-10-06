(function () {
  const ink = "#0c0c0c";
  const red = "#c43c2c";
  const paper = "#e8e2d6";
  const mute = "#6e6a63";
  const chalk = "#f2efe8";

  Chart.defaults.color = ink;
  Chart.defaults.borderColor = "rgba(12,12,12,0.15)";
  Chart.defaults.font.family = "IBM Plex Mono, SF Mono, Menlo, Consolas, monospace";

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KiB";
    if (n < 1073741824) return (n / 1048576).toFixed(1) + " MiB";
    return (n / 1073741824).toFixed(2) + " GiB";
  }

  function labels(hist) {
    return hist.map(function (p) {
      const d = new Date(p.ts * 1000);
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    });
  }

  const commonOpts = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { labels: { boxWidth: 12 } } },
    scales: {
      x: { ticks: { maxTicksLimit: 8, color: mute }, grid: { color: "rgba(12,12,12,0.08)" } },
      y: { beginAtZero: true, ticks: { color: mute }, grid: { color: "rgba(12,12,12,0.08)" } },
    },
  };

  const totalsChart = new Chart(document.getElementById("chart-mail-totals"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "принято", data: [], borderColor: ink, backgroundColor: "rgba(12,12,12,0.08)", tension: 0.25, fill: true },
        { label: "доставлено", data: [], borderColor: "#2f6b4f", backgroundColor: "rgba(47,107,79,0.12)", tension: 0.25, fill: true },
        { label: "отклонено", data: [], borderColor: red, backgroundColor: "rgba(196,60,44,0.12)", tension: 0.25, fill: true },
        { label: "bounce", data: [], borderColor: mute, backgroundColor: "rgba(110,106,99,0.12)", tension: 0.25, fill: false },
      ],
    },
    options: commonOpts,
  });

  const rateChart = new Chart(document.getElementById("chart-mail-rate"), {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        { label: "recv/s", data: [], backgroundColor: ink },
        { label: "deliv/s", data: [], backgroundColor: "#2f6b4f" },
        { label: "reject/s", data: [], backgroundColor: red },
      ],
    },
    options: commonOpts,
  });

  const sysChart = new Chart(document.getElementById("chart-sys"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "CPU %", data: [], borderColor: red, yAxisID: "y", tension: 0.25, fill: false },
        { label: "RSS MiB", data: [], borderColor: ink, yAxisID: "y1", tension: 0.25, fill: false },
        { label: "Heap MiB", data: [], borderColor: mute, yAxisID: "y1", tension: 0.25, borderDash: [4, 4], fill: false },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { labels: { boxWidth: 12 } } },
      scales: {
        x: { ticks: { maxTicksLimit: 8, color: mute }, grid: { color: "rgba(12,12,12,0.08)" } },
        y: { beginAtZero: true, max: 100, position: "left", title: { display: true, text: "CPU %" }, ticks: { color: red }, grid: { color: "rgba(12,12,12,0.08)" } },
        y1: { beginAtZero: true, position: "right", title: { display: true, text: "MiB" }, ticks: { color: ink }, grid: { drawOnChartArea: false } },
      },
    },
  });

  const queueChart = new Chart(document.getElementById("chart-queue"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "incoming", data: [], borderColor: ink, tension: 0.25 },
        { label: "active", data: [], borderColor: "#2f6b4f", tension: 0.25 },
        { label: "deferred", data: [], borderColor: red, tension: 0.25 },
        { label: "bounce", data: [], borderColor: mute, tension: 0.25 },
      ],
    },
    options: commonOpts,
  });

  function apply(live) {
    const h = live.history || [];
    const now = live.now || {};
    const lbs = labels(h);

    document.getElementById("kpi-recv").textContent = now.received || 0;
    document.getElementById("kpi-deliv").textContent = now.delivered || 0;
    document.getElementById("kpi-rej").textContent = now.rejected || 0;
    document.getElementById("kpi-def").textContent = now.deferred || 0;
    document.getElementById("kpi-bnc").textContent = now.bounced || 0;
    document.getElementById("kpi-cpu").textContent = (now.cpu_percent || 0).toFixed(1) + "%";
    document.getElementById("kpi-rss").textContent = fmtBytes(now.rss_bytes || 0);
    document.getElementById("kpi-go").textContent = now.goroutines || 0;

    totalsChart.data.labels = lbs;
    totalsChart.data.datasets[0].data = h.map((p) => p.received);
    totalsChart.data.datasets[1].data = h.map((p) => p.delivered);
    totalsChart.data.datasets[2].data = h.map((p) => p.rejected);
    totalsChart.data.datasets[3].data = h.map((p) => p.bounced);
    totalsChart.update();

    rateChart.data.labels = lbs;
    rateChart.data.datasets[0].data = h.map((p) => p.recv_rate);
    rateChart.data.datasets[1].data = h.map((p) => p.deliv_rate);
    rateChart.data.datasets[2].data = h.map((p) => p.reject_rate);
    rateChart.update();

    sysChart.data.labels = lbs;
    sysChart.data.datasets[0].data = h.map((p) => p.cpu_percent);
    sysChart.data.datasets[1].data = h.map((p) => (p.rss_bytes || 0) / 1048576);
    sysChart.data.datasets[2].data = h.map((p) => (p.heap_bytes || 0) / 1048576);
    sysChart.update();

    queueChart.data.labels = lbs;
    queueChart.data.datasets[0].data = h.map((p) => p.queue_incoming);
    queueChart.data.datasets[1].data = h.map((p) => p.queue_active);
    queueChart.data.datasets[2].data = h.map((p) => p.queue_deferred);
    queueChart.data.datasets[3].data = h.map((p) => p.queue_bounce);
    queueChart.update();

    const meter = document.getElementById("meter-totals");
    if (meter && live.totals) {
      meter.innerHTML = Object.keys(live.totals)
        .sort()
        .map((k) => "<li><span>" + k + "</span><strong>" + live.totals[k] + "</strong></li>")
        .join("");
    }
  }

  async function tick() {
    try {
      const r = await fetch("/admin/api/live", { credentials: "same-origin" });
      if (!r.ok) return;
      apply(await r.json());
    } catch (_) {}
  }

  tick();
  setInterval(tick, 5000);
})();
