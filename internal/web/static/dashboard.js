(function () {
  const messages = JSON.parse(document.getElementById("dashboard").dataset.labels);
  const t = (key) => messages[key] || key;
  const locale = document.documentElement.lang;
  const palettes = {
    dark: {
      ink: "#e2e8f0", red: "#fb7185", mute: "#94a3b8", green: "#34d399",
      grid: "rgba(148,163,184,0.08)", border: "rgba(148,163,184,0.25)",
    },
    light: {
      ink: "#1e293b", red: "#be123c", mute: "#475569", green: "#047857",
      grid: "rgba(71,85,105,0.12)", border: "rgba(71,85,105,0.3)",
    },
  };
  const palette = () => palettes[document.documentElement.dataset.theme] || palettes.dark;
  const color = (key) => () => palette()[key];
  const ink = color("ink");
  const red = color("red");
  const mute = color("mute");
  const green = color("green");
  const grid = color("grid");

  Chart.defaults.borderColor = palette().border;
  Chart.defaults.font.family = "IBM Plex Mono, SF Mono, Menlo, Consolas, monospace";

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KiB";
    if (n < 1073741824) return (n / 1048576).toFixed(1) + " " + t("MiB");
    return (n / 1073741824).toFixed(2) + " GiB";
  }

  function labels(hist) {
    return hist.map(function (p) {
      const d = new Date(p.ts * 1000);
      return d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    });
  }

  const commonOpts = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { labels: { boxWidth: 12, color: ink } } },
    scales: {
      x: { ticks: { maxTicksLimit: 8, color: mute }, grid: { color: grid } },
      y: { beginAtZero: true, ticks: { color: mute }, grid: { color: grid } },
    },
  };

  const totalsChart = new Chart(document.getElementById("chart-mail-totals"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: t("Received"), data: [], borderColor: ink, backgroundColor: "rgba(148,163,184,0.08)", tension: 0.25, fill: true },
        { label: t("Delivered"), data: [], borderColor: green, backgroundColor: "rgba(52,211,153,0.12)", tension: 0.25, fill: true },
        { label: t("Rejected"), data: [], borderColor: red, backgroundColor: "rgba(251,113,133,0.12)", tension: 0.25, fill: true },
        { label: t("Bounced"), data: [], borderColor: mute, backgroundColor: "rgba(148,163,184,0.12)", tension: 0.25, fill: false },
      ],
    },
    options: commonOpts,
  });

  const rateChart = new Chart(document.getElementById("chart-mail-rate"), {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        { label: t("Received/s"), data: [], backgroundColor: ink },
        { label: t("Delivered/s"), data: [], backgroundColor: green },
        { label: t("Rejected/s"), data: [], backgroundColor: red },
      ],
    },
    options: commonOpts,
  });

  const sysChart = new Chart(document.getElementById("chart-sys"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: t("CPU %"), data: [], borderColor: red, yAxisID: "y", tension: 0.25, fill: false },
        { label: t("RSS MiB"), data: [], borderColor: ink, yAxisID: "y1", tension: 0.25, fill: false },
        { label: t("Heap MiB"), data: [], borderColor: mute, yAxisID: "y1", tension: 0.25, borderDash: [4, 4], fill: false },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { labels: { boxWidth: 12, color: ink } } },
      scales: {
        x: { ticks: { maxTicksLimit: 8, color: mute }, grid: { color: grid } },
        y: { beginAtZero: true, max: 100, position: "left", title: { display: true, text: t("CPU %"), color: ink }, ticks: { color: red }, grid: { color: grid } },
        y1: { beginAtZero: true, position: "right", title: { display: true, text: t("MiB"), color: ink }, ticks: { color: ink }, grid: { drawOnChartArea: false } },
      },
    },
  });

  const queueChart = new Chart(document.getElementById("chart-queue"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: t("Incoming"), data: [], borderColor: ink, tension: 0.25 },
        { label: t("Active"), data: [], borderColor: green, tension: 0.25 },
        { label: t("Deferred"), data: [], borderColor: red, tension: 0.25 },
        { label: t("Bounced"), data: [], borderColor: mute, tension: 0.25 },
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
      const rows = Object.keys(live.totals).sort().map((key) => {
        const row = document.createElement("li");
        const label = document.createElement("span");
        const value = document.createElement("strong");
        label.textContent = t(key);
        value.textContent = live.totals[key];
        row.append(label, value);
        return row;
      });
      meter.replaceChildren(...rows);
    }
  }

  document.addEventListener("mailedge:themechange", () => {
    Chart.defaults.borderColor = palette().border;
    for (const chart of [totalsChart, rateChart, sysChart, queueChart]) {
      chart.update("none");
    }
  });

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
