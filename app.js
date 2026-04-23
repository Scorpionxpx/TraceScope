const state = {
  selectedFile: null,
  events: [],
  filteredEvents: [],
  sortBy: "index",
  sortDirection: "asc",
  page: 1,
  pageSize: 25
};

const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const fileName = document.getElementById("fileName");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const conversionHelpEl = document.getElementById("conversionHelp");
const statsGrid = document.getElementById("statsGrid");
const protocolBars = document.getElementById("protocolBars");
const ipBars = document.getElementById("ipBars");
const eventsBody = document.getElementById("eventsBody");
const eventsMeta = document.getElementById("eventsMeta");
const quickFilter = document.getElementById("quickFilter");
const tableFilter = document.getElementById("tableFilter");
const exportBtn = document.getElementById("exportBtn");
const flowOnlyToggle = document.getElementById("flowOnlyToggle");
const prevPageBtn = document.getElementById("prevPageBtn");
const nextPageBtn = document.getElementById("nextPageBtn");
const pageInfo = document.getElementById("pageInfo");
const sortableHeaders = Array.from(document.querySelectorAll("th[data-sort]"));

fileInput.addEventListener("change", () => {
  state.selectedFile = fileInput.files[0] || null;
  updateFileName();
});

["dragenter", "dragover"].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.add("dragging");
  });
});

["dragleave", "drop"].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragging");
  });
});

dropZone.addEventListener("drop", (e) => {
  const file = e.dataTransfer.files[0];
  if (!file) return;
  state.selectedFile = file;
  updateFileName();
});

analyzeBtn.addEventListener("click", analyzeSelectedFile);
tableFilter.addEventListener("input", applyTableFilter);
quickFilter.addEventListener("change", applyTableFilter);
flowOnlyToggle.addEventListener("change", applyTableFilter);
exportBtn.addEventListener("click", exportJson);
prevPageBtn.addEventListener("click", () => changePage(-1));
nextPageBtn.addEventListener("click", () => changePage(1));
sortableHeaders.forEach((th) => th.addEventListener("click", () => sortBy(th.dataset.sort)));

function updateFileName() {
  fileName.textContent = state.selectedFile
    ? `Fichier charge: ${state.selectedFile.name}`
    : "Aucun fichier charge";
}

function setStatus(message, type = "") {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`.trim();
}

async function analyzeSelectedFile() {
  if (!state.selectedFile) {
    setStatus("Selectionnez d abord un fichier.", "error");
    return;
  }

  setStatus("Lecture du fichier...", "");
  conversionHelpEl.hidden = true;

  const file = state.selectedFile;

  try {
    const isBinary = await detectBinary(file);

    if (isBinary && file.name.toLowerCase().endsWith(".etl")) {
      resultsEl.hidden = true;
      conversionHelpEl.hidden = false;
      setStatus(
        "ETL binaire detecte. Convertissez en TXT avec pktmon etl2txt, puis reimportez.",
        "error"
      );
      return;
    }

    const content = await file.text();
    const parsed = parsePktMonText(content);

    state.events = parsed.events;
    state.page = 1;
    state.sortBy = "index";
    state.sortDirection = "asc";

    renderStats(parsed);
    renderBars(protocolBars, parsed.protocolCounts, 8);
    renderBars(ipBars, parsed.ipCounts, 8);
    applyTableFilter();

    resultsEl.hidden = false;
    conversionHelpEl.hidden = true;
    setStatus(
      `Analyse terminee: ${parsed.events.length} evenement(s) detecte(s).`,
      "ok"
    );
  } catch (err) {
    setStatus(`Erreur de lecture: ${err.message}`, "error");
  }
}

async function detectBinary(file) {
  const chunk = await file.slice(0, 2048).arrayBuffer();
  const bytes = new Uint8Array(chunk);
  let suspicious = 0;

  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i];
    const isPrintable = b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126);
    if (!isPrintable) suspicious += 1;
  }

  return suspicious / Math.max(bytes.length, 1) > 0.3;
}

function parsePktMonText(content) {
  const lines = content.split(/\r?\n/);
  const events = [];
  const protocolCounts = new Map();
  const ipCounts = new Map();
  const actionCounts = new Map();

  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i].trim();
    if (!raw) continue;

    const event = parseLine(raw, i + 1);
    if (!event) continue;

    events.push(event);

    increment(protocolCounts, event.protocol || "INCONNU");
    if (event.srcIp) increment(ipCounts, event.srcIp);
    if (event.dstIp) increment(ipCounts, event.dstIp);
    increment(actionCounts, event.action || "inconnu");
  }

  const dominantProtocol = topEntry(protocolCounts)?.key || "INCONNU";
  const topIp = topEntry(ipCounts)?.key || "N/A";
  const dropCount = actionCounts.get("drop") || 0;

  return {
    events,
    totalLines: lines.length,
    protocolCounts,
    ipCounts,
    actionCounts,
    dominantProtocol,
    topIp,
    dropCount
  };
}

function parseLine(raw, lineNumber) {
  const protocolMatch = raw.match(/\b(TCP|UDP|ICMPV6|ICMP|ARP|DNS|IPV4|IPV6)\b/i);
  const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : "";

  const timeMatch = raw.match(/\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b/);
  const timestamp = timeMatch ? timeMatch[0] : "";

  const action = inferAction(raw);

  const flowMatch = raw.match(
    /((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\s*(?:->|>|to)\s*((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?/i
  );

  let srcIp = "";
  let srcPort = "";
  let dstIp = "";
  let dstPort = "";

  if (flowMatch) {
    srcIp = flowMatch[1] || "";
    srcPort = flowMatch[2] || "";
    dstIp = flowMatch[3] || "";
    dstPort = flowMatch[4] || "";
  } else {
    const ips = raw.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || [];
    if (ips[0]) srcIp = ips[0];
    if (ips[1]) dstIp = ips[1];

    const ports = [...raw.matchAll(/:(\d{1,5})\b/g)].map((m) => m[1]);
    if (ports[0]) srcPort = ports[0];
    if (ports[1]) dstPort = ports[1];
  }

  const hasSignals = protocol || srcIp || dstIp || action !== "inconnu";
  if (!hasSignals) return null;

  return {
    lineNumber,
    timestamp,
    action,
    protocol: protocol || "INCONNU",
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    raw
  };
}

function inferAction(line) {
  const text = line.toLowerCase();
  if (/\bdrop|dropped|rejete|blocked|refused\b/.test(text)) return "drop";
  if (/\ballow|accepted|autorise|permit\b/.test(text)) return "allow";
  if (/\bsent|send|tx|transmit\b/.test(text)) return "tx";
  if (/\brecv|receive|rx\b/.test(text)) return "rx";
  return "inconnu";
}

function renderStats(parsed) {
  const cards = [
    { label: "Lignes lues", value: parsed.totalLines.toLocaleString("fr-FR") },
    { label: "Evenements detectes", value: parsed.events.length.toLocaleString("fr-FR") },
    { label: "Protocole dominant", value: parsed.dominantProtocol },
    { label: "Top IP", value: parsed.topIp },
    { label: "Paquets drop", value: parsed.dropCount.toLocaleString("fr-FR") }
  ];

  statsGrid.innerHTML = cards
    .map(
      (c) =>
        `<article class="stat"><div class="label">${escapeHtml(c.label)}</div><div class="value">${escapeHtml(c.value)}</div></article>`
    )
    .join("");
}

function renderBars(container, map, maxItems) {
  const entries = [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, maxItems);
  const max = entries[0]?.[1] || 1;

  if (!entries.length) {
    container.innerHTML = "<p>Aucune donnee.</p>";
    return;
  }

  container.innerHTML = entries
    .map(([label, value]) => {
      const pct = Math.max(4, (value / max) * 100);
      return `
        <div class="bar-item">
          <span>${escapeHtml(label)}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
          <strong>${value}</strong>
        </div>
      `;
    })
    .join("");
}

function renderTable() {
  const sorted = getSortedEvents();

  if (!sorted.length) {
    eventsBody.innerHTML = "<tr><td colspan=\"7\">Aucun evenement a afficher.</td></tr>";
    eventsMeta.innerHTML = "";
    pageInfo.textContent = "Page 1 / 1";
    prevPageBtn.disabled = true;
    nextPageBtn.disabled = true;
    updateSortIndicators();
    return;
  }

  const totalPages = Math.max(1, Math.ceil(sorted.length / state.pageSize));
  if (state.page > totalPages) state.page = totalPages;

  const start = (state.page - 1) * state.pageSize;
  const paged = sorted.slice(start, start + state.pageSize);

  const rows = paged.map((e, idx) => {
    const src = [e.srcIp, e.srcPort].filter(Boolean).join(":");
    const dst = [e.dstIp, e.dstPort].filter(Boolean).join(":");
    const actionClass = sanitizeClassName(e.action);
    const globalIndex = start + idx + 1;

    return `
      <tr>
        <td>${globalIndex}</td>
        <td>${escapeHtml(e.timestamp)}</td>
        <td><span class="action-badge ${actionClass}">${escapeHtml(e.action)}</span></td>
        <td>${escapeHtml(e.protocol)}</td>
        <td>${escapeHtml(src)}</td>
        <td>${escapeHtml(dst)}</td>
        <td class="raw-cell" title="${escapeHtml(e.raw)}">${escapeHtml(e.raw)}</td>
      </tr>
    `;
  });

  eventsBody.innerHTML = rows.join("");
  pageInfo.textContent = `Page ${state.page} / ${totalPages}`;
  prevPageBtn.disabled = state.page <= 1;
  nextPageBtn.disabled = state.page >= totalPages;
  renderTableMeta();
  updateSortIndicators();
}

function applyTableFilter() {
  const q = tableFilter.value.trim().toLowerCase();
  state.filteredEvents = state.events.filter((e) => {
    const matchesText = !q || [
      e.timestamp,
      e.action,
      e.protocol,
      e.srcIp,
      e.srcPort,
      e.dstIp,
      e.dstPort,
      e.raw
    ]
      .join(" ")
      .toLowerCase()
      .includes(q);

    return matchesText && matchesQuickFilter(e) && matchesFlowToggle(e);
  });

  state.page = 1;
  renderTable();
}

function exportJson() {
  if (!state.filteredEvents.length) {
    setStatus("Aucune donnee a exporter.", "error");
    return;
  }

  const payload = {
    exportedAt: new Date().toISOString(),
    total: state.filteredEvents.length,
    events: state.filteredEvents
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json"
  });

  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "analyse-pktmon.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

function increment(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

function topEntry(map) {
  const sorted = [...map.entries()].sort((a, b) => b[1] - a[1]);
  if (!sorted.length) return null;
  return { key: sorted[0][0], value: sorted[0][1] };
}

function changePage(delta) {
  state.page += delta;
  if (state.page < 1) state.page = 1;
  renderTable();
}

function sortBy(key) {
  if (!key) return;

  if (state.sortBy === key) {
    state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
  } else {
    state.sortBy = key;
    state.sortDirection = "asc";
  }

  state.page = 1;
  renderTable();
}

function getSortedEvents() {
  const factor = state.sortDirection === "asc" ? 1 : -1;
  const arr = [...state.filteredEvents];

  arr.sort((a, b) => {
    let va;
    let vb;

    switch (state.sortBy) {
      case "timestamp":
        va = a.timestamp || "";
        vb = b.timestamp || "";
        break;
      case "action":
        va = a.action || "";
        vb = b.action || "";
        break;
      case "protocol":
        va = a.protocol || "";
        vb = b.protocol || "";
        break;
      case "src":
        va = `${a.srcIp || ""}:${a.srcPort || ""}`;
        vb = `${b.srcIp || ""}:${b.srcPort || ""}`;
        break;
      case "dst":
        va = `${a.dstIp || ""}:${a.dstPort || ""}`;
        vb = `${b.dstIp || ""}:${b.dstPort || ""}`;
        break;
      case "raw":
        va = a.raw || "";
        vb = b.raw || "";
        break;
      case "index":
      default:
        va = a.lineNumber || 0;
        vb = b.lineNumber || 0;
        break;
    }

    if (typeof va === "number" && typeof vb === "number") {
      return (va - vb) * factor;
    }

    return String(va).localeCompare(String(vb), "fr", { sensitivity: "base" }) * factor;
  });

  return arr;
}

function renderTableMeta() {
  const total = state.events.length;
  const shown = state.filteredEvents.length;
  const drops = state.filteredEvents.filter((e) => e.action === "drop").length;
  const unknown = state.filteredEvents.filter((e) => e.action === "inconnu").length;
  const selectedQuickFilter = quickFilter.value || "all";
  const flowMode = flowOnlyToggle.checked ? "OUI" : "NON";

  eventsMeta.innerHTML = [
    `<span class="meta-chip">Affiches: ${shown.toLocaleString("fr-FR")} / ${total.toLocaleString("fr-FR")}</span>`,
    `<span class="meta-chip">Drop: ${drops.toLocaleString("fr-FR")}</span>`,
    `<span class="meta-chip">Inconnu: ${unknown.toLocaleString("fr-FR")}</span>`,
    `<span class="meta-chip">IP source+destination uniquement: ${flowMode}</span>`,
    `<span class="meta-chip">Filtre rapide: ${escapeHtml(selectedQuickFilter.toUpperCase())}</span>`,
    `<span class="meta-chip">Tri: ${escapeHtml(state.sortBy)} (${escapeHtml(state.sortDirection)})</span>`
  ].join("");
}

function matchesFlowToggle(event) {
  if (!flowOnlyToggle.checked) return true;
  return Boolean(event.srcIp && event.dstIp);
}

function matchesQuickFilter(event) {
  const selected = quickFilter.value || "all";
  if (selected === "all") return true;

  const protocol = String(event.protocol || "").toLowerCase();
  const action = String(event.action || "").toLowerCase();

  if (["tcp", "udp", "icmp", "dns"].includes(selected)) {
    return protocol === selected;
  }

  if (["drop", "allow", "tx", "rx"].includes(selected)) {
    return action === selected;
  }

  return true;
}

function updateSortIndicators() {
  sortableHeaders.forEach((th) => {
    th.classList.remove("sorted-asc", "sorted-desc");
    if (th.dataset.sort === state.sortBy) {
      th.classList.add(state.sortDirection === "asc" ? "sorted-asc" : "sorted-desc");
    }
  });
}

function sanitizeClassName(value) {
  return String(value || "inconnu")
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "") || "inconnu";
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
