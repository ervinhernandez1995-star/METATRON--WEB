/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║        METATRON v2.1 — API Client (script.js)               ║
 * ║  • Cliente fetch global con headers ngrok pre-configurados  ║
 * ║  • analizarIP()  → /analyze  (compatible con index.html)    ║
 * ║  • escanearRedes() → /network-scan → tabla dinámica         ║
 * ║  • Botones Interactuar / Atacar se habilitan automáticamente ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

// ══════════════════════════════════════════════════════════════
// 1. CONFIGURACIÓN GLOBAL
//    Lee NEXT_PUBLIC_API_URL si existe (Next.js/Vercel).
//    Si el script se usa en HTML plano, cambia la constante aquí.
// ══════════════════════════════════════════════════════════════

const API_URL =
  (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_URL) ||
  "https://subentire-sibyl-gleesomely.ngrok-free.dev";   // ← actualiza con tu URL ngrok

/**
 * Cliente fetch global.
 * Incluye SIEMPRE los headers obligatorios para ngrok + JSON.
 * Lanza un Error si la respuesta no es ok.
 *
 * @param {string} path   – endpoint relativo, ej. "/network-scan"
 * @param {object} [body] – body JSON (omitir para GET)
 * @param {string} [method] – "GET" | "POST" | …  (default: "POST" si body, "GET" si no)
 */
async function apiFetch(path, body = null, method = null) {
  const resolvedMethod = method || (body ? "POST" : "GET");

  const options = {
    method: resolvedMethod,
    headers: {
      "Content-Type":              "application/json",
      // ↓ CRÍTICO: evita que ngrok devuelva HTML en lugar de JSON
      "ngrok-skip-browser-warning": "true",
    },
  };

  if (body && resolvedMethod !== "GET") {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(`${API_URL}${path}`, options);

  // Si ngrok devuelve HTML (texto), lo detectamos antes de parsear
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    const text = await response.text();
    throw new Error(
      `Respuesta inesperada (no JSON). ¿Está ngrok corriendo?\n\n${text.slice(0, 200)}`
    );
  }

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

// ══════════════════════════════════════════════════════════════
// 2. ANÁLISIS DE IP / DOMINIO  (/analyze)
//    Usado por el index.html original con el campo #ip-address
// ══════════════════════════════════════════════════════════════

async function analizarIP() {
  const ipInput  = document.getElementById("ip-address") ||
                   document.querySelector('input[type="text"]');
  const resultDiv = document.getElementById("results") ||
                    document.getElementById("output");

  if (!ipInput?.value?.trim()) {
    alert("⚠️ Por favor, ingresa una dirección IP o dominio.");
    return;
  }

  resultDiv.innerHTML =
    "<p style='color:#00ff00;'>📡 Conectando con Metatron Engine… espera.</p>";

  try {
    const data = await apiFetch("/analyze", { ip: ipInput.value.trim() });

    resultDiv.innerHTML = `
      <div style="border:1px solid #00ff00;padding:15px;background:#000;">
        <h3 style="color:#00ff00;">🔍 Análisis Llama-3 — Riesgo: ${data.risk_level}</h3>
        <p style="white-space:pre-wrap;color:#fff;">${data.analysis}</p>
        ${renderVulnerabilities(data.vulnerabilities)}
      </div>`;
  } catch (error) {
    console.error("Error /analyze:", error);
    resultDiv.innerHTML = `
      <p style="color:red;">❌ Error de conexión: ${error.message}<br>
      Asegúrate de que el motor de Metatron y ngrok estén corriendo en Ubuntu.</p>`;
  }
}

/** Genera HTML para la lista de vulnerabilidades (opcional). */
function renderVulnerabilities(vulns = []) {
  if (!vulns.length) return "";
  const rows = vulns
    .map(
      (v) => `<tr>
        <td style="color:#ff4444;">${v.severity}</td>
        <td>${v.vuln_name}</td>
        <td>${v.port || "N/A"}</td>
        <td>${v.service || "N/A"}</td>
      </tr>`
    )
    .join("");
  return `
    <table style="width:100%;margin-top:12px;border-collapse:collapse;color:#ccc;">
      <thead><tr style="color:#00ff00;">
        <th>Severidad</th><th>Vulnerabilidad</th><th>Puerto</th><th>Servicio</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ══════════════════════════════════════════════════════════════
// 3. ESCANEO DE REDES WI-FI  (/network-scan)
//    Llena la tabla #networks-table y habilita los botones
// ══════════════════════════════════════════════════════════════

/**
 * Dispara el escaneo de redes y actualiza la UI.
 * @param {string} [method="powershell"] – "powershell" | "nmcli" | "nmap" | "all"
 */
async function escanearRedes(method = "powershell") {
  const statusEl = document.getElementById("scan-status");
  const tableBody = document.querySelector("#networks-table tbody") ||
                    document.getElementById("networks-tbody");

  if (statusEl) statusEl.textContent = "⏳ Escaneando redes… puede tardar ~15 s";
  if (tableBody) tableBody.innerHTML =
    '<tr><td colspan="6" style="color:#00ff00;text-align:center;">Escaneando…</td></tr>';

  try {
    const data = await apiFetch("/network-scan", { method, label: "wifi_scan" });

    if (statusEl)
      statusEl.textContent =
        `✅ ${data.total_found} red(es) encontrada(s) — Sesión #${data.sl_no}`;

    renderNetworksTable(data.networks, tableBody);
  } catch (error) {
    console.error("Error /network-scan:", error);
    if (statusEl) statusEl.textContent = `❌ Error: ${error.message}`;
    if (tableBody)
      tableBody.innerHTML = `<tr><td colspan="6" style="color:red;">${error.message}</td></tr>`;
  }
}

/**
 * Renderiza las filas de la tabla de redes y habilita botones de acción.
 *
 * Estructura del JSON de /network-scan:
 * {
 *   networks: [
 *     { ssid, bssid, channel, signal, security, radio? }
 *   ]
 * }
 */
function renderNetworksTable(networks = [], tableBody) {
  if (!tableBody) {
    console.warn("renderNetworksTable: no se encontró el tbody de la tabla.");
    return;
  }

  if (!networks.length) {
    tableBody.innerHTML =
      '<tr><td colspan="6" style="color:#aaa;">No se detectaron redes.</td></tr>';
    return;
  }

  tableBody.innerHTML = networks
    .map((net, idx) => {
      const ssid      = escapeHtml(net.ssid     || "<hidden>");
      const bssid     = escapeHtml(net.bssid    || "N/A");
      const channel   = escapeHtml(net.channel  || "N/A");
      const signal    = escapeHtml(net.signal   || "N/A");
      const security  = escapeHtml(net.security || "OPEN");
      const radio     = escapeHtml(net.radio    || "");

      // Color de señal
      const signalNum = parseInt(signal);
      const signalColor =
        isNaN(signalNum) ? "#aaa" :
        signalNum >= 70  ? "#00ff00" :
        signalNum >= 40  ? "#ffaa00" : "#ff4444";

      return `
        <tr data-idx="${idx}" data-ssid="${ssid}" data-bssid="${bssid}">
          <td>${ssid}</td>
          <td style="font-family:monospace;font-size:0.85em;">${bssid}</td>
          <td style="text-align:center;">${channel}</td>
          <td style="color:${signalColor};text-align:center;">${signal}</td>
          <td>${security}${radio ? ` <span style="color:#888;font-size:0.8em;">(${radio})</span>` : ""}</td>
          <td style="white-space:nowrap;">
            <button
              onclick="accionRed('interact','${escapeAttr(ssid)}','${escapeAttr(bssid)}')"
              style="margin-right:4px;padding:3px 10px;background:#004400;color:#00ff00;
                     border:1px solid #00ff00;cursor:pointer;border-radius:3px;">
              🔍 Interactuar
            </button>
            <button
              onclick="accionRed('attack','${escapeAttr(ssid)}','${escapeAttr(bssid)}')"
              style="padding:3px 10px;background:#440000;color:#ff4444;
                     border:1px solid #ff4444;cursor:pointer;border-radius:3px;">
              ⚡ Atacar
            </button>
          </td>
        </tr>`;
    })
    .join("");
}

/**
 * Manejador de los botones de acción de cada red.
 * @param {"interact"|"attack"} action
 * @param {string} ssid
 * @param {string} bssid
 */
function accionRed(action, ssid, bssid) {
  const label = action === "attack" ? "⚡ ATAQUE" : "🔍 INTERACCIÓN";
  const confirmMsg =
    action === "attack"
      ? `⚠️ ¿Confirmas el ataque a "${ssid}" (${bssid})?\n\nUso solo en redes propias/autorizadas.`
      : `Iniciar interacción/reconocimiento en "${ssid}" (${bssid})?`;

  if (!confirm(confirmMsg)) return;

  const statusEl = document.getElementById("scan-status");
  if (statusEl) statusEl.textContent = `${label} en progreso: ${ssid} (${bssid})…`;

  // Aquí puedes llamar a tu endpoint específico, ej:
  // apiFetch("/scan", { target: bssid, tools: ["nmap_service"] })
  //   .then(data => { ... })
  //   .catch(err => { ... });

  console.log(`[METATRON] ${label} → SSID: ${ssid} | BSSID: ${bssid}`);
  alert(`${label} iniciado para:\nSSID: ${ssid}\nBSSID: ${bssid}\n\n(Implementa el endpoint correspondiente en api.py)`);
}

// ══════════════════════════════════════════════════════════════
// 4. HELPERS
// ══════════════════════════════════════════════════════════════

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(str) {
  return String(str).replace(/'/g, "\\'").replace(/"/g, "&quot;");
}

// ══════════════════════════════════════════════════════════════
// 5. INICIALIZACIÓN
// ══════════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
  // ── Botón de análisis de IP ────────────────────────────────
  const btnScan = document.getElementById("scan-btn") ||
                  document.querySelector('button[data-action="scan"]');
  if (btnScan) btnScan.addEventListener("click", analizarIP);

  // ── Botón de escaneo de redes ──────────────────────────────
  const btnNetworks = document.getElementById("network-scan-btn") ||
                      document.querySelector('button[data-action="network-scan"]');
  if (btnNetworks) {
    btnNetworks.addEventListener("click", () => {
      // Lee el selector de método si existe
      const methodSel = document.getElementById("scan-method");
      escanearRedes(methodSel?.value || "powershell");
    });
  }

  // ── Primer botón genérico (compatibilidad index.html original) ──
  if (!btnScan && !btnNetworks) {
    const firstBtn = document.querySelector("button");
    if (firstBtn) firstBtn.addEventListener("click", analizarIP);
  }
});

// ══════════════════════════════════════════════════════════════
// EXPORTAR para uso en Next.js / módulos ES
// ══════════════════════════════════════════════════════════════
if (typeof module !== "undefined") {
  module.exports = { apiFetch, analizarIP, escanearRedes, renderNetworksTable, accionRed };
}
