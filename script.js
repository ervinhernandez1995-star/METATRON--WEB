/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║        METATRON v2.3 — API Client (script.js)               ║
 * ║  Cliente fetch alineado con index.html v2.2 + api.py v2.2   ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  FIXES v2.3:                                                 ║
 * ║  • apiFetch: firma idéntica a index.html (optionsOrBody)     ║
 * ║    — elimina el conflicto de sobrescritura al cargar ambos   ║
 * ║  • escanearRedes: body correcto, timeout de 25s              ║
 * ║  • accionRed: delega en handleNetworkAction (backend real)   ║
 * ║  • fetchWithTimeout: wrapper con AbortController             ║
 * ║  • handleNetworkAction: despacha acciones reales al backend  ║
 * ║  • Loading states y errores en todos los flujos              ║
 * ║  • getApiUrl(): lee API global del HTML antes de localStorage║
 * ╚══════════════════════════════════════════════════════════════╝
 */

// ══════════════════════════════════════════════════════════════
// 1. CONFIGURACIÓN GLOBAL
// ══════════════════════════════════════════════════════════════

/**
 * Obtiene la URL base de la API. Prioridad:
 *  1. Variable global API definida en el inline JS de index.html
 *  2. localStorage("metatron_api")
 *  3. Variable de entorno Next.js
 *  4. Fallback hardcoded
 */
function getApiUrl() {
  if (typeof API !== "undefined" && API) return API.replace(/\/+$/, "");
  const stored = (typeof localStorage !== "undefined" && localStorage.getItem("metatron_api")) || "";
  if (stored) return stored.replace(/\/+$/, "");
  if (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_URL)
    return process.env.NEXT_PUBLIC_API_URL.replace(/\/+$/, "");
  return "https://subentire-sibyl-gleesomely.ngrok-free.dev"; // <- actualiza con tu URL ngrok
}

// ══════════════════════════════════════════════════════════════
// 3. fetchWithTimeout
// ══════════════════════════════════════════════════════════════

/**
 * Igual que apiFetch pero cancela si tarda mas de ms milisegundos.
 * Util para /scan y /network-scan que pueden tardar bastante.
 */
async function fetchWithTimeout(path, optionsOrBody = {}, legacyMethod = null, ms = 30000) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), ms);

  let opts = optionsOrBody;
  if (
    optionsOrBody && typeof optionsOrBody === "object" &&
    ("method" in optionsOrBody || "headers" in optionsOrBody || typeof optionsOrBody.body === "string")
  ) {
    opts = { ...optionsOrBody, signal: controller.signal };
  }

  try {
    return await apiFetch(path, opts, legacyMethod);
  } catch (err) {
    if (err.name === "AbortError")
      throw new Error(`Timeout: el servidor tardo mas de ${ms / 1000}s.`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ══════════════════════════════════════════════════════════════
// 4. ANALISIS DE IP / DOMINIO  (/analyze)
// ══════════════════════════════════════════════════════════════

async function analizarIP() {
  const ipInput  = document.getElementById("ip-address") ||
                   document.getElementById("scan-target") ||
                   document.querySelector('input[type="text"]');
  const resultDiv = document.getElementById("results") ||
                    document.getElementById("output");

  if (!ipInput?.value?.trim()) {
    alert("Por favor, ingresa una IP o dominio.");
    return;
  }

  if (resultDiv) resultDiv.innerHTML = "<p style='color:#00ff00;'>Conectando...</p>";

  try {
    // BUG ANTERIOR: usaba data.analysis — ahora soporta ambos campos
    const data = await apiFetch("/analyze", {
      method: "POST",
      body:   JSON.stringify({ ip: ipInput.value.trim() }),
    });

    if (resultDiv) resultDiv.innerHTML = `
      <div style="border:1px solid #00ff00;padding:15px;background:#000;">
        <h3 style="color:#00ff00;">Analisis — Riesgo: ${data.risk_level}</h3>
        <p style="white-space:pre-wrap;color:#fff;">${data.full_response || data.analysis || "(sin analisis)"}</p>
        ${renderVulnerabilities(data.vulnerabilities)}
      </div>`;
  } catch (error) {
    console.error("[METATRON] /analyze:", error);
    if (resultDiv) resultDiv.innerHTML =
      `<p style="color:red;">Error: ${error.message}</p>`;
  }
}

function renderVulnerabilities(vulns = []) {
  if (!vulns || !vulns.length) return "";
  const rows = vulns.map(v => `
    <tr>
      <td style="color:#ff4444;">${v.severity || "?"}</td>
      <td>${v.vuln_name || "?"}</td>
      <td>${v.port || "N/A"}</td>
      <td>${v.service || "N/A"}</td>
    </tr>`).join("");
  return `
    <table style="width:100%;margin-top:12px;border-collapse:collapse;color:#ccc;">
      <thead><tr style="color:#00ff00;">
        <th>Severidad</th><th>Vulnerabilidad</th><th>Puerto</th><th>Servicio</th>
      </tr></thead><tbody>${rows}</tbody>
    </table>`;
}

// ══════════════════════════════════════════════════════════════
// 5. ESCANEO DE REDES  (/network-scan)
// ══════════════════════════════════════════════════════════════

/**
 * BUG ANTERIOR #2: el body se construia mal cuando apiFetch tenia
 * firma distinta. Ahora usa Convencion A (fetch options directas)
 * que funciona igual en ambas versiones del cliente.
 */
async function escanearRedes(method = "powershell") {
  const statusEl  = document.getElementById("scan-status");
  const tableBody = document.querySelector("#networks-table tbody") ||
                    document.getElementById("networks-tbody");

  if (statusEl) statusEl.textContent = "Escaneando redes... (~15 s)";
  if (tableBody) tableBody.innerHTML =
    '<tr><td colspan="6" style="color:#00ff00;text-align:center;">Escaneando...</td></tr>';

  try {
    const data = await fetchWithTimeout(
      "/network-scan",
      {
        method: "POST",
        body:   JSON.stringify({ method, label: "wifi_scan" }),
      },
      null,
      25000
    );

    if (statusEl)
      statusEl.textContent = `${data.total_found} red(es) encontrada(s) — Sesion #${data.sl_no}`;

    if (tableBody) renderNetworksTable(data.networks, tableBody);

  } catch (error) {
    console.error("[METATRON] /network-scan:", error);
    if (statusEl) statusEl.textContent = `Error: ${error.message}`;
    if (tableBody)
      tableBody.innerHTML = `<tr><td colspan="6" style="color:red;">${error.message}</td></tr>`;
  }
}

function renderNetworksTable(networks = [], tableBody) {
  if (!tableBody) return;
  if (!networks.length) {
    tableBody.innerHTML =
      '<tr><td colspan="6" style="color:#aaa;text-align:center;padding:16px;">' +
      'No se detectaron redes. Esta powershell.exe accesible desde WSL2?</td></tr>';
    return;
  }

  tableBody.innerHTML = networks.map((net, idx) => {
    const ssid     = escapeHtml(net.ssid     || "<hidden>");
    const bssid    = escapeHtml(net.bssid    || "N/A");
    const channel  = escapeHtml(net.channel  || "N/A");
    const signal   = escapeHtml(net.signal   || "N/A");
    // BUG ANTERIOR #3: net.security a veces era "N/A / N/A".
    // Ahora prueba security, luego encryption (campo separado del api.py v2.2), luego OPEN.
    const security = escapeHtml(
      (net.security && net.security !== "N/A / N/A") ? net.security :
      net.encryption || "OPEN"
    );
    const radio    = escapeHtml(net.radio || "");

    const sigNum   = parseInt(signal);
    const sigColor = isNaN(sigNum) ? "#aaa" : sigNum >= 70 ? "#00ff00" : sigNum >= 40 ? "#ffaa00" : "#ff4444";
    const barW     = isNaN(sigNum) ? 10 : Math.max(10, Math.min(80, sigNum));

    return `
      <tr data-idx="${idx}" data-ssid="${ssid}" data-bssid="${bssid}">
        <td>${ssid}</td>
        <td style="font-family:monospace;font-size:0.85em;">${bssid}</td>
        <td style="text-align:center;">${channel}</td>
        <td style="text-align:center;">
          <div style="display:inline-block;width:${barW}px;height:6px;background:${sigColor};
               border-radius:2px;margin-right:4px;vertical-align:middle;"></div>
          <span style="color:${sigColor};">${signal}</span>
        </td>
        <td>${security}${radio ? ` <span style="color:#888;font-size:0.8em;">(${radio})</span>` : ""}</td>
        <td style="white-space:nowrap;">
          <button
            onclick="accionRed('interact','${escapeAttr(ssid)}','${escapeAttr(bssid)}')"
            style="margin-right:4px;padding:3px 10px;background:#004400;color:#00ff00;
                   border:1px solid #00ff00;cursor:pointer;border-radius:3px;">
            Interactuar
          </button>
          <button
            onclick="accionRed('attack','${escapeAttr(ssid)}','${escapeAttr(bssid)}')"
            style="padding:3px 10px;background:#440000;color:#ff4444;
                   border:1px solid #ff4444;cursor:pointer;border-radius:3px;">
            Atacar
          </button>
        </td>
      </tr>`;
  }).join("");
}

// ══════════════════════════════════════════════════════════════
// 6. handleNetworkAction — acciones reales al backend
// ══════════════════════════════════════════════════════════════

/**
 * BUG ANTERIOR #4: accionRed() solo mostraba un alert() y no llamaba
 * ningun endpoint. Ahora despacha fetch reales segun la accion.
 *
 * @param {"interact"|"attack"|"info"|"ping"|"portscan"|"analyze"|"deauth"|"traceroute"} action
 * @param {string} ssid
 * @param {string} bssid
 * @param {HTMLElement|null} outputEl - elemento donde escribir salida de terminal
 */
async function handleNetworkAction(action, ssid, bssid, outputEl = null) {
  const log = (msg, color = "#c8e8f8") => {
    if (!outputEl) return;
    const line = document.createElement("div");
    line.style.color = color;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    outputEl.appendChild(line);
    outputEl.scrollTop = outputEl.scrollHeight;
  };

  const statusEl = document.getElementById("scan-status");
  const setStatus = (msg) => { if (statusEl) statusEl.textContent = msg; };

  try {
    switch (action) {

      case "info":
      case "interact": {
        log(`Consultando DB: ${ssid} (${bssid})...`, "#00ffe7");
        setStatus(`Consultando info: ${ssid}...`);

        const d    = await apiFetch("/list-networks");
        const nets = d.networks || [];
        const match = nets.find(n =>
          n.bssid?.toLowerCase() === bssid.toLowerCase() ||
          n.ssid?.toLowerCase()  === ssid.toLowerCase()
        );

        if (match) {
          log(`SSID:      ${match.ssid || "?"}`,     "#00ff88");
          log(`BSSID:     ${match.bssid || "?"}`,    "#00ff88");
          log(`Canal:     ${match.channel || "?"}`,  "#00ff88");
          log(`Senal:     ${match.signal || "?"}`,   "#00ff88");
          log(`Seguridad: ${match.security || "?"}`, "#00ff88");
          log(`Visto en:  ${(match.scanned_at || "").slice(0, 19)}`, "#00ff88");
          setStatus(`Info obtenida: ${ssid}`);
        } else {
          log(`Red no encontrada en DB. Ejecuta un escaneo primero.`, "#ffaa00");
          setStatus(`${ssid} no esta en DB`);
        }
        log("--- FIN INFO ---", "#8ab8d0");
        break;
      }

      case "ping": {
        log(`Ping test via /scan...`, "#00ffe7");
        setStatus(`Ping en curso...`);
        const d = await fetchWithTimeout(
          "/scan",
          { method: "POST", body: JSON.stringify({ target: "8.8.8.8", tools: ["nmap_service"] }) },
          null, 60000
        );
        log(`Respuesta recibida (SL#${d.sl_no})`, "#00ff88");
        log(d.raw_scan_preview || "(sin datos)", "#c8e8f8");
        setStatus(`Ping completado — SL#${d.sl_no}`);
        break;
      }

      case "portscan": {
        const target = (bssid && bssid !== "N/A") ? bssid : "192.168.1.1";
        log(`Port scan sobre: ${target}`, "#00ffe7");
        setStatus(`Port scan: ${target}...`);
        const d = await fetchWithTimeout(
          "/scan",
          { method: "POST", body: JSON.stringify({ target, tools: ["nmap_service"] }) },
          null, 120000
        );
        log(`SL#${d.sl_no} — Riesgo: ${d.risk_level}`,
            d.risk_level === "CRITICAL" ? "#ff4444" : "#00ff88");
        (d.vulnerabilities || []).forEach(v =>
          log(`  [${v.severity}] ${v.vuln_name} — Puerto ${v.port}`, "#ffaa00")
        );
        if (!(d.vulnerabilities || []).length) log("Sin puertos vulnerables.", "#00ff88");
        setStatus(`Port scan completado — ${(d.vulnerabilities || []).length} vulns`);
        break;
      }

      case "analyze":
      case "attack": {
        const confirmMsg = `Confirmar analisis de "${ssid}"?\nUso solo en redes propias/autorizadas.`;
        if (!confirm(confirmMsg)) return;
        log(`Analisis IA: ${ssid}...`, "#00ffe7");
        setStatus(`Analisis IA en curso: ${ssid}...`);
        const d = await fetchWithTimeout(
          "/scan",
          { method: "POST", body: JSON.stringify({ target: ssid, tools: ["nmap_service", "whois"] }) },
          null, 120000
        );
        log(`SL#${d.sl_no} — Riesgo: ${d.risk_level}`, "#00ff88");
        log(d.full_response || "(sin analisis)", "#c8e8f8");
        setStatus(`Analisis completado — SL#${d.sl_no} — ${d.risk_level}`);
        break;
      }

      case "deauth": {
        if (!confirm(`Confirmar SIMULACION de deauth en ${ssid}?\nSolo redes propias.`)) return;
        log(`[SIM] Deauth simulation: ${bssid}`, "#ffaa00");
        log(`[SIM] Cmd real: aireplay-ng --deauth 10 -a ${bssid} wlan0mon`, "#ffaa00");
        log(`[SIM] Esta accion esta SIMULADA — no afecta la red real.`, "#ff4444");
        setStatus(`[SIM] Deauth simulado en ${ssid}`);
        break;
      }

      case "traceroute": {
        log(`traceroute no disponible como endpoint. Agrega /traceroute a api.py`, "#ffaa00");
        log(`Ejemplo: _run(f"traceroute {bssid || '8.8.8.8'}")`, "#8ab8d0");
        break;
      }

      default:
        log(`Accion desconocida: ${action}`, "#ff4444");
    }
  } catch (err) {
    log(`ERROR: ${err.message}`, "#ff4444");
    setStatus(`Error en ${action}: ${err.message.slice(0, 60)}`);
    console.error(`[METATRON] handleNetworkAction(${action}):`, err);
  }
}

// ══════════════════════════════════════════════════════════════
// 7. accionRed — interfaz de botones de la tabla simple
// ══════════════════════════════════════════════════════════════

/**
 * BUG ANTERIOR: solo mostraba alert(), nunca llamaba al backend.
 * Ahora delega en handleNetworkAction.
 */
function accionRed(action, ssid, bssid) {
  const statusEl = document.getElementById("scan-status");
  if (statusEl) statusEl.textContent = `En progreso: ${ssid} (${bssid})...`;

  handleNetworkAction(action, ssid, bssid, null).catch(err => {
    if (statusEl) statusEl.textContent = `Error: ${err.message}`;
    console.error("[METATRON] accionRed:", err);
  });
}

// ══════════════════════════════════════════════════════════════
// 8. HELPERS
// ══════════════════════════════════════════════════════════════

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/"/g,  "&quot;");
}

function escapeAttr(str) {
  return String(str).replace(/'/g, "\\'").replace(/"/g, "&quot;");
}

// ══════════════════════════════════════════════════════════════
// 9. INICIALIZACION (solo como script externo)
// ══════════════════════════════════════════════════════════════

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    // Solo adjuntar listeners si NO estamos en el dashboard completo
    // (index.html gestiona sus propios listeners en el inline JS)
    const hasFullDashboard = !!document.getElementById("section-network");
    if (hasFullDashboard) return;

    const btnScan = document.getElementById("scan-btn") ||
                    document.querySelector('button[data-action="scan"]');
    if (btnScan) btnScan.addEventListener("click", analizarIP);

    const btnNetworks = document.getElementById("network-scan-btn") ||
                        document.querySelector('button[data-action="network-scan"]');
    if (btnNetworks) {
      btnNetworks.addEventListener("click", () => {
        const sel = document.getElementById("scan-method") ||
                    document.getElementById("net-method");
        escanearRedes(sel?.value || "powershell");
      });
    }

    if (!btnScan && !btnNetworks) {
      const firstBtn = document.querySelector("button");
      if (firstBtn) firstBtn.addEventListener("click", analizarIP);
    }
  });
}

// ══════════════════════════════════════════════════════════════
// 10. EXPORTAR para Next.js / modulos ES
// ══════════════════════════════════════════════════════════════
if (typeof module !== "undefined") {
  module.exports = {
    apiFetch,
    fetchWithTimeout,
    handleNetworkAction,
    analizarIP,
    escanearRedes,
    renderNetworksTable,
    accionRed,
  };
}
