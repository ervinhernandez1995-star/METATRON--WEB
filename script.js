// ======================================================
// CONFIGURACIÓN API (NGROK)
// ======================================================
const API_URL = "https://subentire-sibyl-gleesomely.ngrok-free.dev";

// ======================================================
// ELEMENTOS DEL DOM
// ======================================================
const scanBtn = document.getElementById("scanBtn");
const tableBody = document.getElementById("wifiTableBody");
const statusText = document.getElementById("status");

// ======================================================
// FUNCIÓN PRINCIPAL SCAN
// ======================================================
async function scanNetworks() {
    try {
        statusText.innerText = "Escaneando redes... 📡";

        const response = await fetch(`${API_URL}/network-scan`, {
            method: "POST"
        });

        const data = await response.json();

        if (!data.success) {
            statusText.innerText = "Error al escanear ❌";
            console.error(data);
            return;
        }

        renderTable(data.networks);
        statusText.innerText = `Redes encontradas: ${data.total_found} ✅`;

    } catch (error) {
        statusText.innerText = "Error de conexión ❌";
        console.error(error);
    }
}

// ======================================================
// RENDER TABLA
// ======================================================
function renderTable(networks) {
    tableBody.innerHTML = "";

    networks.forEach((net, index) => {
        const row = document.createElement("tr");

        row.innerHTML = `
            <td>${index + 1}</td>
            <td>${net.ssid}</td>
            <td>${net.bssid}</td>
            <td>${getSignalBar(net.signal)}</td>
            <td>${net.channel}</td>
            <td>${net.security}</td>
        `;

        tableBody.appendChild(row);
    });
}

// ======================================================
// BARRA DE SEÑAL VISUAL 🔥
// ======================================================
function getSignalBar(signal) {
    const value = parseInt(signal);

    let color = "red";
    if (value > 70) color = "green";
    else if (value > 40) color = "orange";

    return `
        <div style="background:#ddd;width:100px;border-radius:5px;">
            <div style="
                width:${value}%;
                background:${color};
                height:10px;
                border-radius:5px;
            "></div>
        </div>
        <span>${value}%</span>
    `;
}

// ======================================================
// EVENTO BOTÓN
// ======================================================
scanBtn.addEventListener("click", scanNetworks);
