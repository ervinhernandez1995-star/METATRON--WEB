import re
import subprocess
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# ========================================================
# 1. CONFIGURACIÓN CORS + NGROK
# ========================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Header para evitar advertencia de ngrok
NGROK_HEADERS = {"ngrok-skip-browser-warning": "true"}

# ========================================================
# 2. PARSER WIFI (ROBUSTO MULTI-IDIOMA)
# ========================================================
def parse_wifi_output(text):
    networks = []
    blocks = re.split(r'SSID \d+ :', text)

    for block in blocks[1:]:
        network = {}

        ssid_match = re.search(r'^\s*(.*)', block, re.MULTILINE)
        bssid_match = re.search(r'BSSID \d+\s*:\s*([0-9a-fA-F:]{17})', block)

        # Soporta español e inglés
        signal_match = re.search(r'(Se.al|Signal)\s*:\s*(\d+)%?', block)
        channel_match = re.search(r'(Canal|Channel)\s*:\s*(\d+)', block)

        if ssid_match:
            network['ssid'] = ssid_match.group(1).strip() or "Desconocida"
            network['bssid'] = bssid_match.group(1) if bssid_match else "N/A"

            # Solo número limpio
            network['signal'] = signal_match.group(2) if signal_match else "0"
            network['channel'] = channel_match.group(2) if channel_match else "N/A"

            # Seguridad básica
            if "WPA3" in block:
                network['security'] = "WPA3"
            elif "WPA2" in block:
                network['security'] = "WPA2"
            elif "WPA" in block:
                network['security'] = "WPA"
            else:
                network['security'] = "Open"

            networks.append(network)

    return networks

# ========================================================
# 3. RUTAS API
# ========================================================

@app.get("/")
async def root():
    return JSONResponse(
        content={"status": "METATRON v2.0 ONLINE", "system": "WSL2-Ubuntu"},
        headers=NGROK_HEADERS
    )

# 🔥 ENDPOINT PRINCIPAL (YA COMPATIBLE CON TU FRONTEND)
@app.post("/network-scan")
async def network_scan(request: Request):
    try:
        cmd = ["powershell.exe", "-Command", "netsh wlan show networks mode=bssid"]
        raw_result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=False)

        decoded_data = raw_result.decode('cp1252', errors='ignore')
        networks_list = parse_wifi_output(decoded_data)

        return JSONResponse(
            content={
                "success": True,
                "message": "Scan completado",
                "networks": networks_list,                 # 👈 CLAVE CORRECTA
                "total_found": len(networks_list),         # 👈 PARA TU UI
                "sl_no": 1                                 # 👈 ID sesión (puedes mejorar luego)
            },
            headers=NGROK_HEADERS
        )

    except Exception as e:
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
            headers=NGROK_HEADERS
        )

# 🔁 LISTADO SIMPLE
@app.get("/list-networks")
async def list_networks():
    try:
        cmd = ["powershell.exe", "-Command", "netsh wlan show networks mode=bssid"]
        raw_result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=False)

        decoded_data = raw_result.decode('cp1252', errors='ignore')
        networks_list = parse_wifi_output(decoded_data)

        return JSONResponse(
            content={
                "success": True,
                "networks": networks_list   # 👈 IMPORTANTE
            },
            headers=NGROK_HEADERS
        )

    except Exception as e:
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
            headers=NGROK_HEADERS
        )

# ========================================================
# 4. RUN SERVER
# ========================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
