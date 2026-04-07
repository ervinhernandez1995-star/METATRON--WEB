#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          METATRON v2 — api.py  (WSL2 / ngrok EDITION)        ║
║   FastAPI + MetatronEngine + DB + Scanner + Skill Creator    ║
║   Groq llama3-70b-8192 | MariaDB | WSL2 Ubuntu               ║
╠══════════════════════════════════════════════════════════════╣
║  FIXES v2.1:                                                 ║
║  • Preflight / OPTIONS respondido explícitamente antes de    ║
║    que cualquier middleware lo intercepte (ruta @app.options)║
║  • CORSMiddleware con allow_credentials=False + wildcard OK  ║
║  • NgrokHeaderMiddleware inyecta el header en TODAS las      ║
║    respuestas, incluidos los 204 del preflight               ║
║  • Parser netsh completamente reescrito: captura bloques     ║
║    multi-BSSID y normaliza campos EN/ES                      ║
║  • Endpoint /analyze alias de /scan para el script.js       ║
║    original sin romper compatibilidad                        ║
╚══════════════════════════════════════════════════════════════╝

INSTRUCCIONES DE USO:
─────────────────────
1. pip install fastapi uvicorn groq mysql-connector-python python-multipart
2. sudo service mariadb start
3. python api.py --init-db   (solo la primera vez)
4. export GROQ_API_KEY="sk-..."
   python api.py
5. ngrok http 8000   → copia la URL https a Vercel como NEXT_PUBLIC_API_URL
"""

import os, sys, json, subprocess, importlib.util, re
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import mysql.connector
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from pydantic import BaseModel
from groq import Groq

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
MODEL        = "llama3-70b-8192"
SKILLS_DIR   = Path(__file__).parent / "skills"
SKILLS_DIR.mkdir(exist_ok=True)

groq_client = Groq(api_key=GROQ_API_KEY)

# ══════════════════════════════════════════════════════════════
# DATABASE LAYER  (sin cambios respecto a v2.0)
# ══════════════════════════════════════════════════════════════

def get_connection():
    for host in ["127.0.0.1", "localhost"]:
        try:
            return mysql.connector.connect(
                host=host, user="metatron", password="1234",
                database="metatron_db", connection_timeout=5)
        except mysql.connector.Error as e:
            last_err = e
    raise last_err

def _dt(v):
    return v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v

def _safe_row(row):
    if row is None: return None
    if isinstance(row, dict): return {k: _dt(v) for k, v in row.items()}
    return tuple(_dt(v) for v in row)

def init_schema():
    conn = get_connection(); c = conn.cursor()
    for sql in [
        """CREATE TABLE IF NOT EXISTS history (
            sl_no INT AUTO_INCREMENT PRIMARY KEY,
            target VARCHAR(255), scan_date DATETIME, status VARCHAR(50))""",
        """CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INT AUTO_INCREMENT PRIMARY KEY, sl_no INT,
            vuln_name VARCHAR(500), severity VARCHAR(50),
            port VARCHAR(50), service VARCHAR(100), description TEXT)""",
        """CREATE TABLE IF NOT EXISTS fixes (
            id INT AUTO_INCREMENT PRIMARY KEY, sl_no INT,
            vuln_id INT, fix_text TEXT, source VARCHAR(50))""",
        """CREATE TABLE IF NOT EXISTS exploits_attempted (
            id INT AUTO_INCREMENT PRIMARY KEY, sl_no INT,
            exploit_name VARCHAR(500), tool_used VARCHAR(200),
            payload TEXT, result VARCHAR(500), notes TEXT)""",
        """CREATE TABLE IF NOT EXISTS summary (
            id INT AUTO_INCREMENT PRIMARY KEY, sl_no INT,
            raw_scan LONGTEXT, ai_analysis LONGTEXT,
            risk_level VARCHAR(50), generated_at DATETIME)""",
        """CREATE TABLE IF NOT EXISTS wifi_networks (
            id INT AUTO_INCREMENT PRIMARY KEY, sl_no INT,
            ssid VARCHAR(255), bssid VARCHAR(50), channel VARCHAR(20),
            signal VARCHAR(20), security VARCHAR(100), scanned_at DATETIME)""",
        """CREATE TABLE IF NOT EXISTS ai_knowledge (
            id INT AUTO_INCREMENT PRIMARY KEY, category VARCHAR(100),
            subject VARCHAR(500), outcome VARCHAR(50),
            confidence FLOAT DEFAULT 0.5, details TEXT, learned_at DATETIME)""",
    ]:
        c.execute(sql)
    conn.commit(); conn.close()
    print("[+] Schema verified / created.")

# ── DB Write ──────────────────────────────────────────────────

def db_create_session(target):
    conn = get_connection(); c = conn.cursor()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history (target,scan_date,status) VALUES (%s,%s,%s)", (target,now,"active"))
    conn.commit(); sl_no = c.lastrowid; conn.close(); return sl_no

def db_save_vulnerability(sl_no, vuln_name, severity, port, service, description):
    conn = get_connection(); c = conn.cursor()
    c.execute("""INSERT INTO vulnerabilities
                 (sl_no,vuln_name,severity,port,service,description) VALUES(%s,%s,%s,%s,%s,%s)""",
              (sl_no,str(vuln_name),str(severity),str(port),str(service),str(description)))
    conn.commit(); vid = c.lastrowid; conn.close(); return vid

def db_save_fix(sl_no, vuln_id, fix_text, source="ai"):
    conn = get_connection(); c = conn.cursor()
    c.execute("INSERT INTO fixes (sl_no,vuln_id,fix_text,source) VALUES(%s,%s,%s,%s)",
              (sl_no,vuln_id,str(fix_text),str(source)))
    conn.commit(); conn.close()

def db_save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection(); c = conn.cursor()
    c.execute("""INSERT INTO exploits_attempted
                 (sl_no,exploit_name,tool_used,payload,result,notes) VALUES(%s,%s,%s,%s,%s,%s)""",
              (sl_no,str(exploit_name or "")[:500],str(tool_used or "")[:200],
               str(payload or ""),str(result or "")[:500],str(notes or "")))
    conn.commit(); conn.close()

def db_save_summary(sl_no, raw_scan, ai_analysis, risk_level):
    conn = get_connection(); c = conn.cursor()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO summary (sl_no,raw_scan,ai_analysis,risk_level,generated_at)
                 VALUES(%s,%s,%s,%s,%s)""",
              (sl_no,str(raw_scan),str(ai_analysis),str(risk_level),now))
    conn.commit(); conn.close()

def db_save_wifi(sl_no, ssid, bssid, channel, signal, security):
    conn = get_connection(); c = conn.cursor()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO wifi_networks
                 (sl_no,ssid,bssid,channel,signal,security,scanned_at) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
              (sl_no,str(ssid),str(bssid),str(channel),str(signal),str(security),now))
    conn.commit(); conn.close()

def db_save_knowledge(category, subject, outcome, confidence, details):
    conn = get_connection(); c = conn.cursor()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO ai_knowledge
                 (category,subject,outcome,confidence,details,learned_at) VALUES(%s,%s,%s,%s,%s,%s)""",
              (str(category),str(subject),str(outcome),float(confidence),str(details),now))
    conn.commit(); conn.close()

def db_delete_session(sl_no):
    conn = get_connection(); c = conn.cursor()
    for tbl in ["fixes","exploits_attempted","vulnerabilities","summary","wifi_networks","history"]:
        c.execute(f"DELETE FROM {tbl} WHERE sl_no=%s", (sl_no,))
    conn.commit(); conn.close()

# ── DB Read ───────────────────────────────────────────────────

def db_get_history():
    conn = get_connection(); c = conn.cursor(dictionary=True)
    c.execute("SELECT sl_no,target,scan_date,status FROM history ORDER BY sl_no DESC")
    rows = [_safe_row(r) for r in c.fetchall()]; conn.close(); return rows

def db_get_session(sl_no):
    conn = get_connection(); c = conn.cursor(dictionary=True)
    c.execute("SELECT * FROM history WHERE sl_no=%s",(sl_no,)); history=_safe_row(c.fetchone())
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no=%s",(sl_no,)); vulns=[_safe_row(r) for r in c.fetchall()]
    c.execute("SELECT * FROM fixes WHERE sl_no=%s",(sl_no,)); fixes=[_safe_row(r) for r in c.fetchall()]
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no=%s",(sl_no,)); exploits=[_safe_row(r) for r in c.fetchall()]
    c.execute("SELECT * FROM summary WHERE sl_no=%s",(sl_no,)); summary=_safe_row(c.fetchone())
    c.execute("SELECT * FROM wifi_networks WHERE sl_no=%s",(sl_no,)); wifi=[_safe_row(r) for r in c.fetchall()]
    conn.close()
    return {"history":history,"vulns":vulns,"fixes":fixes,"exploits":exploits,"summary":summary,"wifi":wifi}

def db_get_wifi(sl_no):
    conn = get_connection(); c = conn.cursor(dictionary=True)
    c.execute("SELECT * FROM wifi_networks WHERE sl_no=%s",(sl_no,))
    rows=[_safe_row(r) for r in c.fetchall()]; conn.close(); return rows

def db_get_knowledge(category=None, limit=30):
    conn = get_connection(); c = conn.cursor(dictionary=True)
    if category:
        c.execute("SELECT * FROM ai_knowledge WHERE category=%s ORDER BY confidence DESC LIMIT %s",(category,limit))
    else:
        c.execute("SELECT * FROM ai_knowledge ORDER BY confidence DESC, learned_at DESC LIMIT %s",(limit,))
    rows=[_safe_row(r) for r in c.fetchall()]; conn.close(); return rows

def knowledge_summary_text(limit=20):
    rows = db_get_knowledge(limit=limit)
    if not rows: return "No prior knowledge recorded."
    lines = ["=== AI ADAPTIVE MEMORY ==="]
    for r in rows:
        lines.append(
            f"[{str(r.get('category','')).upper()}] {r.get('subject','')} | "
            f"outcome={r.get('outcome','')} | conf={str(r.get('confidence',''))[:4]} | "
            f"{str(r.get('details',''))[:100]}")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
# METATRON ENGINE
# ══════════════════════════════════════════════════════════════

class MetatronEngine:

    @staticmethod
    def _run(cmd, timeout=90):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            return f"[timeout] {cmd}"
        except Exception as e:
            return f"[error] {e}"

    @staticmethod
    def run_nmap(target, mode="service"):
        cmds = {
            "service": f"nmap -sV -sC -T4 {target}",
            "full":    f"nmap -p- --open -T4 {target}",
            "vuln":    f"nmap --script vuln {target}",
            "quick":   f"nmap -sn {target}",
        }
        return MetatronEngine._run(cmds.get(mode, cmds["service"]), timeout=120)

    @staticmethod
    def run_whatweb(target): return MetatronEngine._run(f"whatweb {target}", timeout=30)
    @staticmethod
    def run_whois(target):   return MetatronEngine._run(f"whois {target}", timeout=20)
    @staticmethod
    def run_dig(target):     return MetatronEngine._run(f"dig +short {target}", timeout=10)

    # ── Wi-Fi Scanner: nmcli (Linux nativo) ──────────────────

    @staticmethod
    def scan_wifi_nmcli():
        out = MetatronEngine._run(
            "nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list", timeout=20)
        networks = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                networks.append({
                    "ssid":     parts[0] if parts[0] != "--" else "<hidden>",
                    "bssid":    parts[1] if len(parts) > 1 else "N/A",
                    "channel":  parts[2] if len(parts) > 2 else "N/A",
                    "signal":   f"{parts[3]}%" if len(parts) > 3 else "N/A",
                    "security": " ".join(parts[4:]) if len(parts) > 4 else "OPEN",
                })
        return networks, out

    # ── Wi-Fi Scanner: netsh via PowerShell (WSL2 → Windows) ─
    # ─────────────────────────────────────────────────────────
    # Parser robusto: soporta salida en inglés Y español, y captura
    # correctamente varios BSSIDs por SSID.
    #
    # Estructura típica de netsh:
    #   SSID 1                 : MiRed
    #    Network type          : Infrastructure
    #    Authentication        : WPA2-Personal
    #    Encryption            : CCMP
    #    BSSID 1               : aa:bb:cc:dd:ee:ff
    #         Signal           : 72%
    #         Radio type       : 802.11ac
    #         Channel          : 6
    #    BSSID 2               : ...
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def scan_wifi_powershell():
        raw = MetatronEngine._run(
            'powershell.exe -Command "netsh wlan show networks mode=bssid"',
            timeout=20
        )
        networks: list[dict] = []

        # ── Regex patterns (EN + ES, full accent coverage) ────
        RE_SSID     = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
        RE_AUTH     = re.compile(r"^(Authentication|Autenticaci[oó]n)\s*:\s*(.*)$", re.IGNORECASE | re.UNICODE)
        RE_ENCRYPT  = re.compile(r"^(Encryption|Cifrado)\s*:\s*(.*)$", re.IGNORECASE | re.UNICODE)
        RE_BSSID    = re.compile(r"^BSSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
        # "Señal", "Senal", "Signal" — handles ñ as literal or escaped \xf1
        RE_SIGNAL   = re.compile(r"^(Signal|Se[ñn\xf1]al)\s*:\s*(.*)$", re.IGNORECASE | re.UNICODE)
        RE_CHANNEL  = re.compile(r"^(Channel|Canal)\s*:\s*(.*)$", re.IGNORECASE | re.UNICODE)
        RE_RADIO    = re.compile(r"^(Radio type|Tipo de radio)\s*:\s*(.*)$", re.IGNORECASE | re.UNICODE)

        current_ssid    = None
        current_auth    = "N/A"
        current_encrypt = "N/A"
        current_bssid_block: dict | None = None  # bloque en construcción para 1 BSSID

        def flush_bssid():
            """Agrega el bloque BSSID actual a la lista y lo resetea."""
            nonlocal current_bssid_block
            if current_bssid_block and current_ssid:
                entry = {
                    "ssid":       current_ssid,
                    "bssid":      current_bssid_block.get("bssid", "N/A"),
                    "channel":    current_bssid_block.get("channel", "N/A"),
                    "signal":     current_bssid_block.get("signal", "N/A"),
                    "encryption": current_encrypt,          # ← campo separado que pide el frontend
                    "radio":      current_bssid_block.get("radio", "N/A"),
                    "security":   f"{current_auth} / {current_encrypt}",  # ← campo legacy
                }
                networks.append(entry)
            current_bssid_block = None

        for line in raw.splitlines():
            line_s = line.strip()
            if not line_s:
                continue

            m = RE_SSID.match(line_s)
            if m:
                flush_bssid()   # cierra el BSSID anterior (si había)
                current_ssid    = m.group(1).strip() or "<hidden>"
                current_auth    = "N/A"
                current_encrypt = "N/A"
                current_bssid_block = None
                continue

            m = RE_AUTH.match(line_s)
            if m:
                current_auth = m.group(2).strip()
                continue

            m = RE_ENCRYPT.match(line_s)
            if m:
                current_encrypt = m.group(2).strip()
                continue

            m = RE_BSSID.match(line_s)
            if m:
                flush_bssid()   # cierra el BSSID anterior de la misma SSID
                current_bssid_block = {"bssid": m.group(1).strip()}
                continue

            if current_bssid_block is not None:
                m = RE_SIGNAL.match(line_s)
                if m:
                    current_bssid_block["signal"] = m.group(2).strip()
                    continue
                m = RE_CHANNEL.match(line_s)
                if m:
                    current_bssid_block["channel"] = m.group(2).strip()
                    continue
                m = RE_RADIO.match(line_s)
                if m:
                    current_bssid_block["radio"] = m.group(2).strip()
                    continue

        flush_bssid()   # cierra el último bloque
        return networks, raw

    @staticmethod
    def scan_nmap_subnet():
        iface = MetatronEngine._run("ip route show default")
        subnet = "192.168.1.0/24"
        m = re.search(r"src (\d+\.\d+\.\d+)\.", iface)
        if m:
            subnet = f"{m.group(1)}.0/24"
        return MetatronEngine._run(f"nmap -sn --open {subnet}", timeout=60)

    # ── AI Analysis ───────────────────────────────────────────

    @staticmethod
    def analyse(target, raw_scan):
        memory = knowledge_summary_text()
        system = """You are METATRON, expert AI penetration testing assistant.
Return ONLY valid JSON (no markdown, no backticks):
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "vulnerabilities": [{"vuln_name":"","severity":"","port":"","service":"","description":"","fix":""}],
  "exploits": [{"exploit_name":"","tool_used":"","payload":"","result":"","notes":""}],
  "full_response": "narrative"
}"""
        user = f"Target: {target}\n\nSCAN:\n{raw_scan[:6000]}\n\nMEMORY:\n{memory}"
        try:
            resp = groq_client.chat.completions.create(
                model=MODEL,
                messages=[{"role":"system","content":system},{"role":"user","content":user}],
                max_tokens=3000, temperature=0.2
            )
            raw = resp.choices[0].message.content.strip().replace("```json","").replace("```","").strip()
            data = json.loads(raw)
            db_save_knowledge("attack", f"Analysis: {target}",
                              "success" if data.get("vulnerabilities") else "partial",
                              0.8, f"Risk: {data.get('risk_level','?')}")
            data["raw_scan"] = raw_scan
            return data
        except Exception as e:
            db_save_knowledge("attack", f"Analysis failed: {target}", "failure", 0.1, str(e))
            return {"risk_level":"UNKNOWN","vulnerabilities":[],"exploits":[],
                    "full_response":f"Error: {e}","raw_scan":raw_scan}

    # ── Skill Creator ─────────────────────────────────────────

    @staticmethod
    def generate_skill(service, port, context, language="python"):
        memory = knowledge_summary_text()
        system = """You are METATRON Skill Creator.
Output ONLY JSON (no markdown):
{"skill_name":"snake_case","description":"one sentence","language":"python|bash","code":"full script"}
The script must be self-contained, have TARGET='127.0.0.1' at top, print results, be ethical."""
        user = (f"Generate a {language} security testing script for:\n"
                f"Service: {service} | Port: {port} | Context: {context}\n\n"
                f"Prior knowledge:\n{memory}")
        try:
            resp = groq_client.chat.completions.create(
                model=MODEL,
                messages=[{"role":"system","content":system},{"role":"user","content":user}],
                max_tokens=2000, temperature=0.3
            )
            raw = resp.choices[0].message.content.strip().replace("```json","").replace("```","").strip()
            return json.loads(raw)
        except Exception as e:
            return {"skill_name":"error","description":str(e),"language":language,
                    "code":f"# Error: {e}"}

    @staticmethod
    def save_skill(skill_data):
        name = skill_data.get("skill_name","unnamed").replace(" ","_").lower()
        ext  = ".py" if skill_data.get("language","python") == "python" else ".sh"
        path = SKILLS_DIR / f"{name}{ext}"
        with open(path,"w") as f: f.write(skill_data.get("code","# empty"))
        if ext == ".sh": os.chmod(path, 0o755)
        db_save_knowledge("skill", f"Created: {name}", "created", 0.7,
                          f"File: {path} | {skill_data.get('description','')}")
        return str(path)

    @staticmethod
    def run_skill(filename, target="127.0.0.1"):
        path = SKILLS_DIR / filename
        if not path.exists(): return f"[error] Skill not found: {filename}"
        try:
            if path.suffix == ".py":
                spec = importlib.util.spec_from_file_location("skill_mod", path)
                mod  = importlib.util.module_from_spec(spec)
                mod.TARGET = target
                spec.loader.exec_module(mod)
                return str(mod.run(target)) if hasattr(mod,"run") else "[*] Module executed (no run() fn)."
            elif path.suffix == ".sh":
                env = {**os.environ, "TARGET": target}
                r   = subprocess.run(["bash",str(path)], capture_output=True, text=True, timeout=60, env=env)
                return r.stdout + r.stderr
            return "[error] Unknown extension."
        except Exception as e:
            return f"[error] {e}"

    @staticmethod
    def list_skills():
        files = list(SKILLS_DIR.glob("*.py")) + list(SKILLS_DIR.glob("*.sh"))
        return [{"name":f.name,"type":"python" if f.suffix==".py" else "bash",
                 "size":f.stat().st_size} for f in sorted(files)]


# ══════════════════════════════════════════════════════════════
# FASTAPI APP  +  MIDDLEWARE
# ══════════════════════════════════════════════════════════════

app = FastAPI(
    title="METATRON v2 API",
    description="AI Penetration Testing Assistant — REST API Bridge",
    version="2.1.0"
)

# ── 1. NgrokHeaderMiddleware ──────────────────────────────────
# Inyecta 'ngrok-skip-browser-warning' en TODAS las respuestas,
# incluidos los 200/204 de OPTIONS, para que ngrok nunca devuelva
# su página HTML de advertencia en lugar de JSON.
class NgrokHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["ngrok-skip-browser-warning"] = "true"
        response.headers["Access-Control-Allow-Origin"]  = "*"
        if "application/json" in response.headers.get("content-type",""):
            response.headers["content-type"] = "application/json; charset=utf-8"
        return response

app.add_middleware(NgrokHeaderMiddleware)

# ── 2. CORSMiddleware ─────────────────────────────────────────
# IMPORTANTE: allow_credentials=True es INCOMPATIBLE con allow_origins=["*"].
# Usamos allow_credentials=False para que el wildcard funcione.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET","POST","DELETE","OPTIONS","PUT","PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,   # cachea el preflight 10 min en el navegador
)

engine = MetatronEngine()

# ══════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str
    tools: Optional[List[str]] = ["nmap_service"]

class AnalyzeRequest(BaseModel):
    """Alias para compatibilidad con el script.js original (/analyze)."""
    ip: str

class NetworkScanRequest(BaseModel):
    label:  Optional[str] = "wifi_scan"
    method: Optional[str] = "powershell"   # nmcli|powershell|nmap|all

class SkillCreateRequest(BaseModel):
    service:   str
    port:      str
    context:   str
    language:  Optional[str]  = "python"
    auto_save: Optional[bool] = True

class SkillRunRequest(BaseModel):
    filename: str
    target:   Optional[str] = "127.0.0.1"

class KnowledgeAddRequest(BaseModel):
    category:   str
    subject:    str
    outcome:    str
    confidence: Optional[float] = 0.7
    details:    Optional[str]   = ""

# ══════════════════════════════════════════════════════════════
# EXPLICIT OPTIONS HANDLER
# ══════════════════════════════════════════════════════════════
# Responde manualmente a los preflight de CORS antes de que ngrok
# o cualquier middleware pueda interferir.  FastAPI ya lo hace vía
# CORSMiddleware, pero este handler extra garantiza el 200 inmediato.

@app.options("/{full_path:path}")
async def preflight_handler(full_path: str):
    return JSONResponse(
        content={"status": "ok"},
        status_code=200,
        headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, PUT, PATCH, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age":       "600",
            "ngrok-skip-browser-warning":   "true",
        }
    )

# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {
        "status":    "online",
        "app":       "METATRON v2.1",
        "model":     MODEL,
        "endpoints": [
            "/scan", "/analyze", "/network-scan", "/list-networks",
            "/create-skill", "/skills", "/run-skill",
            "/history", "/session/{sl_no}", "/knowledge"
        ]
    }


@app.post("/analyze")
def analyze_ip(req: AnalyzeRequest):
    """
    Endpoint de compatibilidad con el script.js original.
    Recibe { ip: "..." } y devuelve { analysis: "..." }.
    """
    target = req.ip.strip()
    if not target:
        raise HTTPException(400, "ip is required")

    raw_scan = engine.run_nmap(target, "service")
    result   = engine.analyse(target, raw_scan)

    sl_no = db_create_session(target)
    for v in result.get("vulnerabilities", []):
        vid = db_save_vulnerability(sl_no, v.get("vuln_name",""), v.get("severity",""),
                                    v.get("port",""), v.get("service",""), v.get("description",""))
        if v.get("fix"):
            db_save_fix(sl_no, vid, v["fix"], "ai")
    db_save_summary(sl_no, raw_scan, result.get("full_response",""), result.get("risk_level","UNKNOWN"))

    return {
        "sl_no":        sl_no,
        "target":       target,
        "risk_level":   result.get("risk_level","UNKNOWN"),
        "analysis":     result.get("full_response",""),   # ← campo que usa el script.js original
        "vulnerabilities": result.get("vulnerabilities",[]),
    }


@app.post("/scan")
async def scan_target(req: ScanRequest, background_tasks: BackgroundTasks):
    """Full recon + AI analysis of a target."""
    target = req.target.strip()
    if not target:
        raise HTTPException(400, "target is required")

    raw_parts = []
    for tool in req.tools:
        if tool == "nmap_service": raw_parts.append("=== nmap service ===\n" + engine.run_nmap(target,"service"))
        elif tool == "nmap_full":  raw_parts.append("=== nmap full ===\n"    + engine.run_nmap(target,"full"))
        elif tool == "nmap_vuln":  raw_parts.append("=== nmap vuln ===\n"    + engine.run_nmap(target,"vuln"))
        elif tool == "whatweb":    raw_parts.append("=== whatweb ===\n"      + engine.run_whatweb(target))
        elif tool == "whois":      raw_parts.append("=== whois ===\n"        + engine.run_whois(target))
        elif tool == "dig":        raw_parts.append("=== dig ===\n"          + engine.run_dig(target))

    raw_scan = "\n\n".join(raw_parts) or "No scan data"
    result   = engine.analyse(target, raw_scan)
    sl_no    = db_create_session(target)

    for v in result.get("vulnerabilities",[]):
        vid = db_save_vulnerability(sl_no, v.get("vuln_name",""), v.get("severity",""),
                                    v.get("port",""), v.get("service",""), v.get("description",""))
        if v.get("fix"): db_save_fix(sl_no, vid, v["fix"], "ai")
    for e in result.get("exploits",[]):
        db_save_exploit(sl_no, e.get("exploit_name",""), e.get("tool_used",""),
                        e.get("payload",""), e.get("result",""), e.get("notes",""))
    db_save_summary(sl_no, raw_scan, result.get("full_response",""), result.get("risk_level","UNKNOWN"))

    return {
        "sl_no":            sl_no,
        "target":           target,
        "risk_level":       result.get("risk_level","UNKNOWN"),
        "vulnerabilities":  result.get("vulnerabilities",[]),
        "exploits":         result.get("exploits",[]),
        "full_response":    result.get("full_response",""),
        "raw_scan_preview": raw_scan[:1000],
    }


# ── /network-scan  ────────────────────────────────────────────
# Devuelve JSON estructurado:
# {
#   "sl_no": 42,
#   "networks": [
#     { "ssid":"MiRed", "bssid":"aa:bb:...", "channel":"6",
#       "signal":"72%", "security":"WPA2-Personal / CCMP", "radio":"802.11ac" }
#   ],
#   "total_found": 1
# }
@app.post("/network-scan")
def network_scan(req: NetworkScanRequest):
    """Scan nearby Wi-Fi networks and save to DB. Returns structured JSON."""
    sl_no    = db_create_session(req.label or "wifi_scan")
    networks = []
    raw_all  = []
    method   = req.method or "powershell"

    if method in ("nmcli", "all"):
        nets, raw = engine.scan_wifi_nmcli()
        networks.extend(nets)
        raw_all.append(f"=== nmcli ===\n{raw}")

    if method in ("powershell", "all"):
        nets, raw = engine.scan_wifi_powershell()
        networks.extend(nets)
        raw_all.append(f"=== netsh/powershell ===\n{raw}")

    if method in ("nmap", "all"):
        raw = engine.scan_nmap_subnet()
        raw_all.append(f"=== nmap ===\n{raw}")

    for n in networks:
        db_save_wifi(sl_no, n.get("ssid",""), n.get("bssid",""),
                     n.get("channel",""), n.get("signal",""), n.get("security",""))

    return {
        "sl_no":       sl_no,
        "label":       req.label,
        "method":      method,
        "networks":    networks,          # ← lista limpia de objetos JSON
        "total_found": len(networks),
        "raw_preview": "\n".join(raw_all)[:800],
    }


@app.get("/debug-scan")
def debug_scan():
    """Returns raw netsh output for debugging the parser. Remove in production."""
    raw = MetatronEngine._run(
        'powershell.exe -Command "netsh wlan show networks mode=bssid"', timeout=20)
    networks, _ = engine.scan_wifi_powershell()
    return {
        "raw_output": raw,
        "parsed_count": len(networks),
        "parsed_networks": networks,
    }



def list_networks(sl_no: Optional[int] = None):
    if sl_no:
        return {"sl_no": sl_no, "networks": db_get_wifi(sl_no)}
    conn = get_connection(); c = conn.cursor(dictionary=True)
    c.execute("SELECT * FROM wifi_networks ORDER BY id DESC LIMIT 100")
    rows = [_safe_row(r) for r in c.fetchall()]; conn.close()
    return {"networks": rows, "total": len(rows)}


@app.post("/create-skill")
def create_skill(req: SkillCreateRequest):
    skill = engine.generate_skill(req.service, req.port, req.context, req.language or "python")
    filepath = engine.save_skill(skill) if req.auto_save else None
    return {"skill_name":skill.get("skill_name"),"description":skill.get("description"),
            "language":skill.get("language"),"code":skill.get("code"),"saved_to":filepath}


@app.get("/skills")
def list_skills():
    return {"skills": engine.list_skills(), "skills_dir": str(SKILLS_DIR)}


@app.post("/run-skill")
def run_skill(req: SkillRunRequest):
    output = engine.run_skill(req.filename, req.target or "127.0.0.1")
    return {"filename": req.filename, "target": req.target, "output": output}


@app.get("/history")
def history():
    rows = db_get_history()
    return {"sessions": rows, "total": len(rows)}


@app.get("/session/{sl_no}")
def session_detail(sl_no: int):
    data = db_get_session(sl_no)
    if not data["history"]:
        raise HTTPException(404, f"Session SL#{sl_no} not found")
    return data


@app.delete("/session/{sl_no}")
def delete_session(sl_no: int):
    data = db_get_session(sl_no)
    if not data["history"]:
        raise HTTPException(404, f"Session SL#{sl_no} not found")
    db_delete_session(sl_no)
    return {"deleted": True, "sl_no": sl_no}


@app.get("/knowledge")
def get_knowledge(category: Optional[str] = None, limit: int = 30):
    rows = db_get_knowledge(category, limit)
    return {"knowledge": rows, "total": len(rows),
            "summary_text": knowledge_summary_text(limit)}


@app.post("/knowledge")
def add_knowledge(req: KnowledgeAddRequest):
    db_save_knowledge(req.category, req.subject, req.outcome,
                      req.confidence or 0.7, req.details or "")
    return {"saved": True}


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    if "--init-db" in sys.argv:
        try:    init_schema(); print("[+] Database initialized.")
        except Exception as e: print(f"[!] DB init failed: {e}")
        sys.exit(0)

    try:
        conn = get_connection(); conn.close()
        print("[+] MariaDB connection OK")
        init_schema()
    except Exception as e:
        print(f"[!] MariaDB error: {e}\n    Run: sudo service mariadb start")
        sys.exit(1)

    print("""\033[91m
    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m    \033[90mv2.1 — FastAPI Bridge | Groq llama3-70b | WSL2 (CORS + ngrok FIXED)\033[0m
    """)
    print("[+] API docs: http://localhost:8000/docs")
    print("[+] Ready. Expose with: ngrok http 8000\n")

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
