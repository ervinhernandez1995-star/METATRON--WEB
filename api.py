#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║            METATRON v2 — api.py (ARCHIVO ÚNICO)              ║
║   FastAPI + MetatronEngine + DB + Scanner + Skill Creator    ║
║   Groq llama3-70b-8192 | MariaDB | WSL2 Ubuntu               ║
╚══════════════════════════════════════════════════════════════╝

INSTRUCCIONES DE USO:
─────────────────────
1. INSTALAR DEPENDENCIAS:
   pip install fastapi uvicorn groq mysql-connector-python python-multipart

2. INICIAR MARIADB:
   sudo service mariadb start

3. CREAR BASE DE DATOS (solo la primera vez):
   sudo mysql -e "
     CREATE DATABASE IF NOT EXISTS metatron_db;
     CREATE USER IF NOT EXISTS 'metatron'@'localhost' IDENTIFIED BY '1234';
     GRANT ALL PRIVILEGES ON metatron_db.* TO 'metatron'@'localhost';
     FLUSH PRIVILEGES;"
   python api.py --init-db

4. CORRER EL SERVIDOR:
   export GROQ_API_KEY="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"
   python api.py

5. EXPONER CON NGROK (para Vercel):
   ngrok http 8000
   → Copia la URL https://xxxx.ngrok-free.app y úsala en Vercel

6. ENDPOINTS DISPONIBLES:
   GET  /                    → Status del servidor
   POST /scan                → Análisis completo de un objetivo
   GET  /list-networks       → Listar redes Wi-Fi escaneadas
   POST /network-scan        → Ejecutar Scanner Pro (nmcli/netsh/nmap)
   POST /create-skill        → Generar skill con IA
   GET  /skills              → Listar skills disponibles
   POST /run-skill           → Ejecutar un skill
   GET  /history             → Historial de sesiones
   GET  /session/{sl_no}     → Detalle de sesión
   GET  /knowledge           → Base de conocimiento adaptativa
   POST /knowledge           → Agregar conocimiento manual
   DELETE /session/{sl_no}   → Borrar sesión completa
"""

# ══════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════

import os
import sys
import json
import subprocess
import importlib.util
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import mysql.connector
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from groq import Groq

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════

GROQ_API_KEY = os.environ.get(
    "GROQ_API_KEY",
    "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"
)
MODEL        = "llama3-70b-8192"
SKILLS_DIR   = Path(__file__).parent / "skills"
SKILLS_DIR.mkdir(exist_ok=True)

groq_client  = Groq(api_key=GROQ_API_KEY)


# ══════════════════════════════════════════════════════════════
# ── DATABASE LAYER ────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════

def get_connection():
    """
    Try localhost first, fall back to 127.0.0.1.
    Fixes MariaDB privilege issues where only one host binding is granted.
    """
    hosts = ["127.0.0.1", "localhost"]
    last_err = None
    for host in hosts:
        try:
            return mysql.connector.connect(
                host=host,
                user="metatron",
                password="1234",
                database="metatron_db",
                connection_timeout=5,
            )
        except mysql.connector.Error as e:
            last_err = e
    raise last_err


def _dt(v):
    """Safely convert datetime (or anything) to string."""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return v


def _safe_row(row):
    if row is None:
        return None
    if isinstance(row, dict):
        return {k: _dt(v) for k, v in row.items()}
    return tuple(_dt(v) for v in row)


def init_schema():
    conn = get_connection()
    c = conn.cursor()
    tables = [
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
    ]
    for sql in tables:
        c.execute(sql)
    conn.commit()
    conn.close()
    print("[+] Schema verified / created.")


# ── DB Write ──────────────────────────────────────────────────

def db_create_session(target: str) -> int:
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history (target, scan_date, status) VALUES (%s,%s,%s)",
              (target, now, "active"))
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def db_save_vulnerability(sl_no, vuln_name, severity, port, service, description) -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute("""INSERT INTO vulnerabilities
                 (sl_no,vuln_name,severity,port,service,description) VALUES(%s,%s,%s,%s,%s,%s)""",
              (sl_no, str(vuln_name), str(severity), str(port), str(service), str(description)))
    conn.commit()
    vid = c.lastrowid
    conn.close()
    return vid


def db_save_fix(sl_no, vuln_id, fix_text, source="ai"):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO fixes (sl_no,vuln_id,fix_text,source) VALUES(%s,%s,%s,%s)",
              (sl_no, vuln_id, str(fix_text), str(source)))
    conn.commit()
    conn.close()


def db_save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""INSERT INTO exploits_attempted
                 (sl_no,exploit_name,tool_used,payload,result,notes) VALUES(%s,%s,%s,%s,%s,%s)""",
              (sl_no, str(exploit_name or "")[:500], str(tool_used or "")[:200],
               str(payload or ""), str(result or "")[:500], str(notes or "")))
    conn.commit()
    conn.close()


def db_save_summary(sl_no, raw_scan, ai_analysis, risk_level):
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO summary (sl_no,raw_scan,ai_analysis,risk_level,generated_at)
                 VALUES(%s,%s,%s,%s,%s)""",
              (sl_no, str(raw_scan), str(ai_analysis), str(risk_level), now))
    conn.commit()
    conn.close()


def db_save_wifi(sl_no, ssid, bssid, channel, signal, security):
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO wifi_networks
                 (sl_no,ssid,bssid,channel,signal,security,scanned_at) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
              (sl_no, str(ssid), str(bssid), str(channel), str(signal), str(security), now))
    conn.commit()
    conn.close()


def db_save_knowledge(category, subject, outcome, confidence, details):
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO ai_knowledge
                 (category,subject,outcome,confidence,details,learned_at) VALUES(%s,%s,%s,%s,%s,%s)""",
              (str(category), str(subject), str(outcome), float(confidence), str(details), now))
    conn.commit()
    conn.close()


def db_delete_session(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    for table in ["fixes", "exploits_attempted", "vulnerabilities", "summary", "wifi_networks", "history"]:
        c.execute(f"DELETE FROM {table} WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()


# ── DB Read ───────────────────────────────────────────────────

def db_get_history():
    conn = get_connection()
    c = conn.cursor(dictionary=True)
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = [_safe_row(r) for r in c.fetchall()]
    conn.close()
    return rows


def db_get_session(sl_no: int) -> dict:
    conn = get_connection()
    c = conn.cursor(dictionary=True)
    c.execute("SELECT * FROM history WHERE sl_no=%s", (sl_no,))
    history = _safe_row(c.fetchone())
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no=%s", (sl_no,))
    vulns = [_safe_row(r) for r in c.fetchall()]
    c.execute("SELECT * FROM fixes WHERE sl_no=%s", (sl_no,))
    fixes = [_safe_row(r) for r in c.fetchall()]
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no=%s", (sl_no,))
    exploits = [_safe_row(r) for r in c.fetchall()]
    c.execute("SELECT * FROM summary WHERE sl_no=%s", (sl_no,))
    summary = _safe_row(c.fetchone())
    c.execute("SELECT * FROM wifi_networks WHERE sl_no=%s", (sl_no,))
    wifi = [_safe_row(r) for r in c.fetchall()]
    conn.close()
    return {"history": history, "vulns": vulns, "fixes": fixes,
            "exploits": exploits, "summary": summary, "wifi": wifi}


def db_get_knowledge(category=None, limit=30) -> list:
    conn = get_connection()
    c = conn.cursor(dictionary=True)
    if category:
        c.execute("SELECT * FROM ai_knowledge WHERE category=%s ORDER BY confidence DESC LIMIT %s",
                  (category, limit))
    else:
        c.execute("SELECT * FROM ai_knowledge ORDER BY confidence DESC, learned_at DESC LIMIT %s",
                  (limit,))
    rows = [_safe_row(r) for r in c.fetchall()]
    conn.close()
    return rows


def db_get_wifi(sl_no: int) -> list:
    conn = get_connection()
    c = conn.cursor(dictionary=True)
    c.execute("SELECT * FROM wifi_networks WHERE sl_no=%s", (sl_no,))
    rows = [_safe_row(r) for r in c.fetchall()]
    conn.close()
    return rows


def knowledge_summary_text(limit=20) -> str:
    rows = db_get_knowledge(limit=limit)
    if not rows:
        return "No prior knowledge recorded."
    lines = ["=== AI ADAPTIVE MEMORY ==="]
    for r in rows:
        lines.append(
            f"[{str(r.get('category','')).upper()}] {r.get('subject','')} | "
            f"outcome={r.get('outcome','')} | conf={str(r.get('confidence',''))[:4]} | "
            f"{str(r.get('details',''))[:100]}"
        )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
# ── METATRON ENGINE ───────────────────────────────────────────
# ══════════════════════════════════════════════════════════════

class MetatronEngine:
    """Core logic: scanning, AI analysis, skill creation."""

    # ── Recon Tools ───────────────────────────────────────────

    @staticmethod
    def _run(cmd: str, timeout=90) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            return (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            return f"[timeout] {cmd}"
        except Exception as e:
            return f"[error] {e}"

    @staticmethod
    def run_nmap(target: str, mode: str = "service") -> str:
        cmds = {
            "service":   f"nmap -sV -sC -T4 {target}",
            "full":      f"nmap -p- --open -T4 {target}",
            "vuln":      f"nmap --script vuln {target}",
            "quick":     f"nmap -sn {target}",
        }
        cmd = cmds.get(mode, cmds["service"])
        return MetatronEngine._run(cmd, timeout=120)

    @staticmethod
    def run_whatweb(target: str) -> str:
        return MetatronEngine._run(f"whatweb {target}", timeout=30)

    @staticmethod
    def run_whois(target: str) -> str:
        return MetatronEngine._run(f"whois {target}", timeout=20)

    @staticmethod
    def run_dig(target: str) -> str:
        return MetatronEngine._run(f"dig +short {target}", timeout=10)

    # ── Network Scanner (Wi-Fi) ───────────────────────────────

    @staticmethod
    def scan_wifi_nmcli() -> tuple:
        out = MetatronEngine._run(
            "nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list", timeout=20
        )
        networks = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                networks.append({
                    "ssid":     parts[0] if parts[0] != "--" else "<hidden>",
                    "bssid":    parts[1] if len(parts) > 1 else "N/A",
                    "channel":  parts[2] if len(parts) > 2 else "N/A",
                    "signal":   parts[3] if len(parts) > 3 else "N/A",
                    "security": " ".join(parts[4:]) if len(parts) > 4 else "N/A",
                })
        return networks, out

    @staticmethod
    def scan_wifi_powershell() -> tuple:
        out = MetatronEngine._run(
            'powershell.exe -Command "netsh wlan show networks mode=bssid"',
            timeout=15
        )
        networks = []
        current: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                if current.get("ssid"):
                    networks.append(current)
                current = {"ssid": line.split(":", 1)[-1].strip(),
                           "bssid": "N/A", "channel": "N/A",
                           "signal": "N/A", "security": "N/A"}
            elif "BSSID" in line:
                current["bssid"] = line.split(":", 1)[-1].strip()
            elif "Channel" in line or "Canal" in line:
                current["channel"] = line.split(":", 1)[-1].strip()
            elif "Signal" in line or "Señal" in line:
                current["signal"] = line.split(":", 1)[-1].strip()
            elif "Authentication" in line or "Autenticación" in line:
                current["security"] = line.split(":", 1)[-1].strip()
        if current.get("ssid"):
            networks.append(current)
        return networks, out

    @staticmethod
    def scan_nmap_subnet() -> str:
        iface = MetatronEngine._run("ip route show default")
        subnet = "192.168.1.0/24"
        m = re.search(r"src (\d+\.\d+\.\d+)\.", iface)
        if m:
            subnet = f"{m.group(1)}.0/24"
        return MetatronEngine._run(f"nmap -sn --open {subnet}", timeout=60)

    # ── AI Analysis ───────────────────────────────────────────

    @staticmethod
    def analyse(target: str, raw_scan: str) -> dict:
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
            # Learn from this
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
    def generate_skill(service: str, port: str, context: str, language: str = "python") -> dict:
        memory = knowledge_summary_text()
        system = """You are METATRON Skill Creator.
Output ONLY JSON (no markdown):
{"skill_name":"snake_case","description":"one sentence","language":"python|bash","code":"full script"}
The script must: be self-contained, have TARGET='127.0.0.1' at top, print results, be ethical."""
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
            data = json.loads(raw)
            return data
        except Exception as e:
            return {"skill_name":"error","description":str(e),"language":language,
                    "code":f"# Error: {e}"}

    @staticmethod
    def save_skill(skill_data: dict) -> str:
        name = skill_data.get("skill_name","unnamed").replace(" ","_").lower()
        ext  = ".py" if skill_data.get("language","python") == "python" else ".sh"
        path = SKILLS_DIR / f"{name}{ext}"
        with open(path, "w") as f:
            f.write(skill_data.get("code","# empty"))
        if ext == ".sh":
            os.chmod(path, 0o755)
        db_save_knowledge("skill", f"Created: {name}", "created", 0.7,
                          f"File: {path} | {skill_data.get('description','')}")
        return str(path)

    @staticmethod
    def run_skill(filename: str, target: str = "127.0.0.1") -> str:
        path = SKILLS_DIR / filename
        if not path.exists():
            return f"[error] Skill not found: {filename}"
        try:
            if path.suffix == ".py":
                spec = importlib.util.spec_from_file_location("skill_mod", path)
                mod  = importlib.util.module_from_spec(spec)
                mod.TARGET = target  # type: ignore
                spec.loader.exec_module(mod)  # type: ignore
                if hasattr(mod, "run"):
                    return str(mod.run(target))
                return "[*] Module executed (no run() fn)."
            elif path.suffix == ".sh":
                env = {**os.environ, "TARGET": target}
                r = subprocess.run(["bash", str(path)],
                                   capture_output=True, text=True, timeout=60, env=env)
                return r.stdout + r.stderr
            return "[error] Unknown extension."
        except Exception as e:
            return f"[error] {e}"

    @staticmethod
    def list_skills() -> list:
        files = list(SKILLS_DIR.glob("*.py")) + list(SKILLS_DIR.glob("*.sh"))
        return [{"name": f.name, "type": "python" if f.suffix==".py" else "bash",
                 "size": f.stat().st_size} for f in sorted(files)]


# ══════════════════════════════════════════════════════════════
# ── FASTAPI APP ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════

app = FastAPI(
    title="METATRON v2 API",
    description="AI Penetration Testing Assistant — REST API Bridge",
    version="2.0.0"
)

# ── Middleware: strip ngrok browser-warning for ALL responses ─
# ngrok intercepts requests without this header and returns an HTML
# warning page instead of JSON — this causes "Unexpected token '<'" errors.
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

class NgrokHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        # Tell ngrok to skip its interstitial warning page
        response.headers["ngrok-skip-browser-warning"] = "true"
        # Ensure JSON content-type is never overridden
        if "application/json" in response.headers.get("content-type", ""):
            response.headers["content-type"] = "application/json; charset=utf-8"
        return response

app.add_middleware(NgrokHeaderMiddleware)

# ── CORS (allows Vercel + ngrok frontend) ────────────────────
# NOTE: allow_credentials=True is INCOMPATIBLE with allow_origins=["*"].
# We set allow_credentials=False so the wildcard origin works correctly.
# This is safe for a local pentest tool accessed via ngrok.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

engine = MetatronEngine()


# ── Pydantic Models ───────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    tools: Optional[List[str]] = ["nmap_service"]   # nmap_service|nmap_full|nmap_vuln|whatweb|whois|dig

class NetworkScanRequest(BaseModel):
    label: Optional[str] = "wifi_scan"
    method: Optional[str] = "powershell"   # nmcli|powershell|nmap|all

class SkillCreateRequest(BaseModel):
    service: str
    port: str
    context: str
    language: Optional[str] = "python"
    auto_save: Optional[bool] = True

class SkillRunRequest(BaseModel):
    filename: str
    target: Optional[str] = "127.0.0.1"

class KnowledgeAddRequest(BaseModel):
    category: str
    subject: str
    outcome: str
    confidence: Optional[float] = 0.7
    details: Optional[str] = ""


# ── Routes ────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "status": "online",
        "app": "METATRON v2",
        "model": MODEL,
        "endpoints": ["/scan", "/network-scan", "/list-networks",
                      "/create-skill", "/skills", "/run-skill",
                      "/history", "/session/{sl_no}", "/knowledge"]
    }


@app.post("/scan")
async def scan_target(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Full recon + AI analysis of a target.
    Runs tools, sends to Groq, saves everything to DB.
    """
    target = req.target.strip()
    if not target:
        raise HTTPException(400, "target is required")

    # Run selected tools
    raw_parts = []
    for tool in req.tools:
        if tool == "nmap_service":
            raw_parts.append("=== nmap service ===\n" + engine.run_nmap(target, "service"))
        elif tool == "nmap_full":
            raw_parts.append("=== nmap full ===\n" + engine.run_nmap(target, "full"))
        elif tool == "nmap_vuln":
            raw_parts.append("=== nmap vuln ===\n" + engine.run_nmap(target, "vuln"))
        elif tool == "whatweb":
            raw_parts.append("=== whatweb ===\n" + engine.run_whatweb(target))
        elif tool == "whois":
            raw_parts.append("=== whois ===\n" + engine.run_whois(target))
        elif tool == "dig":
            raw_parts.append("=== dig ===\n" + engine.run_dig(target))

    raw_scan = "\n\n".join(raw_parts) or "No scan data"

    # AI analysis
    result = engine.analyse(target, raw_scan)

    # Save to DB
    sl_no = db_create_session(target)

    for v in result.get("vulnerabilities", []):
        vid = db_save_vulnerability(sl_no, v.get("vuln_name",""), v.get("severity",""),
                                    v.get("port",""), v.get("service",""), v.get("description",""))
        if v.get("fix"):
            db_save_fix(sl_no, vid, v["fix"], "ai")

    for e in result.get("exploits", []):
        db_save_exploit(sl_no, e.get("exploit_name",""), e.get("tool_used",""),
                        e.get("payload",""), e.get("result",""), e.get("notes",""))

    db_save_summary(sl_no, raw_scan, result.get("full_response",""),
                    result.get("risk_level","UNKNOWN"))

    return {
        "sl_no":            sl_no,
        "target":           target,
        "risk_level":       result.get("risk_level","UNKNOWN"),
        "vulnerabilities":  result.get("vulnerabilities", []),
        "exploits":         result.get("exploits", []),
        "full_response":    result.get("full_response",""),
        "raw_scan_preview": raw_scan[:1000],
    }


@app.post("/network-scan")
def network_scan(req: NetworkScanRequest):
    """Scan nearby Wi-Fi networks and save to DB."""
    sl_no = db_create_session(req.label or "wifi_scan")
    networks = []
    raw_all  = []

    method = req.method or "powershell"

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
        "sl_no":        sl_no,
        "label":        req.label,
        "method":       method,
        "networks":     networks,
        "total_found":  len(networks),
        "raw_preview":  "\n".join(raw_all)[:800],
    }


@app.get("/list-networks")
def list_networks(sl_no: Optional[int] = None):
    """List saved Wi-Fi networks. If sl_no provided, filter by session."""
    if sl_no:
        return {"sl_no": sl_no, "networks": db_get_wifi(sl_no)}
    # All recent networks (last 100)
    conn = get_connection()
    c = conn.cursor(dictionary=True)
    c.execute("SELECT * FROM wifi_networks ORDER BY id DESC LIMIT 100")
    rows = [_safe_row(r) for r in c.fetchall()]
    conn.close()
    return {"networks": rows, "total": len(rows)}


@app.post("/create-skill")
def create_skill(req: SkillCreateRequest):
    """Ask Groq to generate a specialized attack/test script."""
    skill = engine.generate_skill(req.service, req.port, req.context, req.language or "python")
    filepath = None
    if req.auto_save:
        filepath = engine.save_skill(skill)
    return {
        "skill_name":  skill.get("skill_name"),
        "description": skill.get("description"),
        "language":    skill.get("language"),
        "code":        skill.get("code"),
        "saved_to":    filepath,
    }


@app.get("/skills")
def list_skills():
    """List all generated skills in /skills directory."""
    return {"skills": engine.list_skills(), "skills_dir": str(SKILLS_DIR)}


@app.post("/run-skill")
def run_skill(req: SkillRunRequest):
    """Execute a skill by filename against a target."""
    output = engine.run_skill(req.filename, req.target or "127.0.0.1")
    return {"filename": req.filename, "target": req.target, "output": output}


@app.get("/history")
def history():
    """List all scan sessions."""
    rows = db_get_history()
    return {"sessions": rows, "total": len(rows)}


@app.get("/session/{sl_no}")
def session_detail(sl_no: int):
    """Full detail of a session (vulns, fixes, exploits, summary, wifi)."""
    data = db_get_session(sl_no)
    if not data["history"]:
        raise HTTPException(404, f"Session SL#{sl_no} not found")
    return data


@app.delete("/session/{sl_no}")
def delete_session(sl_no: int):
    """Delete all data for a session."""
    data = db_get_session(sl_no)
    if not data["history"]:
        raise HTTPException(404, f"Session SL#{sl_no} not found")
    db_delete_session(sl_no)
    return {"deleted": True, "sl_no": sl_no}


@app.get("/knowledge")
def get_knowledge(category: Optional[str] = None, limit: int = 30):
    """View adaptive memory (ai_knowledge table)."""
    rows = db_get_knowledge(category, limit)
    return {"knowledge": rows, "total": len(rows),
            "summary_text": knowledge_summary_text(limit)}


@app.post("/knowledge")
def add_knowledge(req: KnowledgeAddRequest):
    """Manually add an entry to the knowledge base."""
    db_save_knowledge(req.category, req.subject, req.outcome,
                      req.confidence or 0.7, req.details or "")
    return {"saved": True}


# ══════════════════════════════════════════════════════════════
# ── ENTRY POINT ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    # Handle --init-db flag
    if "--init-db" in sys.argv:
        try:
            init_schema()
            print("[+] Database initialized successfully.")
        except Exception as e:
            print(f"[!] DB init failed: {e}")
        sys.exit(0)

    # Verify DB connection
    try:
        conn = get_connection()
        conn.close()
        print("[+] MariaDB connection OK")
        init_schema()
    except Exception as e:
        print(f"[!] MariaDB error: {e}")
        print("    Run: sudo service mariadb start")
        sys.exit(1)

    print("""
\033[91m
    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
    \033[90mv2.0 — FastAPI Bridge | Groq llama3-70b | WSL2\033[0m
    """)
    print("[+] API docs: http://localhost:8000/docs")
    print("[+] Ready. Expose with: ngrok http 8000\n")

    uvicorn.run(
        "api:app",
        host="0.0.0.0",   # required for ngrok to reach WSL2
        port=8000,
        reload=False,      # reload=True causes double-init issues in WSL2
        log_level="info",
    )
