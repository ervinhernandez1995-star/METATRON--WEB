#!/usr/bin/env python3
"""
METATRON v3.1 - app.py (Flask + SQLite + Ollama LOCAL)
USO:
  1. python -m pip install flask psutil ollama
  2. Instala Ollama:  https://ollama.com/download
  3. Descarga modelo: ollama pull dolphin-phi
  4. Inicia Ollama:   ollama serve          (queda en localhost:11434)
  5. python app.py
  6. Abre http://localhost:5000
"""
import os, sys, json, subprocess, re, sqlite3, importlib.util
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

# ── CONFIG OLLAMA LOCAL ──────────────────────────────────────
OLLAMA_HOST = "http://localhost:11434"
MODEL       = "dolphin-phi"           # ollama pull dolphin-phi
import ollama
import concurrent.futures

def analizar_con_ia(prompt):
    def _call():
        # Usamos timeout de 120s requerido.
        # Solo usamos client.chat puro sin referencias a openai.ChatCompletion
        client = ollama.Client(host=OLLAMA_HOST, timeout=120)
        return client.chat(model=MODEL, messages=[
            {'role': 'user', 'content': prompt},
        ])
        
    # Usamos threading explícito para no bloquear el hilo principal y evitar congelamiento
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_call)
        response = future.result(timeout=125) # 5 segundos de margen
        
    return response['message']['content']

def check_ollama():
    """Verifica que Ollama esté corriendo y el modelo disponible."""
    try:
        import ollama
        client = ollama.Client(host=OLLAMA_HOST)
        models = [m.model for m in client.list().models]
        if MODEL in models or any(MODEL in m for m in models):
            print(f"✅ Ollama OK — modelo '{MODEL}' listo en {OLLAMA_HOST}")
            return True
        else:
            print(f"⚠  Ollama corre pero '{MODEL}' no está descargado.")
            print(f"   Ejecuta: ollama pull {MODEL}")
            return False
    except Exception as e:
        print(f"❌ Ollama no disponible en {OLLAMA_HOST}: {e}")
        print(f"   Instala y ejecuta: ollama serve")
        return False

# ── CONFIG ────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DB_PATH  = BASE_DIR / "metatron.db"
SKILLS_DIR = BASE_DIR / "skills"
SKILLS_DIR.mkdir(exist_ok=True)

app = Flask(__name__, static_folder="static")

# ── DATABASE SQLite ───────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db(); c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS history (
        sl_no INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, scan_date TEXT, status TEXT);
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sl_no INTEGER,
        vuln_name TEXT, severity TEXT, port TEXT, service TEXT, description TEXT);
    CREATE TABLE IF NOT EXISTS fixes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sl_no INTEGER,
        vuln_id INTEGER, fix_text TEXT, source TEXT);
    CREATE TABLE IF NOT EXISTS exploits_attempted (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sl_no INTEGER,
        exploit_name TEXT, tool_used TEXT, payload TEXT, result TEXT, notes TEXT);
    CREATE TABLE IF NOT EXISTS summary (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sl_no INTEGER,
        raw_scan TEXT, ai_analysis TEXT, risk_level TEXT, generated_at TEXT);
    CREATE TABLE IF NOT EXISTS wifi_networks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sl_no INTEGER,
        ssid TEXT, bssid TEXT, channel TEXT, signal TEXT,
        security TEXT, scanned_at TEXT);
    CREATE TABLE IF NOT EXISTS ai_knowledge (
        id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT,
        subject TEXT, outcome TEXT, confidence REAL DEFAULT 0.5,
        details TEXT, learned_at TEXT);
    """)
    conn.commit(); conn.close()

def row_to_dict(row): return dict(row) if row else None
def rows_to_list(rows): return [dict(r) for r in rows]

def db_create_session(target):
    conn = get_db(); c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history (target,scan_date,status) VALUES (?,?,?)", (target,now,"active"))
    conn.commit(); sl_no = c.lastrowid; conn.close(); return sl_no

def db_save_vulnerability(sl_no, vuln_name, severity, port, service, description):
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO vulnerabilities (sl_no,vuln_name,severity,port,service,description) VALUES (?,?,?,?,?,?)",
              (sl_no,str(vuln_name),str(severity),str(port),str(service),str(description)))
    conn.commit(); vid = c.lastrowid; conn.close(); return vid

def db_save_fix(sl_no, vuln_id, fix_text, source="ai"):
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO fixes (sl_no,vuln_id,fix_text,source) VALUES (?,?,?,?)",(sl_no,vuln_id,str(fix_text),str(source)))
    conn.commit(); conn.close()

def db_save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO exploits_attempted (sl_no,exploit_name,tool_used,payload,result,notes) VALUES (?,?,?,?,?,?)",
              (sl_no,str(exploit_name or "")[:500],str(tool_used or "")[:200],str(payload or ""),str(result or "")[:500],str(notes or "")))
    conn.commit(); conn.close()

def db_save_summary(sl_no, raw_scan, ai_analysis, risk_level):
    conn = get_db(); c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO summary (sl_no,raw_scan,ai_analysis,risk_level,generated_at) VALUES (?,?,?,?,?)",
              (sl_no,str(raw_scan),str(ai_analysis),str(risk_level),now))
    conn.commit(); conn.close()

def db_save_wifi(sl_no, ssid, bssid, channel, signal, security):
    conn = get_db(); c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO wifi_networks (sl_no,ssid,bssid,channel,signal,security,scanned_at) VALUES (?,?,?,?,?,?,?)",
              (sl_no,str(ssid),str(bssid),str(channel),str(signal),str(security),now))
    conn.commit(); conn.close()

def db_save_knowledge(category, subject, outcome, confidence, details):
    conn = get_db(); c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO ai_knowledge (category,subject,outcome,confidence,details,learned_at) VALUES (?,?,?,?,?,?)",
              (str(category),str(subject),str(outcome),float(confidence),str(details),now))
    conn.commit(); conn.close()

def db_delete_session(sl_no):
    conn = get_db(); c = conn.cursor()
    for tbl in ["fixes","exploits_attempted","vulnerabilities","summary","wifi_networks","history"]:
        c.execute(f"DELETE FROM {tbl} WHERE sl_no=?", (sl_no,))
    conn.commit(); conn.close()

def db_get_history():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT sl_no,target,scan_date,status FROM history ORDER BY sl_no DESC")
    r = rows_to_list(c.fetchall()); conn.close(); return r

def db_get_session(sl_no):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM history WHERE sl_no=?",(sl_no,)); history = row_to_dict(c.fetchone())
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no=?",(sl_no,)); vulns = rows_to_list(c.fetchall())
    c.execute("SELECT * FROM fixes WHERE sl_no=?",(sl_no,)); fixes = rows_to_list(c.fetchall())
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no=?",(sl_no,)); exploits = rows_to_list(c.fetchall())
    c.execute("SELECT * FROM summary WHERE sl_no=?",(sl_no,)); summary = row_to_dict(c.fetchone())
    c.execute("SELECT * FROM wifi_networks WHERE sl_no=?",(sl_no,)); wifi = rows_to_list(c.fetchall())
    conn.close()
    return {"history":history,"vulns":vulns,"fixes":fixes,"exploits":exploits,"summary":summary,"wifi":wifi}

def db_get_wifi_all():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM wifi_networks ORDER BY id DESC LIMIT 100")
    r = rows_to_list(c.fetchall()); conn.close(); return r

def db_get_knowledge(category=None, limit=30):
    conn = get_db(); c = conn.cursor()
    if category:
        c.execute("SELECT * FROM ai_knowledge WHERE category=? ORDER BY confidence DESC LIMIT ?", (category,limit))
    else:
        c.execute("SELECT * FROM ai_knowledge ORDER BY confidence DESC, learned_at DESC LIMIT ?", (limit,))
    r = rows_to_list(c.fetchall()); conn.close(); return r

def knowledge_summary_text(limit=20):
    rows = db_get_knowledge(limit=limit)
    if not rows: return "No prior knowledge recorded."
    lines = ["=== AI ADAPTIVE MEMORY ==="]
    for r in rows:
        lines.append(f"[{str(r.get('category','')).upper()}] {r.get('subject','')} | outcome={r.get('outcome','')} | conf={str(r.get('confidence',''))[:4]} | {str(r.get('details',''))[:100]}")
    return "\n".join(lines)

# ── METATRON ENGINE ───────────────────────────────────────────
class MetatronEngine:

    @staticmethod
    def _run(cmd, timeout=90):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired: return f"[timeout] {cmd}"
        except Exception as e: return f"[error] {e}"

    @staticmethod
    def run_nmap(target, mode="service"):
        cmds = {"service":f"nmap -sV -sC -T4 {target}","full":f"nmap -p- --open -T4 {target}",
                "vuln":f"nmap --script vuln {target}","quick":f"nmap -sn {target}"}
        return MetatronEngine._run(cmds.get(mode, cmds["service"]), timeout=120)

    @staticmethod
    def run_whatweb(target): return MetatronEngine._run(f"whatweb {target}", timeout=30)
    @staticmethod
    def run_whois(target):
        # whois nativo Linux; fallback PowerShell + nslookup para WSL2/Windows
        out = MetatronEngine._run(f"whois {target} 2>/dev/null", timeout=20)
        if not out or "not recognized" in out or "[error]" in out or len(out) < 10:
            out = MetatronEngine._run(
                f'powershell.exe -Command "Resolve-DnsName {target} | Format-List"', timeout=15)
        if not out or "[error]" in out:
            out = MetatronEngine._run(f"nslookup {target}", timeout=10)
        return out or f"[whois] Sin informacion disponible para {target}"
    @staticmethod
    def run_dig(target): return MetatronEngine._run(f"nslookup {target}", timeout=10)

    @staticmethod
    def scan_wifi_windows():
        raw = MetatronEngine._run("netsh wlan show networks mode=bssid", timeout=20)
        networks = []
        RE_SSID    = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
        RE_AUTH    = re.compile(r"^(Authentication|Autenticaci[oó]n)\s*:\s*(.*)$", re.IGNORECASE|re.UNICODE)
        RE_ENCRYPT = re.compile(r"^(Encryption|Cifrado)\s*:\s*(.*)$", re.IGNORECASE|re.UNICODE)
        RE_BSSID   = re.compile(r"^BSSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
        RE_SIGNAL  = re.compile(r"^(Signal|Se[ñn\xf1]al)\s*:\s*(.*)$", re.IGNORECASE|re.UNICODE)
        RE_CHANNEL = re.compile(r"^(Channel|Canal)\s*:\s*(.*)$", re.IGNORECASE|re.UNICODE)
        RE_RADIO   = re.compile(r"^(Radio type|Tipo de radio)\s*:\s*(.*)$", re.IGNORECASE|re.UNICODE)
        current_ssid = None; current_auth = "N/A"; current_encrypt = "N/A"; current_bssid_block = None

        def flush_bssid():
            nonlocal current_bssid_block
            if current_bssid_block and current_ssid:
                _a = current_auth if current_auth != "N/A" else ""
                _e = current_encrypt if current_encrypt != "N/A" else ""
                _s = f"{_a} / {_e}" if _a and _e else (_a or _e or "OPEN")
                networks.append({"ssid":current_ssid,"bssid":current_bssid_block.get("bssid","N/A"),
                    "channel":current_bssid_block.get("channel","N/A"),"signal":current_bssid_block.get("signal","N/A"),
                    "encryption":current_encrypt if current_encrypt!="N/A" else "OPEN",
                    "radio":current_bssid_block.get("radio","N/A"),"security":_s})
            current_bssid_block = None

        for line in raw.splitlines():
            ls = line.strip()
            if not ls: continue
            m = RE_SSID.match(ls)
            if m: flush_bssid(); current_ssid=m.group(1).strip() or "<hidden>"; current_auth=current_encrypt="N/A"; current_bssid_block=None; continue
            m = RE_AUTH.match(ls)
            if m: current_auth=m.group(2).strip(); continue
            m = RE_ENCRYPT.match(ls)
            if m: current_encrypt=m.group(2).strip(); continue
            m = RE_BSSID.match(ls)
            if m: flush_bssid(); current_bssid_block={"bssid":m.group(1).strip()}; continue
            if current_bssid_block is not None:
                m = RE_SIGNAL.match(ls)
                if m: current_bssid_block["signal"]=m.group(2).strip(); continue
                m = RE_CHANNEL.match(ls)
                if m: current_bssid_block["channel"]=m.group(2).strip(); continue
                m = RE_RADIO.match(ls)
                if m: current_bssid_block["radio"]=m.group(2).strip(); continue
        flush_bssid()
        return networks, raw

    @staticmethod
    def get_interfaces():
        try:
            import psutil
            interfaces = []; stats = psutil.net_if_stats(); addrs = psutil.net_if_addrs()
            for name, addr_list in addrs.items():
                ipv4 = mac = ""
                for a in addr_list:
                    fv = a.family.value if hasattr(a.family,"value") else -99
                    if fv == 2: ipv4 = a.address
                    if fv in (17,18,-1): mac = a.address
                is_up = bool(stats.get(name) and stats[name].isup)
                itype = "Wi-Fi" if any(k in name.lower() for k in ["wi","wlan","wireless"]) else "Ethernet"
                interfaces.append({"name":name,"ip":ipv4 or "—","mac":mac or "—","type":itype,"up":is_up})
            return interfaces
        except Exception as e: return [{"error":str(e)}]

    @staticmethod
    def analyse(target, raw_scan):
        """Analiza el output de nmap con Ollama local (dolphin-phi)."""
        system = """You are METATRON, an expert AI penetration testing assistant.
Analyze the provided Nmap scan and return ONLY valid JSON — no markdown, no backticks, no extra text.
Schema:
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "vulnerabilities": [
    {"vuln_name":"","severity":"CRITICAL|HIGH|MEDIUM|LOW","port":"","service":"","description":"","fix":""}
  ],
  "exploits": [
    {"exploit_name":"","tool_used":"","payload":"","result":"simulated","notes":""}
  ],
  "full_response": "narrative summary in Spanish"
}
If no issues found, return risk_level LOW and empty arrays."""

        user = (f"Target: {target}\n\n"
                f"NMAP SCAN OUTPUT:\n{raw_scan[:5000]}\n\n"
                f"PRIOR KNOWLEDGE:\n{knowledge_summary_text()}")

        prompt = f"{system}\n\n{user}"

        try:
            raw_text = analizar_con_ia(prompt).strip()
            # Limpiar posibles bloques de markdown que el modelo añada
            raw_text = re.sub(r"```json|```", "", raw_text).strip()
            # Extraer JSON si hay texto antes/después
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if match:
                raw_text = match.group(0)
            data = json.loads(raw_text)
            db_save_knowledge("attack", f"Analysis: {target}",
                              "success" if data.get("vulnerabilities") else "partial",
                              0.8, f"Risk: {data.get('risk_level','?')}")
            data["raw_scan"] = raw_scan
            return data
        except json.JSONDecodeError as e:
            # Si el modelo no devolvió JSON válido, guardar la respuesta como texto
            db_save_knowledge("attack", f"Analysis partial: {target}", "partial", 0.4, str(e))
            return {"risk_level":"UNKNOWN","vulnerabilities":[],"exploits":[],
                    "full_response": raw_text if 'raw_text' in dir() else f"Error JSON: {e}",
                    "raw_scan": raw_scan}
        except Exception as e:
            db_save_knowledge("attack", f"Analysis failed: {target}", "failure", 0.1, str(e))
            return {"risk_level":"UNKNOWN","vulnerabilities":[],"exploits":[],
                    "full_response": f"Error Ollama: {e}\nVerifica que 'ollama serve' esté corriendo en {OLLAMA_HOST}",
                    "raw_scan": raw_scan}

    @staticmethod
    def generate_skill(service, port, context, language="python"):
        """Genera un script de pentesting usando Ollama local."""
        system = """You are METATRON Skill Creator. Output ONLY valid JSON (no markdown, no backticks):
{"skill_name":"snake_case_name","description":"one sentence description","language":"python|bash","code":"full self-contained script"}
Rules: script must have TARGET='127.0.0.1' at the top, print all results to stdout, be ethical and legal."""
        user = (f"Generate a {language} security testing script for:\n"
                f"Service: {service} | Port: {port} | Context: {context}\n\n"
                f"Prior knowledge:\n{knowledge_summary_text()}")

        prompt = f"{system}\n\n{user}"

        try:
            raw_text = analizar_con_ia(prompt).strip()
            raw_text = re.sub(r"```json|```", "", raw_text).strip()
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if match:
                raw_text = match.group(0)
            return json.loads(raw_text)
        except Exception as e:
            return {"skill_name":"error","description":str(e),"language":language,
                    "code":f"# Error generando skill: {e}\n# Verifica que ollama serve esté activo"}

    @staticmethod
    def save_skill(skill_data):
        name = skill_data.get("skill_name","unnamed").replace(" ","_").lower()
        ext  = ".py" if skill_data.get("language","python") == "python" else ".sh"
        path = SKILLS_DIR / f"{name}{ext}"
        with open(path,"w") as f: f.write(skill_data.get("code","# empty"))
        db_save_knowledge("skill",f"Created: {name}","created",0.7,f"File: {path} | {skill_data.get('description','')}")
        return str(path)

    @staticmethod
    def run_skill(filename, target="127.0.0.1"):
        path = SKILLS_DIR / filename
        if not path.exists(): return f"[error] Skill not found: {filename}"
        try:
            if path.suffix == ".py":
                spec = importlib.util.spec_from_file_location("skill_mod",path)
                mod  = importlib.util.module_from_spec(spec); mod.TARGET = target
                spec.loader.exec_module(mod)
                return str(mod.run(target)) if hasattr(mod,"run") else "[*] Module executed."
            elif path.suffix == ".sh":
                r = subprocess.run(["bash",str(path)],capture_output=True,text=True,timeout=60,env={**os.environ,"TARGET":target})
                return r.stdout + r.stderr
        except Exception as e: return f"[error] {e}"

    @staticmethod
    def list_skills():
        files = list(SKILLS_DIR.glob("*.py")) + list(SKILLS_DIR.glob("*.sh"))
        return [{"name":f.name,"type":"python" if f.suffix==".py" else "bash","size":f.stat().st_size} for f in sorted(files)]

engine = MetatronEngine()

# ── ROUTES ────────────────────────────────────────────────────
@app.route("/")
def index(): return send_from_directory("static","index.html")

@app.route("/status")
def status():
    try:
        import ollama
        client = ollama.Client(host=OLLAMA_HOST)
        models = [m.model for m in client.list().models]
        ollama_ok = any(MODEL in m for m in models)
    except Exception:
        ollama_ok = False
    return jsonify({"status":"online","app":"METATRON v3.1","model":MODEL,
                    "ollama_host":OLLAMA_HOST,"ollama_ready":ollama_ok})

@app.route("/scan", methods=["GET","POST"])
def scan():
    if request.method == "GET":
        interfaces = engine.get_interfaces()
        networks, _ = engine.scan_wifi_windows()
        results = {"interfaces":interfaces,"wifi_networks":networks}
        with open(BASE_DIR/"results.json","w") as f: json.dump(results,f,indent=2,ensure_ascii=False)
        return jsonify(results)
    data = request.get_json(force=True) or {}
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"target requerido"}),400
    tools = data.get("tools",["nmap_service"])
    raw_parts = []
    for tool in tools:
        if tool == "nmap_service": raw_parts.append("=== nmap service ===\n"+engine.run_nmap(target,"service"))
        elif tool == "nmap_full":  raw_parts.append("=== nmap full ===\n"+engine.run_nmap(target,"full"))
        elif tool == "nmap_vuln":  raw_parts.append("=== nmap vuln ===\n"+engine.run_nmap(target,"vuln"))
        elif tool == "whatweb":    raw_parts.append("=== whatweb ===\n"+engine.run_whatweb(target))
        elif tool == "whois":      raw_parts.append("=== whois ===\n"+engine.run_whois(target))
        elif tool == "dig":        raw_parts.append("=== dig ===\n"+engine.run_dig(target))
    raw_scan = "\n\n".join(raw_parts) or "No scan data"
    result = engine.analyse(target,raw_scan); sl_no = db_create_session(target)
    for v in result.get("vulnerabilities",[]):
        vid = db_save_vulnerability(sl_no,v.get("vuln_name",""),v.get("severity",""),v.get("port",""),v.get("service",""),v.get("description",""))
        if v.get("fix"): db_save_fix(sl_no,vid,v["fix"],"ai")
    for e in result.get("exploits",[]):
        db_save_exploit(sl_no,e.get("exploit_name",""),e.get("tool_used",""),e.get("payload",""),e.get("result",""),e.get("notes",""))
    db_save_summary(sl_no,raw_scan,result.get("full_response",""),result.get("risk_level","UNKNOWN"))
    return jsonify({"sl_no":sl_no,"target":target,"risk_level":result.get("risk_level","UNKNOWN"),
        "vulnerabilities":result.get("vulnerabilities",[]),"exploits":result.get("exploits",[]),
        "full_response":result.get("full_response",""),"raw_scan_preview":raw_scan[:1000]})

@app.route("/analyze", methods=["POST"])
def analyze_ip():
    data = request.get_json(force=True) or {}
    target = data.get("ip","").strip()
    if not target: return jsonify({"error":"ip requerida"}),400
    raw_scan = engine.run_nmap(target,"service"); result = engine.analyse(target,raw_scan); sl_no = db_create_session(target)
    for v in result.get("vulnerabilities",[]):
        vid = db_save_vulnerability(sl_no,v.get("vuln_name",""),v.get("severity",""),v.get("port",""),v.get("service",""),v.get("description",""))
        if v.get("fix"): db_save_fix(sl_no,vid,v["fix"],"ai")
    db_save_summary(sl_no,raw_scan,result.get("full_response",""),result.get("risk_level","UNKNOWN"))
    return jsonify({"sl_no":sl_no,"target":target,"risk_level":result.get("risk_level","UNKNOWN"),
        "analysis":result.get("full_response",""),"full_response":result.get("full_response",""),
        "vulnerabilities":result.get("vulnerabilities",[]),"exploits":result.get("exploits",[]),
        "raw_scan_preview":raw_scan[:1000]})

@app.route("/network-scan", methods=["GET","POST"])
def network_scan():
    data = request.get_json(force=True) if request.method=="POST" else {}
    label = (data or {}).get("label","wifi_scan"); sl_no = db_create_session(label)
    networks, raw = engine.scan_wifi_windows()
    for n in networks:
        db_save_wifi(sl_no,n.get("ssid",""),n.get("bssid",""),n.get("channel",""),n.get("signal",""),n.get("security",""))
    return jsonify({"sl_no":sl_no,"label":label,"networks":networks,"total_found":len(networks),"raw_preview":raw[:800]})

@app.route("/list-networks")
def list_networks():
    sl_no = request.args.get("sl_no")
    if sl_no:
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT * FROM wifi_networks WHERE sl_no=?",(sl_no,))
        nets = rows_to_list(c.fetchall()); conn.close()
        return jsonify({"sl_no":int(sl_no),"networks":nets})
    nets = db_get_wifi_all()
    return jsonify({"networks":nets,"total":len(nets)})

@app.route("/network-action", methods=["POST"])
def network_action():
    data = request.get_json(force=True) or {}
    action = data.get("action","").lower(); ssid = data.get("ssid","").strip()
    bssid = data.get("bssid","N/A"); target = data.get("target") or bssid or "192.168.1.1"
    if action == "info":
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT * FROM wifi_networks WHERE ssid=? OR bssid=? ORDER BY id DESC LIMIT 1",(ssid,bssid))
        row = row_to_dict(c.fetchone()); conn.close()
        return jsonify({"action":"info","ssid":ssid,"bssid":bssid,"record":row})
    elif action == "ping":
        # Ping al gateway por defecto (o target si se provee)
        ping_target = target if target and target != "N/A" else "8.8.8.8"
        # Intentar ping nativo, luego nmap -sn como fallback
        out = MetatronEngine._run(f"ping -c 3 {ping_target} 2>/dev/null || ping -n 3 {ping_target}", timeout=15)
        if not out or "[error]" in out:
            out = MetatronEngine._run(f"nmap -sn {ping_target}", timeout=20)
        return jsonify({"action":"ping","ssid":ssid,"target":ping_target,"output":out})
    elif action == "portscan":
        import re as _re
        _ip_re = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if not target or target == "N/A" or not _ip_re.match(target.strip()):
            return jsonify({"action":"portscan","target":target,
                "output":"[!] Ingresa una IP válida como target para escanear puertos. El BSSID es una MAC address, no una IP.",
                "error":"invalid_target"})
        out = engine.run_nmap(target,"service")
        return jsonify({"action":"portscan","target":target,"output":out})
    elif action in ("analyze","attack"):
        import re as _re
        _ip_re = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if not target or not _ip_re.match(target.strip()):
            return jsonify({"action":action,"ssid":ssid,"sl_no":None,"risk_level":"N/A",
                "full_response":(f"Para analizar '{ssid}' necesitas ingresar la IP del router/gateway "
                    "(no el BSSID/MAC). Ejemplo: 192.168.1.1"),
                "vulnerabilities":[],"error":"invalid_target"})
        raw = engine.run_nmap(target,"service"); result = engine.analyse(target,raw)
        sl_no = db_create_session(target); db_save_summary(sl_no,raw,result.get("full_response",""),result.get("risk_level","UNKNOWN"))
        for v in result.get("vulnerabilities",[]):
            vid = db_save_vulnerability(sl_no,v.get("vuln_name",""),v.get("severity",""),v.get("port",""),v.get("service",""),v.get("description",""))
            if v.get("fix"): db_save_fix(sl_no,vid,v["fix"],"ai")
        return jsonify({"action":action,"ssid":ssid,"sl_no":sl_no,"risk_level":result.get("risk_level","UNKNOWN"),
            "full_response":result.get("full_response",""),"vulnerabilities":result.get("vulnerabilities",[])})
    elif action == "deauth":
        return jsonify({"action":"deauth","ssid":ssid,"bssid":bssid,
            "note":"SIMULATION ONLY — no real deauth executed","cmd":f"aireplay-ng --deauth 10 -a {bssid} wlan0mon"})
    return jsonify({"error":f"Accion desconocida: {action}"}),400

@app.route("/create-skill", methods=["POST"])
def create_skill():
    data = request.get_json(force=True) or {}
    skill = engine.generate_skill(data.get("service",""),data.get("port",""),data.get("context",""),data.get("language","python"))
    filepath = engine.save_skill(skill) if data.get("auto_save",True) else None
    return jsonify({"skill_name":skill.get("skill_name"),"description":skill.get("description"),
        "language":skill.get("language"),"code":skill.get("code"),"saved_to":filepath})

@app.route("/skills")
def list_skills(): return jsonify({"skills":engine.list_skills(),"skills_dir":str(SKILLS_DIR)})

@app.route("/run-skill", methods=["POST"])
def run_skill():
    data = request.get_json(force=True) or {}
    output = engine.run_skill(data.get("filename",""),data.get("target","127.0.0.1"))
    return jsonify({"filename":data.get("filename"),"target":data.get("target"),"output":output})

@app.route("/history")
def history():
    rows = db_get_history(); return jsonify({"sessions":rows,"total":len(rows)})

@app.route("/session/<int:sl_no>", methods=["GET","DELETE"])
def session(sl_no):
    data = db_get_session(sl_no)
    if not data["history"]: return jsonify({"error":f"Sesion SL#{sl_no} no encontrada"}),404
    if request.method == "DELETE": db_delete_session(sl_no); return jsonify({"deleted":True,"sl_no":sl_no})
    return jsonify(data)

@app.route("/traceroute", methods=["POST"])
def traceroute():
    data = request.get_json(force=True) or {}
    target = data.get("target","8.8.8.8").strip()
    if not target: return jsonify({"error":"target requerido"}),400
    # tracert en Windows/WSL2, traceroute en Linux nativo
    out = MetatronEngine._run(f"traceroute -m 15 {target} 2>/dev/null", timeout=30)
    if not out or "[error]" in out or "not found" in out:
        out = MetatronEngine._run(f"tracert -h 15 {target}", timeout=30)
    if not out or "[error]" in out:
        # fallback: nmap traceroute
        out = MetatronEngine._run(f"nmap --traceroute -sn {target}", timeout=30)
    return jsonify({"action":"traceroute","target":target,"output":out or "Sin respuesta"})

@app.route("/knowledge", methods=["GET","POST"])
def knowledge():
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        db_save_knowledge(data.get("category","misc"),data.get("subject",""),data.get("outcome","partial"),data.get("confidence",0.7),data.get("details",""))
        return jsonify({"saved":True})
    cat = request.args.get("category"); limit = int(request.args.get("limit",30))
    rows = db_get_knowledge(cat,limit)
    return jsonify({"knowledge":rows,"total":len(rows),"summary_text":knowledge_summary_text(limit)})

# ── ENTRY POINT ───────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\033[91m")
    print("    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗")
    print("    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║")
    print("    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║")
    print("    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║")
    print("    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║")
    print("    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝")
    print("\033[0m    \033[90mv3.1 — Flask · SQLite · psutil · Ollama LOCAL\033[0m\n")
    check_ollama()
    print("\033[96m[+] Dashboard: http://localhost:5000\033[0m\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
