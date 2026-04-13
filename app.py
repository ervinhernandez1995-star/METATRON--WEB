from flask import Flask, jsonify, request, make_response
import subprocess
import json
import os

app = Flask(__name__)

# Solo usamos esta función para manejar los permisos
@app.after_request
def add_cors_headers(response):
    # IMPORTANTE: Solo un '*' para que no se duplique
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, ngrok-skip-browser-warning"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    # El truco para ngrok
    response.headers["ngrok-skip-browser-warning"] = "69420"
    return response

@app.route('/')
def home():
    return jsonify({"status": "Metatron Online"})

@app.route('/network-scan', methods=['GET', 'POST', 'OPTIONS'])
@app.route('/scan', methods=['GET', 'POST', 'OPTIONS'])
def scan():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    try:
        scanner_path = 'C:/Users/PC/Metatron/scanner.py'
        subprocess.run(['python', scanner_path], check=True)
        results_path = 'C:/Users/PC/Metatron/results.json'
        
        if os.path.exists(results_path):
            with open(results_path, 'r') as f:
                return jsonify(json.load(f))
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/skills')
@app.route('/history')
@app.route('/list-networks')
def extra_routes():
    return jsonify({"data": [], "status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
