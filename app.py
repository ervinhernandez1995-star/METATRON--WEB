from flask import Flask, jsonify, request, make_response
import subprocess
import json
import os

app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, ngrok-skip-browser-warning")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    response.headers.add("ngrok-skip-browser-warning", "69420")
    return response

# Ruta raiz que ya funciona
@app.route('/')
def home():
    return jsonify({"status": "Metatron Online"})

# ESTA ES LA RUTA QUE TU DASHBOARD LLAMA COMO "SCAN"
@app.route('/network-scan', methods=['GET', 'OPTIONS'])
@app.route('/scan', methods=['GET', 'OPTIONS'])
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
        return jsonify({"mensaje": "Escaneo vacio"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# RUTAS ADICIONALES PARA QUE NO DEN 404
@app.route('/skills', methods=['GET', 'OPTIONS'])
@app.route('/history', methods=['GET', 'OPTIONS'])
@app.route('/list-networks', methods=['GET', 'OPTIONS'])
def extras():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    # Devolvemos datos vacios para que la web no se rompa
    return jsonify({"data": [], "status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
