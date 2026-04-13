from flask import Flask, jsonify, request, make_response
import subprocess
import json
import os

app = Flask(__name__)

@app.before_request
def handle_options_preflight():
    # Esta es la LLAVE MAESTRA para el error de CORS
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, ngrok-skip-browser-warning")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.headers.add("ngrok-skip-browser-warning", "69420")
        return response

@app.after_request
def add_cors_headers(response):
    # Esto asegura que todas las respuestas lleven los permisos
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("ngrok-skip-browser-warning", "69420")
    return response

@app.route('/')
def home():
    return jsonify({"status": "Metatron Online"})

@app.route('/network-scan', methods=['GET', 'POST', 'OPTIONS'])
@app.route('/scan', methods=['GET', 'POST', 'OPTIONS'])
def scan():
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

# Evitar 404 en otras rutas
@app.route('/skills')
@app.route('/history')
@app.route('/list-networks')
def extra_routes():
    return jsonify({"data": []})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
