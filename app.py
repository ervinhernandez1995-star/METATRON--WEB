from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os

app = Flask(__name__)
# Permitimos TODO de forma agresiva para debugging
CORS(app, resources={r"/*": {"origins": "*"}})

@app.after_request
def add_header(response):
    # Estos headers obligan a ngrok y al navegador a dejar pasar los datos
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, ngrok-skip-browser-warning"
    response.headers["ngrok-skip-browser-warning"] = "69420"
    return response

@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    return jsonify({"status": "Metatron Online", "endpoint": "/scan"})

@app.route('/scan', methods=['GET', 'OPTIONS'])
def scan():
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"}), 200
        
    try:
        scanner_path = 'C:/Users/PC/Metatron/scanner.py'
        results_path = 'C:/Users/PC/Metatron/results.json'
        
        # Ejecutamos el script de scapy
        subprocess.run(['python', scanner_path], check=True)

        if os.path.exists(results_path):
            with open(results_path, 'r') as f:
                resultados = json.load(f)
            return jsonify(resultados)
        else:
            return jsonify({"error": "No se encontro results.json"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
