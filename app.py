from flask import Flask, jsonify, request
import subprocess
import os
import json

app = Flask(__name__)

# LLAVE MAESTRA: Esta función sobreescribe CUALQUIER encabezado duplicado
@app.after_request
def clear_cors_duplication(response):
    # Usamos .set para asegurar que SOLO exista uno, borrando lo que ngrok intente poner
    response.headers.set("Access-Control-Allow-Origin", "*")
    response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    response.headers.set("Access-Control-Allow-Headers", "Content-Type, ngrok-skip-browser-warning")
    response.headers.set("ngrok-skip-browser-warning", "69420")
    return response

@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    return jsonify({"status": "ok"})

@app.route('/network-scan', methods=['GET', 'OPTIONS'])
def scan():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        # Ejecuta el scanner
        subprocess.run(['python', 'C:/Users/PC/Metatron/scanner.py'], check=True)
        if os.path.exists('C:/Users/PC/Metatron/results.json'):
            with open('C:/Users/PC/Metatron/results.json', 'r') as f:
                return jsonify(json.load(f))
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Rutas fantasma para que Vercel no llore
@app.route('/skills')
@app.route('/history')
@app.route('/list-networks')
def void():
    return jsonify({"data": []})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
