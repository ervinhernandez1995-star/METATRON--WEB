from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os

app = Flask(__name__)
# CORS habilitado para TODO (asi no hay falla con Vercel)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["*"]}})

# 1. SOLUCION AL 404: Ruta raiz que Vercel esta buscando
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({'status': 'ok'})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
        return response, 200

@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    response = jsonify({"status": "Metatron Online", "info": "Usa /scan para el hardware"})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("ngrok-skip-browser-warning", "69420")
    return response

# 2. RUTA DEL ESCANER
@app.route('/scan', methods=['GET', 'OPTIONS'])
def scan():
    try:
        scanner_path = 'C:/Users/PC/Metatron/scanner.py'
        results_path = 'C:/Users/PC/Metatron/results.json'
        
        # Ejecutar el scanner
        subprocess.run(['python', scanner_path], check=True)

        if os.path.exists(results_path):
            with open(results_path, 'r') as f:
                resultados = json.load(f)
            
            response = jsonify(resultados)
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("ngrok-skip-browser-warning", "69420")
            return response
        else:
            response = jsonify({"error": "No hay resultados"})
            response.headers.add("Access-Control-Allow-Origin", "*")
            return response, 500
            
    except Exception as e:
        response = jsonify({"error": str(e)})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500

if __name__ == '__main__':
    # Puerto 5000 que es el que abriste en ngrok
    app.run(host='0.0.0.0', port=5000)