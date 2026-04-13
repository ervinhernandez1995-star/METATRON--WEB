from flask import Flask, jsonify
import subprocess
import json
import os

app = Flask(__name__)

@app.route('/scan')
def scan():
    try:
        # Rutas con barras hacia adelante para evitar errores de Windows
        scanner_path = 'C:/Users/PC/Metatron/scanner.py'
        results_path = 'C:/Users/PC/Metatron/results.json'
        
        # Ejecutar el escaneo
        subprocess.run(['python', scanner_path], check=True)

        if os.path.exists(results_path):
            with open(results_path, 'r') as f:
                resultados = json.load(f)
            return jsonify(resultados)
        else:
            return jsonify({"error": "No se encontro el archivo de resultados"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
