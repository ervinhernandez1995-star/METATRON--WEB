// 🔗 URL de tu túnel ngrok (Asegúrate de que sea la misma que ves en tu terminal)
const API_URL = "https://subentire-sibyl-gleesomely.ngrok-free.dev";

async function analizarIP() {
    // Intentamos obtener el input del index.html
    const ipInput = document.getElementById('ip-address') || document.querySelector('input[type="text"]');
    const resultDiv = document.getElementById('results') || document.getElementById('output');
    
    if (!ipInput.value) {
        alert("⚠️ Por favor, ingresa una dirección IP o dominio.");
        return;
    }

    resultDiv.innerHTML = "<p style='color: #00ff00;'>📡 Conectando con Metatron Engine... por favor espera.</p>";

    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // Este header es CRUCIAL para que ngrok no bloquee la petición
                'ngrok-skip-browser-warning': 'true'
            },
            body: JSON.stringify({ ip: ipInput.value })
        });

        if (!response.ok) throw new Error("Error en la respuesta del servidor");

        const data = await response.json();
        
        // Mostramos el análisis de la IA en el dashboard
        resultDiv.innerHTML = `
            <div style="border: 1px solid #00ff00; padding: 15px; background: #000;">
                <h3 style="color: #00ff00;">🔍 Análisis de Inteligencia Llama-3:</h3>
                <p style="white-space: pre-wrap; color: #fff;">${data.analysis}</p>
            </div>
        `;

    } catch (error) {
        console.error("Error:", error);
        resultDiv.innerHTML = `<p style="color: red;">❌ Error de conexión: Asegúrate de que el motor de Metatron y ngrok estén corriendo en Ubuntu.</p>`;
    }
}

// Escuchar el evento click del botón si el index tiene un botón con id "scan-btn"
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('scan-btn') || document.querySelector('button');
    if (btn) {
        btn.addEventListener('click', analizarIP);
    }
});