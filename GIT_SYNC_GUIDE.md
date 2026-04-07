# METATRON v2.1 — Guía de Sincronización
## Git (Ubuntu/WSL2) → GitHub → Vercel

---

## PASO 1 — Ubícate en tu proyecto

```bash
# Si el repo ya existe en WSL2
cd ~/metatron   # o la ruta donde clonaste el proyecto

# Si aún no has clonado el repo
git clone https://github.com/TU_USUARIO/TU_REPO.git
cd TU_REPO
```

---

## PASO 2 — Copia los archivos actualizados

```bash
# Copia los archivos generados a las rutas correctas de tu proyecto
# (ajusta las rutas según tu estructura)

# Backend (FastAPI) — en la raíz o en /backend
cp api.py .

# Frontend (Next.js) — en /public, /lib o /utils según tu proyecto
cp script.js public/script.js
# ó si usas un módulo de React:
# cp script.js lib/api.js
```

---

## PASO 3 — Configura la variable de entorno en Vercel

En tu panel de Vercel (vercel.com → proyecto → Settings → Environment Variables),
agrega:

```
NEXT_PUBLIC_API_URL = https://TU-SUBDOMINIO.ngrok-free.app
```

> ⚠️  Debes actualizar esta variable CADA VEZ que ngrok genere una nueva URL
> (a menos que uses un dominio ngrok fijo con plan de pago).
> Después de actualizarla, haz un redeploy manual desde el panel de Vercel.

---

## PASO 4 — Sube los cambios a GitHub

```bash
# Verifica qué archivos cambiaron
git status

# Agrega los archivos modificados
git add api.py public/script.js
# (agrega también cualquier otro archivo que hayas tocado)

# Crea el commit con un mensaje descriptivo
git commit -m "fix: CORS + ngrok preflight + parser netsh robusto (v2.1)"

# Sube al branch principal
git push origin main
```

> Si tu branch principal se llama `master` en lugar de `main`:
> ```bash
> git push origin master
> ```

Vercel detecta automáticamente el push y despliega en ~30 segundos.

---

## PASO 5 — Verifica el despliegue

```bash
# Desde Ubuntu, prueba el backend directamente
curl -s -H "ngrok-skip-browser-warning: true" \
  https://TU-SUBDOMINIO.ngrok-free.app/ | python3 -m json.tool

# Prueba el endpoint de CORS (preflight)
curl -s -X OPTIONS \
  -H "Origin: https://tu-proyecto.vercel.app" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type,ngrok-skip-browser-warning" \
  -I https://TU-SUBDOMINIO.ngrok-free.app/network-scan
# Debes ver: Access-Control-Allow-Origin: *

# Prueba el escaneo de redes
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "ngrok-skip-browser-warning: true" \
  -d '{"method":"powershell","label":"test"}' \
  https://TU-SUBDOMINIO.ngrok-free.app/network-scan | python3 -m json.tool
```

---

## FLUJO COMPLETO DE ARRANQUE (cada sesión)

Abre **3 terminales** en Ubuntu/WSL2:

### Terminal 1 — Backend
```bash
sudo service mariadb start
export GROQ_API_KEY="gsk_TU_CLAVE_AQUI"
cd ~/metatron
python api.py
```

### Terminal 2 — Túnel ngrok
```bash
ngrok http 8000
# Copia la URL https://xxxx.ngrok-free.app
```

### Terminal 3 — Actualiza Vercel (si la URL cambió)
```bash
# Opción A: actualiza la env var desde la CLI de Vercel
npx vercel env add NEXT_PUBLIC_API_URL
# Ingresa la nueva URL cuando te la pida, elige 'production'

# Opción B: redeploy forzado sin cambios de código
npx vercel --prod
```

---

## SOLUCIÓN RÁPIDA DE PROBLEMAS

| Síntoma | Causa probable | Solución |
|---------|---------------|----------|
| `Unexpected token '<'` | ngrok devuelve HTML | Confirma que el header `ngrok-skip-browser-warning: true` está en el fetch |
| `Preflight request failed` | CORS mal configurado | Verifica que `CORSMiddleware` esté con `allow_credentials=False` y `allow_origins=["*"]` |
| Tabla de redes vacía | Parser netsh falla | Corre `powershell.exe -Command "netsh wlan show networks mode=bssid"` en WSL2 y revisa la salida |
| `ERR_CONNECTION_REFUSED` | ngrok o FastAPI no corre | Verifica que ambos procesos están activos |
| Botones sin efecto | JS no cargado | Abre la consola del navegador (F12) y busca errores |

---

## ESTRUCTURA RECOMENDADA DEL PROYECTO

```
metatron/
├── api.py                  ← Backend FastAPI (WSL2)
├── skills/                 ← Scripts generados por IA
├── frontend/               ← Tu proyecto Next.js
│   ├── public/
│   │   └── script.js       ← Cliente API (HTML plano)
│   ├── lib/
│   │   └── api.js          ← Cliente API (Next.js módulo)
│   ├── components/
│   │   └── NetworksTable.jsx
│   └── .env.local          ← NEXT_PUBLIC_API_URL=https://xxx.ngrok-free.app
└── README.md
```

> En Next.js, crea `.env.local` en la raíz del frontend:
> ```
> NEXT_PUBLIC_API_URL=https://TU-SUBDOMINIO.ngrok-free.app
> ```
> Este archivo NO se sube a GitHub (agrégalo a `.gitignore`).
> Para producción en Vercel, usa el panel de Environment Variables.
