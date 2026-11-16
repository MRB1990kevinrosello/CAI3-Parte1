import base64
import hashlib
import json
import os
import re
import secrets
import time
import requests
import pyotp
from dotenv import dotenv_values
from authlib.jose import jwt, JsonWebKey

AS, RS = "http://localhost:8000", "http://localhost:8001"
CALLBACK = f"{RS}/callback"
ENV = dotenv_values(".env")
CLIENT_SECRET = ENV["CLIENT_SECRET"]
# La semilla solo se puede ver al enrolarse; se guarda para poder repetir el script
FICHERO_SEMILLA = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".semilla_rocio.json")


def comprobar(nombre, obtenido, esperado):
    print(f"  {nombre:<58} HTTP {obtenido}  {'OK' if obtenido == esperado else 'FALLO'}")


# 1. Claims
print("\n[1] Validación de iss, aud y exp (tokens firmados con la clave real)")
with open(ENV["JWT_PRIVATE_KEY_PATH"], "rb") as f:
    privada = JsonWebKey.import_key(f.read(), {"kty": "RSA"})
kid = privada.thumbprint()
now = int(time.time())
base = {"iss": AS, "sub": "rocio", "aud": "hospital-api", "scope": "paciente:leer", "exp": now + 60}


def api_con(claims):
    token = jwt.encode({"alg": "RS256", "kid": kid}, claims, privada).decode()
    return requests.get(f"{RS}/api/historial", headers={"Authorization": f"Bearer {token}"}).status_code


comprobar("Token correcto (control)", api_con(base), 200)
comprobar("Emisor falso (iss = http://evil.example)", api_con({**base, "iss": "http://evil.example"}), 401)
comprobar("Audiencia falsa (aud = otra-app)", api_con({**base, "aud": "otra-app"}), 401)
comprobar("Sin fecha de caducidad (sin exp)", api_con({k: v for k, v in base.items() if k != "exp"}), 401)
comprobar("Caducado hace 100 segundos", api_con({**base, "exp": now - 100}), 401)

# 2. Refresh tokens
print("\n[2] Rotación y reutilización de refresh tokens")
# Enrolamiento MFA legítimo: usuario y contraseña en /enroll-mfa, se lee la clave manual y se confirma con un TOTP.
# Si rocio ya está enrolada (segunda ejecución con el mismo servidor) se reutiliza la semilla guardada.
enrol = requests.Session()
r = enrol.post(f"{AS}/enroll-mfa", data={"username": "rocio", "password": "SuperSegura2026!"}, allow_redirects=False)
if r.status_code == 302:
    pagina = enrol.get(f"{AS}/setup-mfa").text
    semilla = re.search(r'id="clave-manual">([A-Z2-7]{32})<', pagina).group(1)
    r = enrol.post(f"{AS}/setup-mfa", data={"totp": pyotp.TOTP(semilla).now()}, allow_redirects=False)
    comprobar("Enrolamiento MFA de rocio confirmado", r.status_code, 302)
    with open(FICHERO_SEMILLA, "w", encoding="utf-8") as f:
        json.dump({"semilla": semilla}, f)
elif r.status_code == 403 and os.path.exists(FICHERO_SEMILLA):
    with open(FICHERO_SEMILLA, encoding="utf-8") as f:
        semilla = json.load(f)["semilla"]
    print("  rocio ya estaba enrolada: se reutiliza la semilla guardada")
else:
    raise SystemExit(f"  No se pudo enrolar a rocio (HTTP {r.status_code}) y no hay semilla guardada. "
                     "Reinicia auth_server.py y vuelve a ejecutar el script.")
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
r = requests.post(
    f"{AS}/oauth/authorize",
    params={"response_type": "code", "client_id": "hospital-web", "redirect_uri": CALLBACK,
            "scope": "paciente:leer", "state": "x", "code_challenge": challenge, "code_challenge_method": "S256"},
    data={"username": "rocio", "password": "SuperSegura2026!", "totp": pyotp.TOTP(semilla).now()},
    allow_redirects=False,
)
if r.status_code != 302:
    # La semilla guardada es de un arranque anterior del servidor (rocio se ha enrolado de nuevo desde el navegador)
    if os.path.exists(FICHERO_SEMILLA):
        os.remove(FICHERO_SEMILLA)
    raise SystemExit(f"  Login de rocio rechazado (HTTP {r.status_code}): la semilla guardada ya no es válida. "
                     "Reinicia auth_server.py y vuelve a ejecutar el script.")
code = re.search(r"code=([^&]+)", r.headers["Location"]).group(1)
tokens = requests.post(f"{AS}/oauth/token", data={
    "grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK, "code_verifier": verifier,
    "client_id": "hospital-web", "client_secret": CLIENT_SECRET,
}).json()


def refrescar(refresh_token):
    return requests.post(f"{AS}/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": refresh_token,
        "client_id": "hospital-web", "client_secret": CLIENT_SECRET,
    })


rt1 = tokens["refresh_token"]
print(f"  Refresh token inicial (RT1): {rt1[:20]}...")
r = refrescar(rt1)
rt2 = r.json().get("refresh_token", "")
comprobar("Se usa RT1: devuelve tokens nuevos", r.status_code, 200)
print(f"  Refresh token nuevo  (RT2): {rt2[:20]}...  distinto de RT1: {rt1 != rt2}")
r = refrescar(rt1)
comprobar("Se reutiliza RT1 (simula que lo ha robado un atacante)", r.status_code, 400)
print(f"    respuesta: {r.text.strip()}")
r = refrescar(rt2)
comprobar("RT2 tras detectar el reuso (toda la cadena revocada)", r.status_code, 400)

# 3. Logout
print("\n[3] Cierre de sesión en el portal")
s = requests.Session()
url = s.get(f"{RS}/login", allow_redirects=False).headers["Location"]
r = s.post(url, data={"username": "rocio", "password": "SuperSegura2026!", "totp": pyotp.TOTP(semilla).now()},
           allow_redirects=False)
r = s.get(r.headers["Location"], allow_redirects=False)
sid = r.cookies.get("sid") or s.cookies.get("sid")
print(f"  Cookie recibida: {r.headers.get('Set-Cookie', '').split(', session=')[0]}")
comprobar("Leer historial con la sesión abierta", requests.get(f"{RS}/api/historial", cookies={"sid": sid}).status_code, 200)
requests.get(f"{RS}/logout", cookies={"sid": sid}, allow_redirects=False)
comprobar("Mismo sid después de cerrar sesión", requests.get(f"{RS}/api/historial", cookies={"sid": sid}).status_code, 401)
print()
