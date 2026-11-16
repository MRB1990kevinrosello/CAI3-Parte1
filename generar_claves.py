"""Genera la clave privada RSA de firma y un .env con secretos aleatorios.

Se ejecuta UNA vez por instalación:  python generar_claves.py
Ni keys/ ni .env deben subirse a git ni incluirse en el zip.
"""
import os
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = "keys"
KEY_PATH = f"{KEY_DIR}/jwt_private.pem"
ENV_PATH = ".env"

os.makedirs(KEY_DIR, exist_ok=True)

if os.path.exists(KEY_PATH):
    print(f"[=] {KEY_PATH} ya existe, no se sobrescribe")
else:
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = clave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(KEY_PATH, "wb") as f:
        f.write(pem)
    print(f"[+] Clave privada RSA-2048 generada en {KEY_PATH}")

if os.path.exists(ENV_PATH):
    print(f"[=] {ENV_PATH} ya existe, no se sobrescribe")
else:
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write(
            f"AUTH_SERVER_SECRET_KEY={secrets.token_hex(32)}\n"
            f"PORTAL_SECRET_KEY={secrets.token_hex(32)}\n"
            f"CLIENT_SECRET={secrets.token_urlsafe(48)}\n"
            f"JWT_PRIVATE_KEY_PATH={KEY_PATH}\n"
            "OAUTH_ISSUER=http://localhost:8000\n"
            "OAUTH_AUDIENCE=hospital-api\n"
            "COOKIE_SECURE=1\n"
        )
    print(f"[+] {ENV_PATH} generado con secretos aleatorios")
