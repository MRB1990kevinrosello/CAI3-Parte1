import base64
import hashlib
import hmac
import json
import time
import requests
from authlib.jose import jwt, JsonWebKey

AS, RS = "http://localhost:8000", "http://localhost:8001"


def b64(datos):
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def api(token):
    r = requests.post(f"{RS}/api/historial", json={"diagnostico": "X"},
                      headers={"Authorization": f"Bearer {token}"})
    return r.status_code


def comprobar(nombre, obtenido, esperado):
    print(f"{nombre:<55} HTTP {obtenido}  {'OK' if obtenido == esperado else 'FALLO'}")


comprobar("Clave antigua /.well-known/jwt-key", requests.get(f"{AS}/.well-known/jwt-key").status_code, 404)

jwks = requests.get(f"{AS}/.well-known/jwks.json").json()
clave = jwks["keys"][0]
privada_expuesta = any(campo in clave for campo in ("d", "p", "q", "dp", "dq", "qi"))
print(f"{'JWKS solo contiene la parte pública':<55} {sorted(clave)}  {'FALLO' if privada_expuesta else 'OK'}")

now = int(time.time())
claims = {"iss": AS, "sub": "dr_gasca", "aud": "hospital-api",
          "scope": "paciente:leer medico:escribir", "iat": now, "exp": now + 300}
cuerpo = b64(json.dumps(claims).encode())

# Confusión de algoritmo: firmar en HS256 usando la clave pública como secreto
pem_publica = JsonWebKey.import_key(clave).as_pem()
cab = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": clave["kid"]}).encode())
firma = b64(hmac.new(pem_publica, f"{cab}.{cuerpo}".encode(), hashlib.sha256).digest())
comprobar("JWT en HS256 firmado con la clave pública", api(f"{cab}.{cuerpo}.{firma}"), 401)

# Token sin firma
cab = b64(json.dumps({"alg": "none"}).encode())
comprobar("JWT con alg none", api(f"{cab}.{cuerpo}."), 401)

# RS256 firmado con una clave del atacante
atacante = JsonWebKey.generate_key("RSA", 2048, is_private=True)
comprobar("JWT RS256 con clave del atacante (mismo kid)",
          api(jwt.encode({"alg": "RS256", "kid": clave["kid"]}, claims, atacante).decode()), 401)
comprobar("JWT RS256 con clave del atacante (kid inventado)",
          api(jwt.encode({"alg": "RS256", "kid": "x"}, claims, atacante).decode()), 401)

comprobar("API sin token ni sesión", requests.get(f"{RS}/api/historial").status_code, 401)
