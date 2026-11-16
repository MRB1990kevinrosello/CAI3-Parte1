import os
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"

import time
import secrets
import requests
from dotenv import load_dotenv
from flask import Flask, redirect, url_for, request, jsonify, make_response, render_template
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import JsonWebToken, JsonWebKey, JoseError

load_dotenv()

ISSUER = os.environ.get("OAUTH_ISSUER", "http://localhost:8000")
AUDIENCE = os.environ.get("OAUTH_AUDIENCE", "hospital-api")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
CLIENT_ID = "hospital-web"
CLIENT_SECRET = os.environ["CLIENT_SECRET"]   # cliente confidencial: secreto en .env

app = Flask(__name__)
app.secret_key = os.environ["PORTAL_SECRET_KEY"]
app.config["SESSION_COOKIE_NAME"] = "portal_session"

oauth = OAuth(app)
oauth.register(
    name="hospital_insegus",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url=f"{ISSUER}/oauth/authorize",
    access_token_url=f"{ISSUER}/oauth/token",
    client_kwargs={
        "scope": "paciente:leer medico:escribir",
        "token_endpoint_auth_method": "client_secret_post",
        "code_challenge_method": "S256"   # PKCE
    }
)

jwt_rs256 = JsonWebToken(["RS256"])

# iss, aud y exp son obligatorios y deben tener el valor esperado
CLAIMS_OPTIONS = {
    "iss": {"essential": True, "value": ISSUER},
    "aud": {"essential": True, "value": AUDIENCE},
    "exp": {"essential": True},
}

PUBLIC_KEYS = None

def validar_jwt(token_string):
    global PUBLIC_KEYS
    if PUBLIC_KEYS is None:
        # Se descarga una sola vez la clave PÚBLICA del servidor de identidad
        jwks = requests.get(f"{ISSUER}/.well-known/jwks.json", timeout=5).json()
        PUBLIC_KEYS = JsonWebKey.import_key_set(jwks)
    claims = jwt_rs256.decode(token_string, PUBLIC_KEYS, claims_options=CLAIMS_OPTIONS)
    claims.validate()
    return claims

class JWTTokenObj:
    def __init__(self, claims):
        self.claims = claims
        self.scope = claims.get("scope", "")

    def is_expired(self):
        exp = self.claims.get("exp")
        return exp is not None and time.time() > exp

    def is_revoked(self):
        return False

    def get_scope(self):
        return self.scope

class JWTBearerValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        try:
            return JWTTokenObj(validar_jwt(token_string))
        except (JoseError, ValueError, requests.RequestException):
            return None

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return False

    def scope_insufficient(self, token_scopes, required_scopes):
        if not required_scopes:
            return False
        token_scope_set = set(scope_to_list(token_scopes))
        required_scope_set = set(scope_to_list(required_scopes))
        return not required_scope_set.issubset(token_scope_set)

require_oauth = ResourceProtector()
require_oauth.register_token_validator(JWTBearerValidator())

# Sesión en servidor los tokens se quedan aquí y el navegador .solo recibe un identificador aleatorio (sid) en una cookie HttpOnly
SESIONES = {}

def renovar_si_caducado(sesion):
    if time.time() < sesion["exp"] - 10:
        return
    nuevo = oauth.hospital_insegus.fetch_access_token(
        grant_type="refresh_token",
        refresh_token=sesion["refresh_token"],
        scope=sesion["scope"]
    )
    sesion["access_token"] = nuevo["access_token"]
    sesion["refresh_token"] = nuevo["refresh_token"]   # rotación, se guarda el nuevo
    sesion["exp"] = time.time() + nuevo["expires_in"]

@app.route("/")
def index():
    sesion = SESIONES.get(request.cookies.get("sid", ""))
    return render_template("portal.html", usuario=sesion["usuario"] if sesion else None)

@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)
    return oauth.hospital_insegus.authorize_redirect(redirect_uri)

@app.route("/callback")
def callback():
    try:
        token = oauth.hospital_insegus.authorize_access_token()
        claims = validar_jwt(token["access_token"])
    except (OAuthError, JoseError, ValueError, requests.RequestException):
        return "Error de autenticación", 400

    sid = secrets.token_urlsafe(32)
    SESIONES[sid] = {
        "access_token": token["access_token"],
        "refresh_token": token["refresh_token"],
        "usuario": claims["sub"],
        "scope": claims["scope"],
        "exp": claims["exp"]
    }
    resp = make_response(redirect("/"))
    resp.set_cookie("sid", sid, httponly=True, secure=COOKIE_SECURE, samesite="Lax")
    resp.delete_cookie("access_token")   # limpia una cookie heredada del portal antiguo
    return resp

@app.route("/logout")
def logout():
    sesion = SESIONES.pop(request.cookies.get("sid", ""), None)
    if sesion:
        # Se invalida también el refresh token en el servidor de identidad
        try:
            requests.post(
                f"{ISSUER}/oauth/revoke",
                data={"token": sesion["refresh_token"], "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
                timeout=5
            )
        except requests.RequestException:
            pass   # la sesión local se cierra igualmente
    resp = make_response(redirect("/"))
    resp.delete_cookie("sid")
    resp.delete_cookie("access_token")   # limpia una cookie heredada del portal antiguo
    return resp

@app.before_request
def inject_bearer_from_session():
    if request.path.startswith("/api/") and "Authorization" not in request.headers:
        sid = request.cookies.get("sid", "")
        sesion = SESIONES.get(sid)
        if sesion:
            try:
                renovar_si_caducado(sesion)
                request.environ["HTTP_AUTHORIZATION"] = f"Bearer {sesion['access_token']}"
            except (OAuthError, requests.RequestException):
                # Refresh token caducado o revocado, hay que volver a iniciar sesión
                SESIONES.pop(sid, None)

@app.route("/api/historial", methods=["GET"])
@require_oauth("paciente:leer")
def get_historial():
    return jsonify({
        "status": "ok",
        "datos": "Historial clínico confidencial (Grupo O+)"
    })

@app.route("/api/historial", methods=["POST"])
@require_oauth("medico:escribir")
def post_historial():
    datos = request.get_json(silent=True) or {}
    diagnostico = datos.get("diagnostico", "")
    return jsonify({
        "status": "ok",
        "mensaje": f"Historial médico actualizado con: {diagnostico}",
    })

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Server"] = "Hospital-Portal"
    return response

if __name__ == "__main__":
    app.run(port=8001, debug=False)
