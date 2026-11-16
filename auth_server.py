import os
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"
import time
import base64
import secrets
from io import BytesIO

from flask import Flask, request, render_template, jsonify, session, redirect, url_for, abort
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.jose import jwt
from passlib.context import CryptContext
import pyotp
import qrcode
import logging
import threading

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config["OAUTH2_JWT_KEY"] = secrets.token_hex(32)
app.config["OAUTH2_JWT_ALG"] = "HS256"
app.config["OAUTH2_ACCESS_TOKEN_EXPIRES_IN"] = 3600

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
DUMMY_HASH = pwd_context.hash(secrets.token_urlsafe(32))
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 5 * 60

LOGIN_ATTEMPTS = {}
LOGIN_ATTEMPTS_LOCK = threading.Lock()
def esta_bloqueado(username: str) -> bool:
    now = time.time()
    with LOGIN_ATTEMPTS_LOCK:
        entry = LOGIN_ATTEMPTS.get(username)
        if not entry:
            return False
        if entry["locked_until"] > now:
            return True
        if entry["locked_until"] > 0:
            entry["locked_until"] = 0.0
        return False


def registrar_fallo(username: str) -> None:
    now = time.time()
    with LOGIN_ATTEMPTS_LOCK:
        entry = LOGIN_ATTEMPTS.setdefault(username, {"failures": 0, "locked_until": 0.0})
        entry["failures"] += 1

        if entry["failures"] >= MAX_FAILED_ATTEMPTS:
            entry["locked_until"] = now + LOCKOUT_DURATION_SECONDS
            entry["failures"] = 0
            hora_bloqueo = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
            app.logger.warning(
                f"BLOQUEO TEMPORAL activado para el usuario '{username}' a las {hora_bloqueo} "
                f"durante {LOCKOUT_DURATION_SECONDS // 60} minutos por exceder {MAX_FAILED_ATTEMPTS} intentos."
            )


def registrar_exito(username: str) -> None:
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.pop(username, None)

USERS = {
    "rocio": {
        "id": "1",
        "username": "rocio",
        "password_hash": pwd_context.hash("SuperSegura2026!"),
        "totp_secret": pyotp.random_base32(),
        "allowed_scopes": ["paciente:leer"],
        "totp_enrolled": False
    },
    "dr_gasca": {
        "id": "2",
        "username": "dr_gasca",
        "password_hash": pwd_context.hash("MedicoSegura2026!"),
        "totp_secret": pyotp.random_base32(),
        "allowed_scopes": ["paciente:leer", "medico:escribir"],
        "totp_enrolled": False
    }
}

CLIENTS = {
    "hospital-web": {
        "client_id": "hospital-web",
        "redirect_uris": [
            "http://localhost:8001/callback",
            "http://127.0.0.1:8001/callback"
        ],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "paciente:leer medico:escribir",
        "token_endpoint_auth_method": "none"
    }
}

AUTH_CODES = {}
TOKENS = {}

class ClientObj:
    def __init__(self, data): self.__dict__.update(data)
    def get_client_id(self): return self.client_id
    def get_default_redirect_uri(self): return self.redirect_uris[0] if self.redirect_uris else None
    def check_redirect_uri(self, uri): return uri in self.redirect_uris
    def check_grant_type(self, gt): return gt in self.grant_types
    def check_response_type(self, rt): return rt in self.response_types
    def check_endpoint_auth_method(self, method, endpoint): return method == self.token_endpoint_auth_method
    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        client_scopes = set(self.scope.split())
        requested_scopes = scope.split()
        return " ".join([s for s in requested_scopes if s in client_scopes])

class AuthCodeObj:
    def __init__(self, **kwargs): self.__dict__.update(kwargs)
    def is_expired(self): return time.time() > self.expires_at
    def get_redirect_uri(self): return self.redirect_uri
    def get_scope(self): return self.scope

class TokenObj:
    def __init__(self, **kwargs): self.__dict__.update(kwargs)
    def get_scope(self): return self.scope

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    def save_authorization_code(self, code, request):
        requested = (request.scope or "").split()
        user_allowed = set(request.user.get("allowed_scopes", []))
        final_scope = " ".join([s for s in requested if s in user_allowed])

        AUTH_CODES[code] = AuthCodeObj(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=final_scope,
            user_id=request.user["id"],
            code_challenge=request.data.get("code_challenge"),
            code_challenge_method=request.data.get("code_challenge_method"),
            expires_at=time.time() + 300
        )

    def query_authorization_code(self, code, client):
        item = AUTH_CODES.get(code)
        if item and item.client_id == client.client_id and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        AUTH_CODES.pop(authorization_code.code, None)

    def authenticate_user(self, authorization_code):
        return next((u for u in USERS.values() if u["id"] == authorization_code.user_id), None)

class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = False

    def authenticate_refresh_token(self, refresh_token):
        return TOKENS.get(refresh_token)

    def authenticate_user(self, credential):
        return next((u for u in USERS.values() if u["id"] == credential.user_id), None)

    def revoke_old_credential(self, credential):
        pass

def generate_jwt_access_token(client, grant_type, user, scope):
    now = int(time.time())
    header = {"alg": app.config["OAUTH2_JWT_ALG"]}
    payload = {
        "iss": "http://localhost:8000",
        "sub": user["username"],
        "aud": client.client_id,
        "scope": scope,
        "iat": now,
        "exp": now + app.config["OAUTH2_ACCESS_TOKEN_EXPIRES_IN"]
    }
    return jwt.encode(header, payload, app.config["OAUTH2_JWT_KEY"]).decode()

def save_token(token_data, request):
    if "refresh_token" in token_data:
        TOKENS[token_data["refresh_token"]] = TokenObj(
            user_id=request.user["id"],
            client_id=request.client.client_id,
            scope=token_data.get("scope", "")
        )

app.config["OAUTH2_ACCESS_TOKEN_GENERATOR"] = generate_jwt_access_token
server = AuthorizationServer(
    app,
    query_client=lambda cid: ClientObj(CLIENTS[cid]) if cid in CLIENTS else None,
    save_token=save_token
)
server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])
server.register_grant(RefreshTokenGrant)

@app.route("/enroll-mfa", methods=["GET", "POST"])
def enroll_login():
    if request.method == "GET":
        return render_template("enroll_login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if esta_bloqueado(username):
        app.logger.warning(f"Intento de enrolamiento rechazado (429 - bloqueado) para '{username}'")
        return render_template(
            "enroll_login.html",
            error="Demasiados intentos fallidos. Inténtalo de nuevo en unos minutos."
        ), 429

    user = USERS.get(username)
    hash_to_verify = user["password_hash"] if user else DUMMY_HASH
    password_ok = pwd_context.verify(password, hash_to_verify)

    if not user or not password_ok:
        registrar_fallo(username)
        reason = "usuario inexistente" if not user else "contraseña incorrecta"
        app.logger.warning(f"Fallo en enrolamiento MFA para '{username}': {reason}")
        return render_template("enroll_login.html", error="Credenciales inválidas"), 401

    registrar_exito(username)

    if user.get("totp_enrolled"):
        app.logger.info(f"Intento de re-enrolamiento bloqueado para '{username}'")
        return render_template("enroll_login.html", error="Este usuario ya tiene el MFA configurado."), 403

    session["enroll_user"] = username
    return redirect(url_for("setup_mfa"))


@app.route("/setup-mfa", methods=["GET", "POST"])
def setup_mfa():
    username = session.get("enroll_user")
    if not username:
        return redirect(url_for("enroll_login"))

    user = USERS.get(username)
    if not user or user.get("totp_enrolled"):
        session.pop("enroll_user", None)
        abort(403)

    totp = pyotp.TOTP(user["totp_secret"])

    if request.method == "POST":
        if esta_bloqueado(username):
            session.pop("enroll_user", None)
            app.logger.warning(f"Confirmación MFA rechazada (429 - bloqueado) para '{username}'")
            return render_template(
                "enroll_login.html",
                error="Demasiados intentos fallidos. Inténtalo de nuevo en unos minutos."
            ), 429

        totp_code = request.form.get("totp", "").strip()
        if totp.verify(totp_code, valid_window=1):
            registrar_exito(username)
            user["totp_enrolled"] = True
            session.pop("enroll_user", None)
            app.logger.info(f"Enrolamiento MFA completado con éxito para '{username}'")
            return redirect("http://localhost:8001/")
        else:
            registrar_fallo(username)
            app.logger.warning(f"Código TOTP incorrecto durante confirmación MFA para '{username}'")

            if esta_bloqueado(username):
                session.pop("enroll_user", None)
                return render_template(
                    "enroll_login.html",
                    error="Demasiados intentos fallidos. Inténtalo de nuevo en unos minutos."
                ), 429

            uri = totp.provisioning_uri(f"{user['username']}@hospital.es", issuer_name="Insegus")
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            qr_b64 = base64.b64encode(buf.getvalue()).decode()
            return render_template(
                "setup_mfa.html",
                qr_b64=qr_b64,
                username=user["username"],
                error="Código TOTP incorrecto. Inténtalo de nuevo."
            ), 401

    uri = totp.provisioning_uri(f"{user['username']}@hospital.es", issuer_name="Insegus")
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_mfa.html", qr_b64=qr_b64, username=user["username"])

@app.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    totp_code = request.form.get("totp", "").strip()

    if esta_bloqueado(username):
        app.logger.warning(f"Intento de login rechazado (429 - cuenta bloqueada temporalmente) para '{username}'")
        return render_template(
            "login.html",
            error="Demasiados intentos fallidos. Inténtalo de nuevo en unos minutos."
        ), 429

    user = USERS.get(username)
    hash_to_verify = user["password_hash"] if user else DUMMY_HASH
    password_ok = pwd_context.verify(password, hash_to_verify)
    credentials_ok = bool(user and password_ok)

    if credentials_ok and not user.get("totp_enrolled"):
        app.logger.warning(f"Login rechazado para '{username}': enrolamiento MFA incompleto")
        return render_template("login.html", error="Error en el proceso"), 403

    totp_ok = False
    if credentials_ok:
        totp = pyotp.TOTP(user["totp_secret"])
        totp_ok = totp.verify(totp_code, valid_window=1)

    if not (credentials_ok and totp_ok):
        registrar_fallo(username)
        if not user:
            cause = "usuario inexistente"
        elif not password_ok:
            cause = "contraseña incorrecta"
        else:
            cause = "código TOTP inválido"

        app.logger.warning(f"Fallo de autenticación en /oauth/authorize para '{username}': {cause}")
        return render_template("login.html", error="Credenciales o código FreeOTP inválidos"), 401

    registrar_exito(username)
    app.logger.info(f"Autenticación exitosa en /oauth/authorize para '{username}'")
    return server.create_authorization_response(grant_user=user)

@app.route("/oauth/token", methods=["POST"])
def issue_token():
    return server.create_token_response()

@app.route("/.well-known/jwt-key")
def jwt_key():
    return jsonify({"key": app.config["OAUTH2_JWT_KEY"], "alg": app.config["OAUTH2_JWT_ALG"]})

if __name__ == "__main__":
    app.run(port=8000, debug=True)
