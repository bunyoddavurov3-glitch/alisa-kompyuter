import os
import secrets
import time
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)

# =========================
# SOZLAMALAR
# =========================

AGENT_SECRET = os.environ.get("AGENT_SECRET", "")

# Yandex Dialogs'da keyin aynan shu qiymatlarni kiritamiz
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "alisa-kompyuter")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")

# Bitta kompyuter
DEVICE_ID = "windows_pc"

# Windows agent manzili
AGENT_URL = os.environ.get(
    "AGENT_URL",
    "https://alisa-kompyuter-production.up.railway.app"
)

# Oddiy xotira
AUTH_CODES = {}
ACCESS_TOKENS = {}
REFRESH_TOKENS = {}


# =========================
# YORDAMCHI FUNKSIYALAR
# =========================

def make_code():
    return secrets.token_urlsafe(32)


def make_token():
    return secrets.token_urlsafe(48)


def check_agent_token():
    token = request.headers.get("X-Agent-Token", "")
    return bool(AGENT_SECRET) and secrets.compare_digest(
        token, AGENT_SECRET
    )


def check_access_token():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return False, None

    token = header[7:]

    data = ACCESS_TOKENS.get(token)

    if not data:
        return False, None

    # 30 kun
    if time.time() > data["expires_at"]:
        ACCESS_TOKENS.pop(token, None)
        return False, None

    return True, data


# =========================
# TEST / HEALTH
# =========================

@app.route("/", methods=["GET", "HEAD"])
def home():
    return "Alisa Kompyuter serveri ishlayapti", 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "device": DEVICE_ID
    })


# =========================
# OAUTH AUTHORIZE
# =========================

@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():

    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state")
    scope = request.args.get("scope", "")

    if response_type != "code":
        return "response_type=code kerak", 400

    if client_id != CLIENT_ID:
        return "Noto'g'ri client_id", 401

    if not redirect_uri:
        return "redirect_uri kerak", 400

    # Bitta foydalanuvchili tizim:
    # hozircha avtomatik tasdiqlaymiz.
    code = make_code()

    AUTH_CODES[code] = {
        "client_id": client_id,
        "scope": scope,
        "created_at": time.time()
    }

    url = (
        redirect_uri
        + "?code="
        + code
    )

    if state:
        url += "&state=" + state

    return redirect(url)


# =========================
# OAUTH TOKEN
# =========================

@app.route("/oauth/token", methods=["POST"])
def oauth_token():

    grant_type = request.form.get("grant_type")

    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    if client_id != CLIENT_ID:
        return jsonify({
            "error": "invalid_client"
        }), 401

    if CLIENT_SECRET and client_secret != CLIENT_SECRET:
        return jsonify({
            "error": "invalid_client"
        }), 401

    # -------------------------
    # AUTHORIZATION CODE
    # -------------------------

    if grant_type == "authorization_code":

        code = request.form.get("code")

        if not code:
            return jsonify({
                "error": "invalid_request"
            }), 400

        data = AUTH_CODES.pop(code, None)

        if not data:
            return jsonify({
                "error": "invalid_grant"
            }), 400

        access_token = make_token()
        refresh_token = make_token()

        ACCESS_TOKENS[access_token] = {
            "user_id": "windows_user",
            "scope": data.get("scope", ""),
            "expires_at": time.time() + 30 * 24 * 60 * 60
        }

        REFRESH_TOKENS[refresh_token] = {
            "user_id": "windows_user",
            "scope": data.get("scope", "")
        }

        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 2592000,
            "refresh_token": refresh_token
        })

    # -------------------------
    # REFRESH TOKEN
    # -------------------------

    if grant_type == "refresh_token":

        refresh_token = request.form.get("refresh_token")

        data = REFRESH_TOKENS.get(refresh_token)

        if not data:
            return jsonify({
                "error": "invalid_grant"
            }), 400

        access_token = make_token()

        ACCESS_TOKENS[access_token] = {
            "user_id": data["user_id"],
            "scope": data["scope"],
            "expires_at": time.time() + 30 * 24 * 60 * 60
        }

        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 2592000
        })

    return jsonify({
        "error": "unsupported_grant_type"
    }), 400


# =========================
# REFRESH ENDPOINT
# =========================

@app.route("/oauth/refresh", methods=["POST"])
def oauth_refresh():
    return oauth_token()


# =========================
# YANDEX SMART HOME
# =========================

@app.route("/v1.0/", methods=["HEAD"])
def smart_home_root():
    return "", 200


# =========================
# DEVICE DISCOVERY
# =========================

@app.route("/v1.0/user/devices", methods=["GET"])
def get_devices():

    ok, token_data = check_access_token()

    if not ok:
        return jsonify({
            "error_code": "UNAUTHORIZED",
            "error_message": "Invalid access token"
        }), 401

    request_id = request.headers.get(
        "X-Request-Id",
        secrets.token_hex(16)
    )

    return jsonify({
        "request_id": request_id,
        "payload": {
            "user_id": token_data["user_id"],
            "devices": [
                {
                    "id": DEVICE_ID,
                    "name": "Kompyuter",
                    "description": "Windows kompyuter",
                    "room": "Xona",
                    "type": "devices.types.other",
                    "custom_data": {
                        "device": DEVICE_ID
                    },
                    "capabilities": [
                        {
                            "type": "devices.capabilities.on_off",
                            "retrievable": True,
                            "reportable": False,
                            "parameters": {
                                "split": True,
                                "instance": "on",
                                "modes": [
                                    {
                                        "instance": "on",
                                        "type": "devices.capabilities.on_off"
                                    }
                                ]
                            }
                        }
                    ],
                    "device_info": {
                        "manufacturer": "Windows",
                        "model": "Windows PC",
                        "sw_version": "1.0"
                    }
                }
            ]
        }
    })


# =========================
# DEVICE QUERY
# =========================

@app.route("/v1.0/user/devices/query", methods=["POST"])
def query_devices():

    ok, token_data = check_access_token()

    if not ok:
        return jsonify({
            "error_code": "UNAUTHORIZED"
        }), 401

    request_id = request.headers.get(
        "X-Request-Id",
        secrets.token_hex(16)
    )

    body = request.get_json(silent=True) or {}

    devices = []

    for device in body.get("devices", []):
        devices.append({
            "id": device.get("id", DEVICE_ID),
            "capabilities": [
                {
                    "type": "devices.capabilities.on_off",
                    "state": {
                        "instance": "on",
                        "value": False
                    }
                }
            ]
        })

    return jsonify({
        "request_id": request_id,
        "payload": {
            "devices": devices
        }
    })


# =========================
# DEVICE ACTION
# =========================

@app.route("/v1.0/user/devices/action", methods=["POST"])
def device_action():

    ok, token_data = check_access_token()

    if not ok:
        return jsonify({
            "error_code": "UNAUTHORIZED"
        }), 401

    request_id = request.headers.get(
        "X-Request-Id",
        secrets.token_hex(16)
    )

    body = request.get_json(silent=True) or {}

    # Yandex yuborgan buyruqni tekshiramiz
    for device in body.get("payload", {}).get("devices", []):

        device_id = device.get("id")

        for capability in device.get("capabilities", []):

            cap_type = capability.get("type")

            if cap_type == "devices.capabilities.on_off":

                state = capability.get("state", {})
                value = state.get("value")

                if value is False:

                    # Kompyuterni o'chirish
                    try:
                        import requests

                        requests.post(
                            AGENT_URL + "/command",
                            json={
                                "command": "shutdown"
                            },
                            headers={
                                "X-Agent-Token": AGENT_SECRET
                            },
                            timeout=10
                        )

                    except Exception as e:
                        print("Agent xatosi:", e)

    return jsonify({
        "request_id": request_id,
        "payload": {
            "devices": [
                {
                    "id": DEVICE_ID,
                    "capabilities": [
                        {
                            "type": "devices.capabilities.on_off",
                            "state": {
                                "instance": "on",
                                "action_result": {}
                            }
                        }
                    ]
                }
            ]
        }
    })


# =========================
# UNLINK
# =========================

@app.route("/v1.0/user/unlink", methods=["POST"])
def unlink():

    return jsonify({
        "request_id": request.headers.get(
            "X-Request-Id",
            secrets.token_hex(16)
        )
    })


# =========================
# START
# =========================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 8080))

    app.run(
        host="0.0.0.0",
        port=port
    )
