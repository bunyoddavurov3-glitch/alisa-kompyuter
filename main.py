import os
import secrets
import time
import threading
from collections import deque
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)

# ==================================================
# SOZLAMALAR
# ==================================================

AGENT_SECRET = os.environ.get("AGENT_SECRET", "")
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "alisa-kompyuter")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")

DEVICE_ID = "windows_pc"
DEVICE_NAME = "Kompyuter"

# Windows agent bu serverga chiqib /agent/poll ni tekshiradi.
# Railway porti avtomatik PORT orqali olinadi.

# ==================================================
# ODDIY XOTIRA
# ==================================================

AUTH_CODES = {}
ACCESS_TOKENS = {}
REFRESH_TOKENS = {}

# Windows agentga yuboriladigan buyruqlar navbati.
COMMAND_QUEUE = deque()
QUEUE_LOCK = threading.Lock()

# Agent oxirgi marta qachon poll qilganini saqlaymiz.
LAST_AGENT_POLL = 0.0


# ==================================================
# YORDAMCHI FUNKSIYALAR
# ==================================================

def make_code():
    return secrets.token_urlsafe(32)


def make_token():
    return secrets.token_urlsafe(48)


def request_id():
    return request.headers.get("X-Request-Id", secrets.token_hex(16))


def agent_is_online():
    # Agent har 2 soniyada poll qiladi.
    # 15 soniyadan oshsa offline deb hisoblaymiz.
    return LAST_AGENT_POLL > 0 and (time.time() - LAST_AGENT_POLL) < 15


def check_access_token():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return False, None

    token = header[7:].strip()
    data = ACCESS_TOKENS.get(token)

    if not data:
        return False, None

    if time.time() > data["expires_at"]:
        ACCESS_TOKENS.pop(token, None)
        return False, None

    return True, data


def check_agent_secret():
    token = request.headers.get("X-Agent-Token", "")
    return bool(AGENT_SECRET) and secrets.compare_digest(token, AGENT_SECRET)


def oauth_error(message, status=400):
    return jsonify({"error": message}), status


def yandex_unauthorized():
    return jsonify({
        "error_code": "UNAUTHORIZED",
        "error_message": "Invalid access token"
    }), 401


def action_response(device_id, status, error_code=None, error_message=None):
    result = {
        "status": status
    }

    if error_code:
        result["error_code"] = error_code

    if error_message:
        result["error_message"] = error_message

    return jsonify({
        "request_id": request_id(),
        "payload": {
            "devices": [
                {
                    "id": device_id,
                    "capabilities": [
                        {
                            "type": "devices.capabilities.on_off",
                            "state": {
                                "instance": "on",
                                "action_result": result
                            }
                        }
                    ]
                }
            ]
        }
    })


# ==================================================
# HEALTH
# ==================================================

@app.route("/", methods=["GET", "HEAD"])
def home():
    return "Alisa Kompyuter serveri ishlayapti", 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "device": DEVICE_ID,
        "agent_online": agent_is_online()
    })


# ==================================================
# OAUTH AUTHORIZE
# ==================================================

@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():
    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state")
    scope = request.args.get("scope", "")

    if response_type != "code":
        return oauth_error("unsupported_response_type")

    if client_id != CLIENT_ID:
        return oauth_error("invalid_client", 401)

    if not redirect_uri:
        return oauth_error("invalid_request")

    code = make_code()

    AUTH_CODES[code] = {
        "client_id": client_id,
        "scope": scope,
        "created_at": time.time()
    }

    # Authorization code faqat qisqa vaqtga amal qiladi.
    url = redirect_uri + "?code=" + code

    if state:
        url += "&state=" + state

    return redirect(url)


# ==================================================
# OAUTH TOKEN
# ==================================================

@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = request.form.get("grant_type", "")
    client_id = request.form.get("client_id", "")
    client_secret = request.form.get("client_secret", "")

    if client_id != CLIENT_ID:
        return oauth_error("invalid_client", 401)

    if CLIENT_SECRET and client_secret != CLIENT_SECRET:
        return oauth_error("invalid_client", 401)

    if grant_type == "authorization_code":
        code = request.form.get("code", "")
        data = AUTH_CODES.pop(code, None)

        if not data:
            return oauth_error("invalid_grant", 400)

        # 10 daqiqalik authorization code muddati.
        if time.time() - data["created_at"] > 600:
            return oauth_error("invalid_grant", 400)

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

    if grant_type == "refresh_token":
        refresh_token = request.form.get("refresh_token", "")
        data = REFRESH_TOKENS.get(refresh_token)

        if not data:
            return oauth_error("invalid_grant", 400)

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

    return oauth_error("unsupported_grant_type", 400)


@app.route("/oauth/refresh", methods=["POST"])
def oauth_refresh():
    return oauth_token()


# ==================================================
# YANDEX SMART HOME: DEVICE LIST
# ==================================================

@app.route("/v1.0/user/devices", methods=["GET"])
def get_devices():
    ok, token_data = check_access_token()

    if not ok:
        return yandex_unauthorized()

    online = agent_is_online()

    return jsonify({
        "request_id": request_id(),
        "payload": {
            "user_id": token_data["user_id"],
            "devices": [
                {
                    "id": DEVICE_ID,
                    "name": DEVICE_NAME,
                    "description": "Windows kompyuter",
                    "room": "Xona",
                    "type": "devices.types.other",
                    "status_info": {
                        "online": online
                    },
                    "custom_data": {
                        "device": DEVICE_ID
                    },
                    "capabilities": [
                        {
                            "type": "devices.capabilities.on_off",
                            "retrievable": True,
                            "reportable": False,
                            "parameters": {
                                "split": False
                            }
                        }
                    ],
                    "properties": [],
                    "device_info": {
                        "manufacturer": "Windows",
                        "model": "Windows PC",
                        "sw_version": "1.0"
                    }
                }
            ]
        }
    })


# ==================================================
# YANDEX SMART HOME: DEVICE QUERY
# ==================================================

@app.route("/v1.0/user/devices/query", methods=["POST"])
def query_devices():
    ok, _ = check_access_token()

    if not ok:
        return yandex_unauthorized()

    body = request.get_json(silent=True) or {}
    online = agent_is_online()
    devices = []

    for device in body.get("devices", []):
        device_id = device.get("id", DEVICE_ID)

        devices.append({
            "id": device_id,
            "capabilities": [
                {
                    "type": "devices.capabilities.on_off",
                    "state": {
                        "instance": "on",
                        "value": online
                    }
                }
            ]
        })

    return jsonify({
        "request_id": request_id(),
        "payload": {
            "devices": devices
        }
    })


# ==================================================
# YANDEX SMART HOME: DEVICE ACTION
# ==================================================

@app.route("/v1.0/user/devices/action", methods=["POST"])
def device_action():
    ok, _ = check_access_token()

    if not ok:
        return yandex_unauthorized()

    body = request.get_json(silent=True) or {}
    devices = body.get("payload", {}).get("devices", [])

    if not devices:
        return jsonify({
            "request_id": request_id(),
            "payload": {"devices": []}
        })

    for device in devices:
        device_id = device.get("id", DEVICE_ID)

        if device_id != DEVICE_ID:
            return action_response(
                device_id,
                "ERROR",
                "DEVICE_NOT_FOUND",
                "Kompyuter qurilmasi topilmadi"
            )

        for capability in device.get("capabilities", []):
            if capability.get("type") != "devices.capabilities.on_off":
                continue

            state = capability.get("state", {})
            value = state.get("value")

            # FALSE = Kompyuterni o'chirish
            if value is False:
                if not agent_is_online():
                    return action_response(
                        device_id,
                        "ERROR",
                        "DEVICE_UNREACHABLE",
                        "Windows agent ishlamayapti yoki kompyuter ulanmagan"
                    )

                with QUEUE_LOCK:
                    COMMAND_QUEUE.append({
                        "command": "shutdown",
                        "created_at": time.time()
                    })

                print("Yandex: SHUTDOWN buyrug'i navbatga qo'shildi")

                return action_response(device_id, "DONE")

            # TRUE = Kompyuterni yoqish.
            # Kompyuter to'liq o'chganidan keyin oddiy agent uni yoqa olmaydi.
            return action_response(
                device_id,
                "ERROR",
                "INVALID_ACTION",
                "Kompyuterni masofadan yoqish hozircha qo'llab-quvvatlanmaydi"
            )

    return action_response(
        DEVICE_ID,
        "ERROR",
        "INVALID_ACTION",
        "Qo'llab-quvvatlanmagan buyruq"
    )


# ==================================================
# WINDOWS AGENT: POLL
# ==================================================

@app.route("/agent/poll", methods=["GET"])
def agent_poll():
    global LAST_AGENT_POLL

    if not check_agent_secret():
        return jsonify({
            "ok": False,
            "error": "Ruxsat berilmadi"
        }), 401

    LAST_AGENT_POLL = time.time()

    with QUEUE_LOCK:
        if COMMAND_QUEUE:
            command = COMMAND_QUEUE.popleft()
        else:
            command = None

    if command is None:
        return jsonify({
            "ok": True,
            "command": None,
            "agent_online": True
        })

    return jsonify({
        "ok": True,
        "command": command.get("command"),
        "hours": command.get("hours"),
        "agent_online": True
    })


# ==================================================
# WINDOWS AGENT: LOCAL COMMAND TEST
# ==================================================

@app.route("/command", methods=["POST"])
def local_command():
    # Bu endpoint internetdan ochiq buyruq bajarish uchun emas.
    # Agentning eski lokal testlari uchun qoldirilgan.
    if not check_agent_secret():
        return jsonify({
            "ok": False,
            "error": "Ruxsat berilmadi"
        }), 401

    data = request.get_json(silent=True) or {}
    command = data.get("command")

    with QUEUE_LOCK:
        if command == "shutdown":
            COMMAND_QUEUE.append({"command": "shutdown", "created_at": time.time()})
        elif command == "restart":
            COMMAND_QUEUE.append({"command": "restart", "created_at": time.time()})
        elif command == "sleep":
            hours = data.get("hours", 1)
            if hours not in (1, 2):
                return jsonify({"ok": False, "error": "Faqat 1 yoki 2 soat"}), 400
            COMMAND_QUEUE.append({"command": "sleep", "hours": hours, "created_at": time.time()})
        else:
            return jsonify({"ok": False, "error": "Noma'lum buyruq"}), 400

    return jsonify({"ok": True})


# ==================================================
# UNLINK
# ==================================================

@app.route("/v1.0/user/unlink", methods=["POST"])
def unlink():
    return jsonify({
        "request_id": request_id()
    })


# ==================================================
# START
# ==================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))

    print("=" * 60)
    print("ALISA KOMPYUTER SERVERI")
    print("=" * 60)
    print(f"Port: {port}")
    print("Windows agent: /agent/poll")
    print("Yandex: /v1.0/user/devices/action")
    print("Til: O'ZBEKCHA")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
