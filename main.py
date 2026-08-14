import os
import secrets
import time
import threading
import json
import base64
import hashlib
import hmac
from collections import deque
from urllib.parse import urlencode
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)

AGENT_SECRET = os.environ.get("AGENT_SECRET", "")
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "alisa-kompyuter")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
TOKEN_SECRET = (os.environ.get("OAUTH_TOKEN_SECRET") or AGENT_SECRET or CLIENT_SECRET).encode("utf-8")

DEVICE_ID = "windows_pc"
DEVICE_NAME = "Kompyuter"

AUTH_CODES = {}
ACCESS_TOKENS = {}
REFRESH_TOKENS = {}
COMMAND_QUEUE = deque()
QUEUE_LOCK = threading.Lock()
LAST_AGENT_POLL = 0.0

# O'chirish taymerining ilovadagi holati.
# Yandex Smart Home custom nomli mode instance'larni qabul qilmaydi,
# shuning uchun valid "program" capability ichida 4 ta rejim ishlatiladi:
# auto = bekor qilish, one = 30 daqiqa, two = 1 soat, three = 2 soat.
TIMER_LOCK = threading.Lock()
SHUTDOWN_TIMER_MODE = "auto"
SHUTDOWN_TIMER_DEADLINE = None

TIMER_SECONDS = {
    "one": 30 * 60,
    "two": 60 * 60,
    "three": 2 * 60 * 60,
}


def make_code():
    return secrets.token_urlsafe(32)


def make_legacy_token():
    return secrets.token_urlsafe(48)


def request_id():
    return request.headers.get("X-Request-Id", secrets.token_hex(16))


def agent_is_online():
    return LAST_AGENT_POLL > 0 and (time.time() - LAST_AGENT_POLL) < 15


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_signed_token(kind, user_id, scope, expires_at):
    if not TOKEN_SECRET:
        return make_legacy_token()
    payload = {"kind": kind, "user_id": user_id, "scope": scope or "", "exp": int(expires_at), "v": 1}
    raw = _b64(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signature = hmac.new(TOKEN_SECRET, raw.encode("ascii"), hashlib.sha256).digest()
    return raw + "." + _b64(signature)


def verify_signed_token(token, expected_kind):
    if not TOKEN_SECRET or not token or "." not in token:
        return None
    try:
        raw, signature = token.rsplit(".", 1)
        expected = hmac.new(TOKEN_SECRET, raw.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(signature)):
            return None
        payload = json.loads(_unb64(raw).decode("utf-8"))
        if payload.get("kind") != expected_kind or int(payload.get("exp", 0)) <= int(time.time()) or not payload.get("user_id"):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def check_access_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False, None
    token = header[7:].strip()
    signed = verify_signed_token(token, "access")
    if signed:
        return True, signed
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
    return jsonify({"error_code": "UNAUTHORIZED", "error_message": "Invalid access token"}), 401


def action_response(device_id, capability_type, instance, status, error_code=None, error_message=None):
    result = {"status": status}
    if error_code:
        result["error_code"] = error_code
    if error_message:
        result["error_message"] = error_message
    return jsonify({"request_id": request_id(), "payload": {"devices": [{"id": device_id, "capabilities": [{"type": capability_type, "state": {"instance": instance, "action_result": result}}]}]}})


def get_shutdown_timer_mode():
    """Ilovaga joriy o'chirish taymeri holatini qaytaradi."""
    global SHUTDOWN_TIMER_MODE, SHUTDOWN_TIMER_DEADLINE
    with TIMER_LOCK:
        if SHUTDOWN_TIMER_DEADLINE is not None and time.time() >= SHUTDOWN_TIMER_DEADLINE:
            SHUTDOWN_TIMER_MODE = "auto"
            SHUTDOWN_TIMER_DEADLINE = None
        return SHUTDOWN_TIMER_MODE


def set_shutdown_timer(mode):
    """Yandex mode qiymatini ichki timer holatiga o'tkazadi."""
    global SHUTDOWN_TIMER_MODE, SHUTDOWN_TIMER_DEADLINE
    with TIMER_LOCK:
        SHUTDOWN_TIMER_MODE = mode
        seconds = TIMER_SECONDS.get(mode)
        SHUTDOWN_TIMER_DEADLINE = time.time() + seconds if seconds else None


@app.route("/", methods=["GET", "HEAD"])
def home():
    return "Alisa Kompyuter serveri ishlayapti", 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "device": DEVICE_ID, "agent_online": agent_is_online()})


@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():
    if request.args.get("response_type") != "code":
        return oauth_error("unsupported_response_type")
    if request.args.get("client_id") != CLIENT_ID:
        return oauth_error("invalid_client", 401)
    redirect_uri = request.args.get("redirect_uri")
    if not redirect_uri:
        return oauth_error("invalid_request")
    requested_scope = request.args.get("scope", "")
    state = request.args.get("state", "")
    code = make_code()
    AUTH_CODES[code] = {"client_id": CLIENT_ID, "scope": requested_scope, "redirect_uri": redirect_uri, "created_at": time.time()}
    params = {"code": code, "client_id": CLIENT_ID, "scope": requested_scope}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return redirect(redirect_uri + separator + urlencode(params))


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = request.form.get("grant_type", "")
    client_id = request.form.get("client_id", "")
    client_secret = request.form.get("client_secret", "")
    if not client_id:
        basic = request.authorization
        if basic:
            client_id, client_secret = basic.username or "", basic.password or ""
    if client_id != CLIENT_ID:
        return oauth_error("invalid_client", 401)
    if CLIENT_SECRET and client_secret != CLIENT_SECRET:
        return oauth_error("invalid_client", 401)

    if grant_type == "authorization_code":
        code = request.form.get("code", "")
        data = AUTH_CODES.pop(code, None)
        if not data or time.time() - data["created_at"] > 600:
            return oauth_error("invalid_grant")
        user_id = "windows_user"
        scope = data.get("scope", "")
        access_expires = time.time() + 30 * 24 * 60 * 60
        access_token = make_signed_token("access", user_id, scope, access_expires)
        refresh_token = make_signed_token("refresh", user_id, scope, time.time() + 180 * 24 * 60 * 60)
        ACCESS_TOKENS[access_token] = {"user_id": user_id, "scope": scope, "expires_at": access_expires}
        REFRESH_TOKENS[refresh_token] = {"user_id": user_id, "scope": scope}
        return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": 2592000, "refresh_token": refresh_token})

    if grant_type == "refresh_token":
        refresh_token = request.form.get("refresh_token", "")
        signed = verify_signed_token(refresh_token, "refresh")
        if signed:
            access_token = make_signed_token("access", signed["user_id"], signed.get("scope", ""), time.time() + 30 * 24 * 60 * 60)
            return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": 2592000})
        data = REFRESH_TOKENS.get(refresh_token)
        if not data:
            return oauth_error("invalid_grant")
        access_token = make_signed_token("access", data["user_id"], data["scope"], time.time() + 30 * 24 * 60 * 60)
        return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": 2592000})

    return oauth_error("unsupported_grant_type")


@app.route("/oauth/refresh", methods=["POST"])
def oauth_refresh():
    return oauth_token()


@app.route("/v1.0/user/devices", methods=["GET"])
def get_devices():
    ok, token_data = check_access_token()
    if not ok:
        return yandex_unauthorized()
    return jsonify({
        "request_id": request_id(),
        "payload": {
            "user_id": token_data["user_id"],
            "devices": [{
                "id": DEVICE_ID,
                "name": DEVICE_NAME,
                "description": "Windows kompyuter",
                "room": "Xona",
                "type": "devices.types.media_device.tv_box",
                "status_info": {"reportable": False},
                "custom_data": {"device": DEVICE_ID},
                "capabilities": [
                    {"type": "devices.capabilities.toggle", "retrievable": False, "reportable": False, "parameters": {"instance": "pause"}},
                    {"type": "devices.capabilities.on_off", "retrievable": False, "reportable": False, "parameters": {"split": False}},
                    {"type": "devices.capabilities.toggle", "retrievable": False, "reportable": False, "parameters": {"instance": "mute"}},
                    {"type": "devices.capabilities.range", "retrievable": False, "reportable": False, "parameters": {"instance": "volume", "random_access": True, "range": {"min": 0, "max": 100, "precision": 1}, "unit": "unit.percent"}},
                    {
                        "type": "devices.capabilities.mode",
                        "retrievable": True,
                        "reportable": False,
                        "parameters": {
                            "instance": "program",
                            "modes": [
                                {"value": "auto"},
                                {"value": "one"},
                                {"value": "two"},
                                {"value": "three"}
                            ]
                        }
                    }
                ],
                "properties": [],
                "device_info": {"manufacturer": "Windows", "model": "Windows PC", "sw_version": "1.0"}
            }]
        }
    })


@app.route("/v1.0/user/devices/query", methods=["POST"])
def query_devices():
    ok, _ = check_access_token()
    if not ok:
        return yandex_unauthorized()
    body = request.get_json(silent=True) or {}
    online = agent_is_online()
    timer_mode = get_shutdown_timer_mode()
    devices = []
    for device in body.get("devices", []):
        devices.append({
            "id": device.get("id", DEVICE_ID),
            "capabilities": [
                {"type": "devices.capabilities.on_off", "state": {"instance": "on", "value": online}},
                {"type": "devices.capabilities.mode", "state": {"instance": "program", "value": timer_mode}}
            ]
        })
    return jsonify({"request_id": request_id(), "payload": {"devices": devices}})


@app.route("/v1.0/user/devices/action", methods=["POST"])
def device_action():
    ok, _ = check_access_token()
    if not ok:
        return yandex_unauthorized()
    body = request.get_json(silent=True) or {}
    devices = body.get("payload", {}).get("devices", [])
    if not devices:
        return jsonify({"request_id": request_id(), "payload": {"devices": []}})

    for device in devices:
        device_id = device.get("id", DEVICE_ID)
        if device_id != DEVICE_ID:
            return action_response(device_id, "devices.capabilities.on_off", "on", "ERROR", "DEVICE_NOT_FOUND", "Kompyuter qurilmasi topilmadi")

        capabilities = device.get("capabilities", [])

        # Yangi: ilovadagi o'chirish taymeri.
        timer_capability = next(
            (
                capability for capability in capabilities
                if capability.get("type") == "devices.capabilities.mode"
                and capability.get("state", {}).get("instance") == "program"
            ),
            None
        )

        if timer_capability is not None:
            state = timer_capability.get("state", {})
            mode = state.get("value")
            seconds = TIMER_SECONDS.get(mode)

            if mode == "auto":
                if not agent_is_online():
                    return action_response(device_id, "devices.capabilities.mode", "program", "ERROR", "DEVICE_UNREACHABLE", "Windows agent ishlamayapti yoki kompyuter ulanmagan")
                with QUEUE_LOCK:
                    COMMAND_QUEUE.append({"command": "cancel_shutdown", "created_at": time.time()})
                set_shutdown_timer("auto")
                print("Yandex: O'CHIRISH TAYMERI BEKOR QILINDI")
                return action_response(device_id, "devices.capabilities.mode", "program", "DONE")

            if seconds is None:
                return action_response(device_id, "devices.capabilities.mode", "program", "ERROR", "INVALID_VALUE", "O'chirish taymeri qiymati noto'g'ri")

            if not agent_is_online():
                return action_response(device_id, "devices.capabilities.mode", "program", "ERROR", "DEVICE_UNREACHABLE", "Windows agent ishlamayapti yoki kompyuter ulanmagan")

            with QUEUE_LOCK:
                COMMAND_QUEUE.append({"command": "shutdown_after", "created_at": time.time(), "seconds": seconds})
            set_shutdown_timer(mode)
            daqiqa = seconds // 60
            print(f"Yandex: O'CHIRISH TAYMERI {daqiqa} daqiqaga o'rnatildi")
            return action_response(device_id, "devices.capabilities.mode", "program", "DONE")

        pause_capability = next(
            (
                capability for capability in capabilities
                if capability.get("type") == "devices.capabilities.toggle"
                and capability.get("state", {}).get("instance") == "pause"
            ),
            None
        )

        if pause_capability is not None:
            state = pause_capability.get("state", {})
            value = state.get("value")
            with QUEUE_LOCK:
                COMMAND_QUEUE.append({
                    "command": "play_pause",
                    "created_at": time.time(),
                    "value": bool(value)
                })
            print("Yandex: PAUSE buyrug'i ustuvor qilib navbatga qo'shildi")
            return action_response(device_id, "devices.capabilities.toggle", "pause", "DONE")

        for capability in capabilities:
            ctype = capability.get("type")
            state = capability.get("state", {})
            instance = state.get("instance")
            value = state.get("value")
            relative = state.get("relative", False)

            if ctype == "devices.capabilities.on_off" and instance == "on":
                if value is False:
                    if not agent_is_online():
                        return action_response(device_id, ctype, instance, "ERROR", "DEVICE_UNREACHABLE", "Windows agent ishlamayapti yoki kompyuter ulanmagan")
                    with QUEUE_LOCK:
                        COMMAND_QUEUE.append({"command": "shutdown", "created_at": time.time()})
                    print("Yandex: SHUTDOWN buyrug'i navbatga qo'shildi")
                    return action_response(device_id, ctype, instance, "DONE")
                return action_response(device_id, ctype, instance, "ERROR", "INVALID_ACTION", "Kompyuterni masofadan yoqish hozircha qo'llab-quvvatlanmaydi")

            if ctype == "devices.capabilities.toggle" and instance == "mute":
                with QUEUE_LOCK:
                    COMMAND_QUEUE.append({"command": "mute", "created_at": time.time(), "value": bool(value)})
                return action_response(device_id, ctype, instance, "DONE")

            if ctype == "devices.capabilities.range" and instance == "volume":
                try:
                    amount = float(value)
                except (TypeError, ValueError):
                    return action_response(device_id, ctype, instance, "ERROR", "INVALID_VALUE", "Ovoz qiymati noto'g'ri")
                if relative:
                    command = "volume_up" if amount > 0 else "volume_down"
                    count = max(1, min(100, int(round(abs(amount)))))
                    with QUEUE_LOCK:
                        COMMAND_QUEUE.append({"command": command, "created_at": time.time(), "count": count})
                else:
                    percent = max(0, min(100, int(round(amount))))
                    with QUEUE_LOCK:
                        COMMAND_QUEUE.append({"command": "volume_set", "created_at": time.time(), "percent": percent})
                return action_response(device_id, ctype, instance, "DONE")

        return action_response(device_id, "devices.capabilities.on_off", "on", "ERROR", "INVALID_ACTION", "Qo'llab-quvvatlanmagan buyruq")

    return action_response(DEVICE_ID, "devices.capabilities.on_off", "on", "ERROR", "INVALID_ACTION", "Qo'llab-quvvatlanmagan buyruq")


@app.route("/agent/poll", methods=["GET"])
def agent_poll():
    global LAST_AGENT_POLL
    if not check_agent_secret():
        return jsonify({"ok": False, "error": "Ruxsat berilmadi"}), 401
    LAST_AGENT_POLL = time.time()
    with QUEUE_LOCK:
        command = COMMAND_QUEUE.popleft() if COMMAND_QUEUE else None
    if command is None:
        return jsonify({"ok": True, "command": None, "agent_online": True})
    response = {"ok": True, "command": command.get("command"), "agent_online": True}
    for key in ("hours", "seconds", "percent", "count", "value"):
        if key in command:
            response[key] = command[key]
    return jsonify(response)


@app.route("/command", methods=["POST"])
def local_command():
    if not check_agent_secret():
        return jsonify({"ok": False, "error": "Ruxsat berilmadi"}), 401
    data = request.get_json(silent=True) or {}
    command = data.get("command")
    allowed = {"shutdown", "restart", "sleep", "shutdown_after", "cancel_shutdown", "play_pause", "previous", "next", "stop", "mute", "volume_up", "volume_down", "volume_set"}
    if command not in allowed:
        return jsonify({"ok": False, "error": "Noma'lum buyruq"}), 400
    item = {"command": command, "created_at": time.time()}
    if command == "sleep":
        hours = data.get("hours", 1)
        if hours not in (1, 2):
            return jsonify({"ok": False, "error": "Faqat 1 yoki 2 soat"}), 400
        item["hours"] = hours
    elif command == "shutdown_after":
        try:
            seconds = int(data.get("seconds"))
            if seconds < 1:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "seconds noto'g'ri"}), 400
        item["seconds"] = seconds
    elif command == "volume_set":
        try:
            percent = int(data.get("percent"))
            if not 0 <= percent <= 100:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "percent 0-100 oralig'ida bo'lishi kerak"}), 400
        item["percent"] = percent
    elif command in ("volume_up", "volume_down"):
        try:
            count = max(1, min(100, int(data.get("count", 1))))
        except (TypeError, ValueError):
            count = 1
        item["count"] = count
    with QUEUE_LOCK:
        COMMAND_QUEUE.append(item)
    return jsonify({"ok": True})


@app.route("/v1.0/user/unlink", methods=["POST"])
def unlink():
    return jsonify({"request_id": request_id()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print("=" * 60)
    print("ALISA KOMPYUTER SERVERI")
    print("=" * 60)
    print(f"Port: {port}")
    print("Windows agent: /agent/poll")
    print("Yandex: /v1.0/user/devices/action")
    print("O'chirish taymeri: program mode -> auto/1/2/3")
    print("Til: O'zbekcha")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=False)
