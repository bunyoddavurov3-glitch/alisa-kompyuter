import os
import time
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)

# Railway Environment Variables
AGENT_SECRET = os.environ.get("AGENT_SECRET", "")
DEVICE_ID = "windows_pc"

# Buyruqlar navbati
command = None
command_id = None


def check_agent_auth():
    token = request.headers.get("X-Agent-Token", "")
    return AGENT_SECRET and secrets.compare_digest(token, AGENT_SECRET)


@app.route("/", methods=["GET", "HEAD"])
def home():
    return "Alisa Kompyuter serveri ishlayapti", 200


# Yandex Smart Home: qurilmalar ro'yxati
@app.route("/v1.0/user/devices", methods=["GET"])
def devices():
    request_id = request.headers.get("X-Request-Id", "")

    return jsonify({
        "request_id": request_id,
        "payload": {
            "user_id": "local-user",
            "devices": [
                {
                    "id": DEVICE_ID,
                    "name": "Kompyuter",
                    "description": "Windows kompyuter",
                    "room": "Mening xonam",
                    "type": "devices.types.socket",
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
                    "properties": []
                }
            ]
        }
    })


# Yandex qurilma holatini so'raganda
@app.route("/v1.0/user/devices/query", methods=["POST"])
def query_devices():
    data = request.get_json(silent=True) or {}
    request_id = request.headers.get("X-Request-Id", "")

    devices = []

    for device in data.get("devices", []):
        if device.get("id") == DEVICE_ID:
            devices.append({
                "id": DEVICE_ID,
                "capabilities": [
                    {
                        "type": "devices.capabilities.on_off",
                        "state": {
                            "instance": "on",
                            "value": True
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


# Yandex kompyuterni o'chirish buyrug'ini yuborganda
@app.route("/v1.0/user/devices/action", methods=["POST"])
def action():
    global command, command_id

    data = request.get_json(silent=True) or {}
    request_id = request.headers.get("X-Request-Id", "")

    for device in data.get("payload", {}).get("devices", []):
        if device.get("id") != DEVICE_ID:
            continue

        for capability in device.get("capabilities", []):
            if capability.get("type") == "devices.capabilities.on_off":
                state = capability.get("state", {})

                if (
                    state.get("instance") == "on"
                    and state.get("value") is False
                ):
                    command = "shutdown"
                    command_id = secrets.token_hex(16)

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
                                "action_result": {
                                    "status": "DONE"
                                }
                            }
                        }
                    ]
                }
            ]
        }
    })


# Windows agent buyruqni tekshiradi
@app.route("/agent/poll", methods=["GET"])
def agent_poll():
    global command, command_id

    if not check_agent_auth():
        return jsonify({"error": "unauthorized"}), 401

    if command:
        result = {
            "command": command,
            "id": command_id
        }

        command = None
        command_id = None

        return jsonify(result)

    return jsonify({
        "command": None
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "alisa-kompyuter"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
