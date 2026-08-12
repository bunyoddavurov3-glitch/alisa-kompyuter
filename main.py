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
CLIENT_SECRET = os.environ.get("O