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
