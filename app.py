import os
import re
import csv
import io
import hmac
import secrets
import logging
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from functools import wraps
from zipfile import BadZipFile
from datetime import date, datetime, timedelta

from flask import Flask, request, session, redirect, url_for, render_template, flash, send_file, abort
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from openpyxl import load_workbook, Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

from extractors import extract_document, SUPPORTED_EXTENSIONS

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_REQUEST_BYTES = 52 * 1024 * 1024
MAX_FILES = 2
ALLOWED_EXTENSIONS = SUPPORTED_EXTENSIONS

if not SECRET_KEY:
    # Local development fallback only. Configure SECRET_KEY in Render for stable secure sessions.
    SECRET_KEY = secrets.token_hex(32)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
    WTF_CSRF_TIME_LIMIT=3600,
    # Render terminates HTTPS at its proxy. The CSRF token remains enabled;
    # disable only strict Referer validation because some browsers/privacy settings omit it.
    WTF_CSRF_SSL_STRICT=False,
)
CSRFProtect(app)
# Trust the single reverse proxy in front of this Render service for HTTPS scheme detection.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Avoid access logs containing query strings or other request details. Do not log user data.
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "WARNING"))
logger = logging.getLogger("private_analyzer")

# Short-lived in-process cache for interactive GST report and workbook download.
# Reports are not written to disk or a database; they disappear on restart/expiry.
_GST_REPORT_CACHE = {}
_GST_REPORT_TTL_SECONDS = 30 * 60

def _purge_gst_report_cache():
    now = time.time()
    for token, entry in list(_GST_REPORT_CACHE.items()):
        if now - entry["created"] > _GST_REPORT_TTL_SECONDS:
            _GST_REPORT_CACHE.pop(token, None)


# Basic in-memory login throttling. With the configured single Gunicorn worker,
# attempts are tracked for this process only; this is not a replacement for MFA/WAF.
_LOGIN_ATTEMPTS = defaultdict(deque)
_LOGIN_WINDOW_SECONDS = 900
_LOGIN_MAX_ATTEMPTS = 8


def login_rate_limited(client_key):
    now = time.time()
    attempts = _LOGIN_ATTEMPTS[client_key]
    while attempts and now - attempts[0] > _LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts) >= _LOGIN_MAX_ATTEMPTS


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

