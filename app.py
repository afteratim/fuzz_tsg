import os
import re
import csv
import io
import hmac
import secrets
import logging
import tempfile
from pathlib import Path
from functools import wraps
from zipfile import BadZipFile

from flask import Flask, request, session, redirect, url_for, render_template, flash, send_file, abort
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

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
)
CSRFProtect(app)

# Avoid access logs containing query strings or other request details. Do not log user data.
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "WARNING"))
logger = logging.getLogger("private_analyzer")


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # Self-hosted assets only; no inline scripts, external fonts, analytics, or CDNs.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.is_secure or os.environ.get("RENDER", ""):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if not APP_PASSWORD:
        return render_template("setup_required.html"), 503
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user_ok = hmac.compare_digest(username.encode(), APP_USERNAME.encode())
        pass_ok = hmac.compare_digest(password.encode(), APP_PASSWORD.encode())
        if user_ok and pass_ok:
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            return redirect(url_for("index"))
        # Do not log credentials or submitted form data.
        flash("Login failed. Check your credentials and try again.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def index():
    return render_template("index.html", extensions=", ".join(sorted(ALLOWED_EXTENSIONS)))


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    uploads = request.files.getlist("documents")
    if len(uploads) != 2 or any(not f or not f.filename for f in uploads):
        flash("Choose exactly two documents to compare.", "error")
        return redirect(url_for("index"))

    prepared = []
    try:
        with tempfile.TemporaryDirectory(prefix="pda_") as temp_dir:
            root = Path(temp_dir)
            for upload in uploads:
                original_name = upload.filename or "document"
                safe_name = secure_filename(original_name)
                if not safe_name or not allowed_file(safe_name):
                    raise ValueError(f"Unsupported file type for {original_name}.")
                # Stream to temporary storage while enforcing the per-file cap.
                destination = root / (secrets.token_hex(8) + "_" + safe_name)
                total = 0
                with destination.open("wb") as out:
                    while True:
                        chunk = upload.stream.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_FILE_BYTES:
                            raise ValueError(f"{safe_name} exceeds the 25 MB per-file limit.")
                        out.write(chunk)
                if total == 0:
                    raise ValueError(f"{safe_name} is empty.")
                prepared.append((original_name, destination))

            extracted = []
            for name, path in prepared:
                extracted.append((name, extract_document(path, name)))

            name_a, doc_a = extracted[0]
            name_b, doc_b = extracted[1]
            result = compare_documents(doc_a, doc_b, name_a, name_b)
            # Result is rendered immediately; uploads and intermediate files are removed
            # when TemporaryDirectory exits. Results are not persisted in a database/session.
            return render_template("results.html", result=result)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))
    except (BadZipFile, UnicodeDecodeError, csv.Error) as exc:
        logger.warning("A document could not be parsed (type=%s).", type(exc).__name__)
        flash("A file could not be read. Check that it is valid and not password-protected.", "error")
        return redirect(url_for("index"))
    except Exception as exc:
        # Do not log exception messages: parser errors may contain file-derived content.
        logger.error("Document processing failed (type=%s).", type(exc).__name__)
        flash("Processing failed. Try a smaller or simpler file. No document details were logged by this app.", "error")
        return redirect(url_for("index"))


def normalize_cell(value):
    if value is None:
        return ""
    text = str(value).replace("\u00a0", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text.casefold()


def row_key(row):
    return tuple(normalize_cell(cell) for cell in row)


def compare_documents(doc_a, doc_b, name_a, name_b):
    rows_a = doc_a.get("rows", [])
    rows_b = doc_b.get("rows", [])
    # Multiset comparison preserves duplicate counts.
    from collections import Counter
    counter_a = Counter(row_key(r) for r in rows_a if any(normalize_cell(c) for c in r))
    counter_b = Counter(row_key(r) for r in rows_b if any(normalize_cell(c) for c in r))
    missing_b = []
    missing_a = []
    row_display_a = {}
    row_display_b = {}
    for r in rows_a:
        row_display_a.setdefault(row_key(r), r)
    for r in rows_b:
        row_display_b.setdefault(row_key(r), r)
    for key, count in (counter_a - counter_b).items():
        missing_b.extend([row_display_a.get(key, list(key))] * count)
    for key, count in (counter_b - counter_a).items():
        missing_a.extend([row_display_b.get(key, list(key))] * count)

    return {
        "name_a": name_a,
        "name_b": name_b,
        "type_a": doc_a.get("kind", "Document"),
        "type_b": doc_b.get("kind", "Document"),
        "rows_a": len(rows_a),
        "rows_b": len(rows_b),
        "matched": sum((counter_a & counter_b).values()),
        "only_a": missing_b[:500],
        "only_b": missing_a[:500],
        "truncated": len(missing_b) > 500 or len(missing_a) > 500,
        "notes": doc_a.get("notes", []) + doc_b.get("notes", []),
    }


@app.route("/export.csv", methods=["POST"])
@login_required
def export_csv():
    # The report is posted back from the browser. No report is stored server-side.
    # CSRF is enabled; exports should only be requested from the current authenticated session.
    import json
    raw = request.form.get("report_json", "")
    if len(raw) > 2_000_000:
        abort(413)
    try:
        import json
        result = json.loads(raw)
    except Exception:
        abort(400)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Status", "Document A", "Document B", "Row"])
    for row in result.get("only_a", []):
        writer.writerow(["Only in Document A", result.get("name_a", ""), result.get("name_b", ""), " | ".join(map(str, row))])
    for row in result.get("only_b", []):
        writer.writerow(["Only in Document B", result.get("name_a", ""), result.get("name_b", ""), " | ".join(map(str, row))])
    response = send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="comparison_report.csv",
    )
    return response


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    flash("The upload is too large. Each file must be 25 MB or less; select only two files.", "error")
    return redirect(url_for("index"))


@app.errorhandler(413)
def too_large_report(_error):
    return "Export is too large.", 413


if __name__ == "__main__":
    # Local development only. Production is run by Gunicorn through Render.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
