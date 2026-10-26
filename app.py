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

from flask import Flask, request, session, redirect, url_for, render_template, flash, send_file, abort
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

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


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_signature(path, suffix):
    """Basic file-signature checks; not a substitute for parser isolation or malware scanning."""
    with open(path, "rb") as handle:
        head = handle.read(16)
    if suffix == ".pdf":
        valid = head.startswith(b"%PDF-")
    elif suffix in {".xlsx", ".xlsm", ".xltx", ".xltm", ".docx"}:
        valid = head.startswith(b"PK\x03\x04")
    elif suffix in {".jpg", ".jpeg"}:
        valid = head.startswith(b"\xff\xd8\xff")
    elif suffix == ".png":
        valid = head.startswith(b"\x89PNG\r\n\x1a\n")
    elif suffix == ".gif":
        valid = head.startswith((b"GIF87a", b"GIF89a"))
    elif suffix in {".tif", ".tiff"}:
        valid = head.startswith((b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+"))
    elif suffix == ".bmp":
        valid = head.startswith(b"BM")
    elif suffix == ".webp":
        valid = len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    elif suffix == ".rtf":
        valid = head.lstrip().startswith(b"{\\rtf")
    else:
        # CSV/TSV/TXT can legitimately have arbitrary text bytes.
        valid = True
    if not valid:
        raise ValueError(f"The file contents do not match the .{suffix.lstrip('.')} extension.")


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
        # Render is expected to terminate HTTPS at its edge. Use the apparent client IP
        # only as an in-memory rate-limit key; never log or persist it.
        client_key = request.headers.get("X-Forwarded-For", "unknown").split(",", 1)[0].strip()[:64]
        if login_rate_limited(client_key):
            flash("Too many login attempts. Wait 15 minutes before trying again.", "error")
            return render_template("login.html"), 429
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user_ok = hmac.compare_digest(username.encode(), APP_USERNAME.encode())
        pass_ok = hmac.compare_digest(password.encode(), APP_PASSWORD.encode())
        if user_ok and pass_ok:
            _LOGIN_ATTEMPTS.pop(client_key, None)
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            return redirect(url_for("index"))
        _LOGIN_ATTEMPTS[client_key].append(time.time())
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
                validate_file_signature(destination, destination.suffix.lower())
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
    from collections import Counter, defaultdict

    def clean_row(r):
        return ["" if c is None else str(c).strip() for c in r]

    def key_row(r):
        return tuple(normalize_cell(c) for c in r)

    # Use the first row as column headings when both documents appear to share a header.
    header_a = clean_row(rows_a[0]) if rows_a else []
    header_b = clean_row(rows_b[0]) if rows_b else []
    same_header = bool(header_a and header_b and key_row(header_a) == key_row(header_b))
    data_a = rows_a[1:] if same_header else rows_a[:]
    data_b = rows_b[1:] if same_header else rows_b[:]
    headers = header_a if same_header else []

    data_a = [clean_row(r) for r in data_a if any(normalize_cell(c) for c in r)]
    data_b = [clean_row(r) for r in data_b if any(normalize_cell(c) for c in r)]

    # Pair records sharing the first non-empty field (often invoice/bill number).
    # Full-row exact matches are counted separately; differing rows get human-readable remarks.
    exact_a = Counter(key_row(r) for r in data_a)
    exact_b = Counter(key_row(r) for r in data_b)
    matched = sum((exact_a & exact_b).values())

    def first_value(row):
        for value in row:
            if normalize_cell(value):
                return normalize_cell(value)
        return ""

    grouped_a = defaultdict(list)
    grouped_b = defaultdict(list)
    for row in data_a:
        grouped_a[first_value(row)].append(row)
    for row in data_b:
        grouped_b[first_value(row)].append(row)

    remarks = []
    paired_a_indices = set()
    paired_b_indices = set()
    # Pair changed rows by first column/key, only where a key occurs on both sides.
    for key in grouped_a.keys() & grouped_b.keys():
        if not key:
            continue
        a_rows = grouped_a[key]
        b_rows = grouped_b[key]
        if len(a_rows) != 1 or len(b_rows) != 1:
            continue
        a_row, b_row = a_rows[0], b_rows[0]
        if key_row(a_row) == key_row(b_row):
            continue
        fields = []
        max_cols = max(len(a_row), len(b_row))
        for i in range(max_cols):
            av = a_row[i] if i < len(a_row) else ""
            bv = b_row[i] if i < len(b_row) else ""
            if normalize_cell(av) == normalize_cell(bv):
                continue
            col_name = headers[i] if i < len(headers) and headers[i].strip() else f"Column {i + 1}"
            # If a numeric-looking field changed, calculate an absolute numeric difference.
            remark = f"{col_name}: '{av or '(blank)'}' → '{bv or '(blank)'}'"
            def to_num(v):
                try:
                    return float(str(v).replace(",", "").replace("₹", "").strip())
                except (TypeError, ValueError):
                    return None
            na, nb = to_num(av), to_num(bv)
            if na is not None and nb is not None:
                delta = nb - na
                remark += f" (difference: {delta:,.2f})"
            fields.append(remark)
        remarks.append({
            "key": a_row[0] if a_row else key,
            "row_a": a_row,
            "row_b": b_row,
            "remark": "; ".join(fields) if fields else "Rows differ after normalization.",
        })

    # Multiset exact-row comparison keeps duplicates and identifies records unique to each side.
    counter_a = Counter(key_row(r) for r in data_a)
    counter_b = Counter(key_row(r) for r in data_b)
    display_a, display_b = {}, {}
    for r in data_a:
        display_a.setdefault(key_row(r), r)
    for r in data_b:
        display_b.setdefault(key_row(r), r)
    only_a = []
    only_b = []
    for key, count in (counter_a - counter_b).items():
        only_a.extend([display_a[key]] * count)
    for key, count in (counter_b - counter_a).items():
        only_b.extend([display_b[key]] * count)

    # Distinguish rows explained by a changed-record remark from truly unmatched rows.
    changed_keys = {normalize_cell(item["key"]) for item in remarks}
    unmatched_a = [r for r in only_a if first_value(r) not in changed_keys]
    unmatched_b = [r for r in only_b if first_value(r) not in changed_keys]

    return {
        "name_a": name_a,
        "name_b": name_b,
        "type_a": doc_a.get("kind", "Document"),
        "type_b": doc_b.get("kind", "Document"),
        "rows_a": len(data_a),
        "rows_b": len(data_b),
        "matched": matched,
        "only_a": only_a[:500],
        "only_b": only_b[:500],
        "unmatched_a": unmatched_a[:500],
        "unmatched_b": unmatched_b[:500],
        "remarks": remarks[:500],
        "truncated": len(only_a) > 500 or len(only_b) > 500,
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
