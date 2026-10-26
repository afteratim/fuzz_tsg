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


def _self_ping_loop():
    """Optionally ping this service's public health endpoint to reduce idle sleep.

    Enable with ENABLE_SELF_PING=true and PUBLIC_BASE_URL=https://your-service.onrender.com.
    Render may still suspend Free services; this is best-effort, not a guarantee.
    """
    import urllib.request
    interval = max(300, int(os.environ.get("SELF_PING_INTERVAL_SECONDS", "600")))
    base_url = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        logger.warning("Self-ping enabled but PUBLIC_BASE_URL is not configured.")
        return
    health_url = base_url + "/health"
    while True:
        time.sleep(interval)
        try:
            req = urllib.request.Request(health_url, headers={"User-Agent": "PrivateDocumentAnalyzer-SelfPing/1.0"})
            with urllib.request.urlopen(req, timeout=15) as response:
                response.read(64)
        except Exception as exc:
            # Avoid logging URLs or response bodies; only log exception type.
            logger.warning("Self-ping request failed (type=%s).", type(exc).__name__)


def _start_self_ping_if_enabled():
    if os.environ.get("ENABLE_SELF_PING", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    import threading
    # Gunicorn is configured for one worker in this project. Guard against duplicate
    # startup within a process (for example, during local development reloads).
    if getattr(app, "_self_ping_started", False):
        return
    app._self_ping_started = True
    thread = threading.Thread(target=_self_ping_loop, name="self-ping", daemon=True)
    thread.start()


_start_self_ping_if_enabled()


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


@app.route("/gst-reconcile", methods=["GET"])
@login_required
def gst_reconcile():
    return render_template("gst_reconciliation.html")


@app.route("/gst-reconcile/run", methods=["POST"])
@login_required
def run_gst_reconciliation():
    upload = request.files.get("workbook")
    if not upload or not upload.filename:
        flash("Choose one Excel workbook containing the Pur and 2B tables.", "error")
        return redirect(url_for("gst_reconcile"))
    filename = secure_filename(upload.filename)
    if not filename.lower().endswith(".xlsx"):
        flash("Please upload an .xlsx workbook. Save macro-enabled or legacy files as .xlsx first.", "error")
        return redirect(url_for("gst_reconcile"))
    try:
        with tempfile.TemporaryDirectory(prefix="gst_recon_") as temp_dir:
            path = Path(temp_dir) / (secrets.token_hex(8) + "_" + filename)
            total = 0
            with path.open("wb") as out:
                while True:
                    chunk = upload.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_FILE_BYTES:
                        raise ValueError("The workbook exceeds the 25 MB per-file limit.")
                    out.write(chunk)
            if not total:
                raise ValueError("The uploaded workbook is empty.")
            validate_file_signature(path, ".xlsx")
            workbook = load_workbook(path, read_only=False, data_only=True)
            try:
                pur_rows = read_named_table(workbook, "Pur")
                portal_rows = read_named_table(workbook, "2B")
                report = reconcile_gst_tables(pur_rows, portal_rows, tolerance=2.0)
                output = build_gst_workbook(report)
            finally:
                workbook.close()
        return send_file(io.BytesIO(output), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name="GST_2B_Purchase_Reconciliation.xlsx")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("gst_reconcile"))
    except (BadZipFile, KeyError, OSError) as exc:
        logger.warning("GST workbook could not be parsed (type=%s).", type(exc).__name__)
        flash("The workbook could not be read. Confirm it is a valid, unprotected .xlsx file and contains both named tables.", "error")
        return redirect(url_for("gst_reconcile"))
    except Exception as exc:
        logger.error("GST reconciliation failed (type=%s).", type(exc).__name__)
        flash("GST reconciliation failed. Check table names and required columns, then try again.", "error")
        return redirect(url_for("gst_reconcile"))


def read_named_table(workbook, table_name):
    """Read an Excel Table by its defined table name, not by worksheet name."""
    target = table_name.casefold()
    accepted_names = {target}
    if target == "2b":
        # Excel table names cannot begin with a digit in many Excel versions; accept practical aliases.
        accepted_names.update({"table2b", "t2b", "portal2b"})
    for ws in workbook.worksheets:
        for name in ws.tables:
            if name.casefold() in accepted_names:
                table = ws.tables[name]
                cells = ws[table.ref]
                values = [[cell.value for cell in row] for row in cells]
                if len(values) < 2:
                    raise ValueError(f"The Excel table '{table_name}' has headers but no data rows.")
                headers = [str(v).strip() if v is not None else "" for v in values[0]]
                normalized = [normalize_header(h) for h in headers]
                missing = [label for label, aliases in REQUIRED_GST_COLUMNS.items() if not any(h in aliases for h in normalized)]
                if missing:
                    raise ValueError(f"Table '{table_name}' is missing required columns: {', '.join(missing)}.")
                records = []
                for excel_row, values_row in enumerate(values[1:], start=2):
                    if not any(v is not None and str(v).strip() for v in values_row):
                        continue
                    record = {normalize_header(headers[i]): values_row[i] if i < len(values_row) else None for i in range(len(headers))}
                    record["_source_row"] = excel_row
                    record["_table"] = table_name
                    records.append(record)
                return records
    raise ValueError(f"Could not find an Excel Table named '{table_name}'. Check Table Design → Table Name.")


REQUIRED_GST_COLUMNS = {
    "DATE": {"date", "invoice date", "bill date"},
    "Particulars": {"particulars", "party", "party name", "supplier name", "name"},
    "Supplier Invoice No.": {"supplier invoice no", "supplier invoice number", "invoice no", "invoice number", "inv no", "bill no"},
    "GSTIN/UIN": {"gstin uin", "gstin", "gstin number", "supplier gstin", "uin"},
    "TAXABLE VALUE": {"taxable value", "taxable amount", "taxable"},
    "INV VALUE": {"inv value", "invoice value", "invoice amount", "total invoice value"},
    "IGST": {"igst", "igst amount"},
    "CGST": {"cgst", "cgst amount"},
    "SGST": {"sgst", "sgst amount"},
}


def normalize_header(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold()).strip()


def gst_field(record, label):
    aliases = REQUIRED_GST_COLUMNS[label]
    for key, value in record.items():
        if key in aliases:
            return value
    return None


def gst_text(value):
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value).replace("\u00a0", " ")).strip()


def normalize_gstin(value):
    return re.sub(r"\s+", "", gst_text(value)).upper()


def normalize_invoice(value):
    # Conservative normalization: ignore case and whitespace only; preserve punctuation and leading zeros.
    return re.sub(r"\s+", "", gst_text(value)).upper()


def gst_number(value):
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace(",", "").replace("₹", "")
    try:
        return float(text)
    except ValueError:
        return None


def gst_date(value):
    if value is None or value == "":
        return ""
    if isinstance(value, (datetime, date)):
        return value.strftime("%d-%m-%Y")
    if isinstance(value, (int, float)):
        # Excel's default 1900 date system. openpyxl normally converts date-formatted cells already.
        try:
            return (datetime(1899, 12, 30) + timedelta(days=float(value))).strftime("%d-%m-%Y")
        except (OverflowError, ValueError):
            return str(value)
    text = str(value).strip()
    for fmt in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d", "%m/%d/%Y", "%d-%m-%y"):
        try:
            return datetime.strptime(text, fmt).strftime("%d-%m-%Y")
        except ValueError:
            pass
    return text


def parse_gst_date(value):
    """Parse normalized DD-MM-YYYY dates for chronological comparison."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value).strip(), "%d-%m-%Y").date()
    except (TypeError, ValueError):
        return None


def gst_record_view(record):
    return {
        "date": gst_date(gst_field(record, "DATE")),
        "name": gst_text(gst_field(record, "Particulars")),
        "invoice": gst_text(gst_field(record, "Supplier Invoice No.")),
        "gstin": normalize_gstin(gst_field(record, "GSTIN/UIN")),
        "taxable": gst_number(gst_field(record, "TAXABLE VALUE")),
        "invoice_value": gst_number(gst_field(record, "INV VALUE")),
        "igst": gst_number(gst_field(record, "IGST")),
        "cgst": gst_number(gst_field(record, "CGST")),
        "sgst": gst_number(gst_field(record, "SGST")),
        "source_row": record.get("_source_row", ""),
    }


def reconcile_gst_tables(pur_records, portal_records, tolerance=2.0):
    pur = [gst_record_view(r) for r in pur_records]
    portal = [gst_record_view(r) for r in portal_records]
    def key(row):
        inv = normalize_invoice(row["invoice"])
        gst = normalize_gstin(row["gstin"])
        return (gst, inv) if gst and inv else None
    pur_index, portal_index = defaultdict(list), defaultdict(list)
    for i, row in enumerate(pur):
        k = key(row)
        if k: pur_index[k].append(i)
    for i, row in enumerate(portal):
        k = key(row)
        if k: portal_index[k].append(i)
    pur_used, portal_used = set(), set()
    reconciliation, duplicates, validation = [], [], []

    # All records involved in duplicated GSTIN+invoice keys are sent to review; never guess a pairing.
    duplicate_keys = {k for k in set(pur_index) | set(portal_index) if len(pur_index.get(k, [])) > 1 or len(portal_index.get(k, [])) > 1}
    for k in sorted(duplicate_keys):
        for side, index, rows in (("Pur", pur_index, pur), ("2B", portal_index, portal)):
            if len(index.get(k, [])) > 1:
                duplicates.append([k[0], k[1], side, len(index[k]), "Duplicate GSTIN + invoice key; manual review required"] )
        for i in pur_index.get(k, []): pur_used.add(i)
        for i in portal_index.get(k, []): portal_used.add(i)
        # Show each source record as an individual review line.
        for i in pur_index.get(k, []):
            reconciliation.append(make_gst_line(pur[i], None, "Duplicate / Review Required", tolerance, "Duplicate key in Pur"))
        for i in portal_index.get(k, []):
            reconciliation.append(make_gst_line(None, portal[i], "Duplicate / Review Required", tolerance, "Duplicate key in 2B"))

    unique_common = (set(pur_index) & set(portal_index)) - duplicate_keys
    for k in sorted(unique_common):
        i, j = pur_index[k][0], portal_index[k][0]
        pur_used.add(i); portal_used.add(j)
        line = make_gst_line(pur[i], portal[j], "Matched", tolerance, "")
        if line["taxable_diff_abs"] > tolerance or any(line[f"{tax.lower()}_diff_abs"] > tolerance for tax in ("IGST", "CGST", "SGST")) or line["invoice_value_diff_abs"] > tolerance:
            line["remark"] = "Not Matched"
        elif line["date_pur"] != line["date_2b"]:
            line["remark"] = "Date Difference"
        else:
            line["remark"] = "Matched"
        reconciliation.append(line)

    # Earliest valid date in Purchase register, used for Old Bill Filed classification.
    pur_dates = [parsed for row in pur if (parsed := parse_gst_date(row["date"])) is not None]
    min_pur_date = min(pur_dates) if pur_dates else None

    # Check invoice-only overlaps for possible GSTIN mismatch, but do not auto-match them.
    remaining_pur = [i for i in range(len(pur)) if i not in pur_used]
    remaining_portal = [j for j in range(len(portal)) if j not in portal_used]
    pur_inv, portal_inv = defaultdict(list), defaultdict(list)
    for i in remaining_pur:
        inv = normalize_invoice(pur[i]["invoice"])
        if inv: pur_inv[inv].append(i)
    for j in remaining_portal:
        inv = normalize_invoice(portal[j]["invoice"])
        if inv: portal_inv[inv].append(j)
    possible_mismatch_pur, possible_mismatch_portal = set(), set()
    for inv in set(pur_inv) & set(portal_inv):
        for i in pur_inv[inv]:
            for j in portal_inv[inv]:
                if pur[i]["gstin"] != portal[j]["gstin"]:
                    possible_mismatch_pur.add(i); possible_mismatch_portal.add(j)
                    duplicates.append([f"{pur[i]['gstin']} / {portal[j]['gstin']}", inv, "Pur + 2B", 2, "Invoice number matches but GSTIN differs; verify supplier and invoice"] )
    for i in remaining_pur:
        if i in possible_mismatch_pur:
            reconciliation.append(make_gst_line(pur[i], None, "GSTIN Mismatch - Review", tolerance, "Same invoice number found in 2B with a different GSTIN"))
            pur_used.add(i)
        else:
            reconciliation.append(make_gst_line(pur[i], None, "Not on Portal", tolerance, "No corresponding invoice found in 2B"))
            pur_used.add(i)
    for j in remaining_portal:
        if j in possible_mismatch_portal:
            reconciliation.append(make_gst_line(None, portal[j], "GSTIN Mismatch - Review", tolerance, "Same invoice number found in Pur with a different GSTIN"))
            portal_used.add(j)
        else:
            portal_date = parse_gst_date(portal[j]["date"])
            if min_pur_date and portal_date and portal_date < min_pur_date:
                reconciliation.append(make_gst_line(
                    None, portal[j], "Old Bill Filed", tolerance,
                    f"Invoice date {portal[j]['date']} is earlier than the earliest Purchase date {min_pur_date.strftime('%d-%m-%Y')}. Check whether this is an old bill filed in a later period."
                ))
            else:
                reconciliation.append(make_gst_line(None, portal[j], "Not in Tally", tolerance, "No corresponding invoice found in Pur"))
            portal_used.add(j)

    for side, rows in (("Pur", pur), ("2B", portal)):
        for n, row in enumerate(rows, start=1):
            if not row["invoice"]: validation.append([side, row["source_row"], row["gstin"], "", "Supplier Invoice No. is blank"] )
            if not row["gstin"]: validation.append([side, row["source_row"], row["gstin"], row["invoice"], "GSTIN/UIN is blank; reliable matching may not be possible"] )
            elif len(row["gstin"]) != 15: validation.append([side, row["source_row"], row["gstin"], row["invoice"], f"GSTIN length is {len(row['gstin'])}; expected 15 characters. Verify manually."])
            if not row["date"]: validation.append([side, row["source_row"], row["gstin"], row["invoice"], "DATE is blank"] )
            for field in ("taxable", "invoice_value", "igst", "cgst", "sgst"):
                original = row[field]
                if original is None:
                    validation.append([side, row["source_row"], row["gstin"], row["invoice"], f"{field.replace('_', ' ').title()} is blank or not numeric"] )
            if all(row[x] is not None for x in ("taxable", "igst", "cgst", "sgst", "invoice_value")):
                expected = row["taxable"] + row["igst"] + row["cgst"] + row["sgst"]
                if abs(expected - row["invoice_value"]) > tolerance:
                    validation.append([side, row["source_row"], row["gstin"], row["invoice"], f"Taxable + IGST + CGST + SGST = {expected:.2f}; invoice value = {row['invoice_value']:.2f}; difference = {row['invoice_value'] - expected:+.2f}"])
    # Summary counts refer to reconciliation lines; duplicate records are review lines, not automatic matches.
    counts = defaultdict(int)
    for line in reconciliation: counts[line["remark"]] += 1
    return {"reconciliation": reconciliation, "duplicates": duplicates, "validation": validation, "pur_count": len(pur), "portal_count": len(portal), "tolerance": tolerance, "counts": dict(counts)}


def make_gst_line(pur, portal, remark, tolerance, detail):
    def val(row, field): return row[field] if row and row[field] is not None else None
    def diff(field):
        a, b = val(pur, field), val(portal, field)
        return (b - a) if a is not None and b is not None else None
    taxable_diff, inv_diff = diff("taxable"), diff("invoice_value")
    tax_diffs = {tax: diff(tax.lower()) for tax in ("IGST", "CGST", "SGST")}
    name = (pur["name"] if pur and pur["name"] else (portal["name"] if portal else ""))
    return {
        "gstin": val(pur, "gstin") or val(portal, "gstin") or "", "name": name,
        "invoice_pur": val(pur, "invoice") or "", "invoice_2b": val(portal, "invoice") or "",
        "date_pur": val(pur, "date") or "", "date_2b": val(portal, "date") or "",
        "taxable_pur": val(pur, "taxable"), "taxable_2b": val(portal, "taxable"), "taxable_diff": taxable_diff, "taxable_diff_abs": abs(taxable_diff) if taxable_diff is not None else 0,
        "invoice_value_pur": val(pur, "invoice_value"), "invoice_value_2b": val(portal, "invoice_value"), "invoice_value_diff": inv_diff, "invoice_value_diff_abs": abs(inv_diff) if inv_diff is not None else 0,
        "igst_pur": val(pur, "igst"), "igst_2b": val(portal, "igst"), "igst_diff": tax_diffs["IGST"], "igst_diff_abs": abs(tax_diffs["IGST"]) if tax_diffs["IGST"] is not None else 0,
        "cgst_pur": val(pur, "cgst"), "cgst_2b": val(portal, "cgst"), "cgst_diff": tax_diffs["CGST"], "cgst_diff_abs": abs(tax_diffs["CGST"]) if tax_diffs["CGST"] is not None else 0,
        "sgst_pur": val(pur, "sgst"), "sgst_2b": val(portal, "sgst"), "sgst_diff": tax_diffs["SGST"], "sgst_diff_abs": abs(tax_diffs["SGST"]) if tax_diffs["SGST"] is not None else 0,
        "remark": remark, "detail": detail, "tolerance": tolerance,
    }


def build_gst_workbook(report):
    wb = Workbook()
    ws = wb.active; ws.title = "Reconciliation"
    columns = [
        ("FinalGST", "gstin"), ("FinalName", "name"), ("Pur Invoice No.", "invoice_pur"), ("2B Invoice No.", "invoice_2b"),
        ("Pur Date", "date_pur"), ("2B Date", "date_2b"),
        ("2B TAXABLE VALUE", "taxable_2b"), ("2B INV VALUE", "invoice_value_2b"), ("2B IGST", "igst_2b"), ("2B CGST", "cgst_2b"), ("2B SGST", "sgst_2b"),
        ("PUR TAXABLE VALUE", "taxable_pur"), ("PUR INV VALUE", "invoice_value_pur"), ("PUR IGST", "igst_pur"), ("PUR CGST", "cgst_pur"), ("PUR SGST", "sgst_pur"),
        ("TAXABLE DIFF (2B - Pur)", "taxable_diff"), ("INV VALUE DIFF (2B - Pur)", "invoice_value_diff"), ("IGST DIFF (2B - Pur)", "igst_diff"), ("CGST DIFF (2B - Pur)", "cgst_diff"), ("SGST DIFF (2B - Pur)", "sgst_diff"), ("REMARKS", "remark"), ("DETAIL", "detail")
    ]
    write_sheet(ws, [c[0] for c in columns], [[line.get(c[1]) for c in columns] for line in report["reconciliation"]])
    missing_2b = [x for x in report["reconciliation"] if x["remark"] == "Not on Portal"]
    missing_pur = [x for x in report["reconciliation"] if x["remark"] == "Not in Tally"]
    old_bills = [x for x in report["reconciliation"] if x["remark"] == "Old Bill Filed"]
    tax_diffs = [x for x in report["reconciliation"] if any(x[k] is not None and x[k] > report["tolerance"] for k in ("taxable_diff_abs", "invoice_value_diff_abs", "igst_diff_abs", "cgst_diff_abs", "sgst_diff_abs"))]
    review = [x for x in report["reconciliation"] if "Review" in x["remark"] or x["remark"] == "Duplicate / Review Required"]
    all_discrepancies = [x for x in report["reconciliation"] if x["remark"] != "Matched"]
    write_gst_subset(wb, "Missing in 2B", columns, missing_2b)
    write_gst_subset(wb, "Missing in Purchase", columns, missing_pur)
    write_gst_subset(wb, "Old Bill Filed", columns, old_bills)
    write_gst_subset(wb, "Tax Differences", columns, tax_diffs)
    write_gst_subset(wb, "Duplicates & Review", columns, review)
    write_gst_subset(wb, "All Discrepancies", columns, all_discrepancies)
    write_sheet(wb.create_sheet("Validation"), ["Source", "Excel Row in Source Table", "GSTIN", "Invoice No.", "Validation Warning"], report["validation"])
    write_sheet(wb.create_sheet("Duplicate Keys"), ["GSTIN / GSTINs", "Normalized Invoice No.", "Source", "Count", "Review Note"], report["duplicates"])
    summary = wb.create_sheet("Summary", 0)
    summary_rows = [["GST 2B and Purchase Reconciliation", "Count / Value"], ["Records in Pur", report["pur_count"]], ["Records in 2B", report["portal_count"]], ["Amount tolerance (₹ per field)", report["tolerance"]]]
    for label in sorted(report["counts"]):
        summary_rows.append([label, report["counts"][label]])
    summary_rows.extend([["Old Bill Filed", len(old_bills)], ["All Discrepancies", len(all_discrepancies)],
                         ["Validation warnings", len(report["validation"])], ["Duplicate / mismatch review entries", len(report["duplicates"])],
                         ["Difference convention", "2B minus Pur; positive means 2B is higher"],
                         ["Matching rule", "Normalized GSTIN + invoice number; invoice-only overlap flags possible GSTIN mismatch; duplicates are not auto-matched"]])
    for row in summary_rows:
        summary.append(row)
    style_sheet(summary)
    sheet_links = {
        "Not on Portal": "Missing in 2B",
        "Not in Tally": "Missing in Purchase",
        "Old Bill Filed": "Old Bill Filed",
        "Not Matched": "Tax Differences",
        "Date Difference": "All Discrepancies",
        "GSTIN Mismatch - Review": "Duplicates & Review",
        "Duplicate / Review Required": "Duplicates & Review",
        "Validation warnings": "Validation",
        "Duplicate / mismatch review entries": "Duplicate Keys",
        "All Discrepancies": "All Discrepancies",
    }
    for r in range(2, summary.max_row + 1):
        label = str(summary.cell(r, 1).value or "")
        target = sheet_links.get(label)
        if not target and label in {"Taxable Value Difference", "Tax Amount Difference", "Invoice Value Difference", "Tax Differences"}:
            target = "Tax Differences"
        if target and target in wb.sheetnames:
            summary.cell(r, 1).hyperlink = f"#'{target}'!A1"
            summary.cell(r, 1).style = "Hyperlink"
    for row in summary.iter_rows(min_row=2, min_col=1, max_col=2):
        row[0].font = Font(bold=True)
    for sheet in wb.worksheets:
        sheet.freeze_panes = "A2"
    buffer = io.BytesIO(); wb.save(buffer); return buffer.getvalue()

def write_gst_subset(wb, title, columns, lines):
    ws = wb.create_sheet(title)
    write_sheet(ws, [c[0] for c in columns], [[line.get(c[1]) for c in columns] for line in lines])

def write_sheet(ws, headers, rows):
    ws.append(headers)
    for row in rows: ws.append(row)
    style_sheet(ws)

def style_sheet(ws):
    header_fill = PatternFill("solid", fgColor="1F4E78")
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = header_fill
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 32
    if ws.max_row > 1 and ws.max_column > 0:
        ws.auto_filter.ref = ws.dimensions
    for col in range(1, ws.max_column + 1):
        values = [len(str(ws.cell(row=r, column=col).value or "")) for r in range(1, min(ws.max_row, 200) + 1)]
        ws.column_dimensions[get_column_letter(col)].width = min(max(max(values or [10]) + 2, 12), 42)
    ws.sheet_view.showGridLines = False


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
    """Compare documents by a detected record key where possible, with exact-row fallback."""
    from collections import Counter, defaultdict

    rows_a = doc_a.get("rows", [])
    rows_b = doc_b.get("rows", [])

    def clean_row(row):
        return ["" if cell is None else str(cell).strip() for cell in row]

    def normalized_row(row):
        return tuple(normalize_cell(cell) for cell in row)

    header_a = clean_row(rows_a[0]) if rows_a else []
    header_b = clean_row(rows_b[0]) if rows_b else []
    same_header = bool(header_a and header_b and normalized_row(header_a) == normalized_row(header_b))
    headers = header_a if same_header else []
    data_a = [clean_row(r) for r in (rows_a[1:] if same_header else rows_a) if any(normalize_cell(c) for c in r)]
    data_b = [clean_row(r) for r in (rows_b[1:] if same_header else rows_b) if any(normalize_cell(c) for c in r)]

    # Prefer a business identifier such as Invoice No. rather than the first column.
    key_candidates = ("invoice no", "invoice number", "inv no", "bill no", "bill number",
                      "voucher no", "document no", "doc no", "reference no", "ref no", "gr no")
    key_index = None
    if headers:
        normalized_headers = [re.sub(r"[^a-z0-9]+", " ", h.casefold()).strip() for h in headers]
        for candidate in key_candidates:
            for i, header in enumerate(normalized_headers):
                if header == candidate or candidate in header:
                    key_index = i
                    break
            if key_index is not None:
                break
    if key_index is None and headers:
        # Use the first column only as a fallback, clearly identified in the report.
        key_index = 0
    key_label = headers[key_index] if key_index is not None and key_index < len(headers) else ("First column" if key_index == 0 else "Exact row")

    def record_key(row):
        if key_index is None or key_index >= len(row):
            return ""
        return normalize_cell(row[key_index])

    def index_rows(rows):
        index = defaultdict(list)
        for position, row in enumerate(rows):
            key = record_key(row)
            if key:
                index[key].append((position, row))
        return index

    index_a, index_b = index_rows(data_a), index_rows(data_b)
    counts_a, counts_b = Counter(normalized_row(r) for r in data_a), Counter(normalized_row(r) for r in data_b)
    exact_matched = sum((counts_a & counts_b).values())
    remarks = []
    paired_a, paired_b = set(), set()
    duplicate_keys = []

    def to_num(value):
        try:
            text = str(value).replace(",", "").replace("₹", "").replace("%", "").strip()
            return float(text) if text else None
        except (TypeError, ValueError):
            return None

    for key in sorted(index_a.keys() & index_b.keys()):
        a_items, b_items = index_a[key], index_b[key]
        if len(a_items) != 1 or len(b_items) != 1:
            duplicate_keys.append({"key": key, "count_a": len(a_items), "count_b": len(b_items)})
            continue
        pos_a, row_a = a_items[0]
        pos_b, row_b = b_items[0]
        paired_a.add(pos_a); paired_b.add(pos_b)
        if normalized_row(row_a) == normalized_row(row_b):
            continue
        fields = []
        for i in range(max(len(row_a), len(row_b))):
            av = row_a[i] if i < len(row_a) else ""
            bv = row_b[i] if i < len(row_b) else ""
            if normalize_cell(av) == normalize_cell(bv):
                continue
            col_name = headers[i] if i < len(headers) and headers[i].strip() else f"Column {i + 1}"
            remark = f"{col_name}: '{av or '(blank)'}' → '{bv or '(blank)'}'"
            na, nb = to_num(av), to_num(bv)
            if na is not None and nb is not None:
                delta = nb - na
                remark += f" (B − A: {delta:+,.2f})"
            fields.append(remark)
        remarks.append({"key": row_a[key_index] if key_index < len(row_a) else key,
                        "row_a": row_a, "row_b": row_b, "remark": "; ".join(fields)})

    only_a, only_b = [], []
    if key_index is not None:
        for i, row in enumerate(data_a):
            key = record_key(row)
            if not key or key not in index_b or (key in index_b and (len(index_a[key]) != 1 or len(index_b[key]) != 1)):
                only_a.append(row)
        for i, row in enumerate(data_b):
            key = record_key(row)
            if not key or key not in index_a or (key in index_a and (len(index_a[key]) != 1 or len(index_b[key]) != 1)):
                only_b.append(row)
        # Rows with shared unique keys are paired records, even when some fields differ.
    else:
        counter_a, counter_b = Counter(normalized_row(r) for r in data_a), Counter(normalized_row(r) for r in data_b)
        display_a, display_b = {}, {}
        for row in data_a: display_a.setdefault(normalized_row(row), row)
        for row in data_b: display_b.setdefault(normalized_row(row), row)
        for key, count in (counter_a - counter_b).items(): only_a.extend([display_a[key]] * count)
        for key, count in (counter_b - counter_a).items(): only_b.extend([display_b[key]] * count)

    # Simple arithmetic validation is separate from comparison and never changes match status.
    validation_issues = []
    if headers:
        norm_headers = [re.sub(r"[^a-z0-9]+", " ", h.casefold()).strip() for h in headers]
        def col_index(*names):
            for i, h in enumerate(norm_headers):
                if any(name in h for name in names): return i
            return None
        qty_i = col_index("quantity", "qty")
        rate_i = col_index("rate", "unit price", "unit rate")
        taxable_i = col_index("taxable amount", "taxable value", "taxable")
        gst_rate_i = col_index("gst rate", "tax rate")
        gst_amount_i = col_index("gst amount", "tax amount")
        invoice_i = col_index("invoice amount", "total amount", "gross amount", "inv value")
        def add_issue(source, row, row_num, message):
            validation_issues.append({"source": source, "key": row[key_index] if key_index is not None and key_index < len(row) else (row[0] if row else f"Row {row_num}"), "row_number": row_num, "message": message})
        for source, rows in ((name_a, data_a), (name_b, data_b)):
            for row_num, row in enumerate(rows, start=2 if same_header else 1):
                def val(idx): return to_num(row[idx]) if idx is not None and idx < len(row) else None
                qty, rate, taxable = val(qty_i), val(rate_i), val(taxable_i)
                gst_rate, gst_amount, invoice_amount = val(gst_rate_i), val(gst_amount_i), val(invoice_i)
                if qty is not None and rate is not None and taxable is not None and abs(qty * rate - taxable) > 0.02:
                    add_issue(source, row, row_num, f"Quantity × Rate = {qty * rate:,.2f}, but Taxable Amount = {taxable:,.2f}.")
                if taxable is not None and gst_rate is not None and gst_amount is not None and abs(taxable * gst_rate / 100 - gst_amount) > 0.02:
                    add_issue(source, row, row_num, f"Expected GST = {taxable * gst_rate / 100:,.2f}, but GST Amount = {gst_amount:,.2f}.")
                if taxable is not None and gst_amount is not None and invoice_amount is not None and abs(taxable + gst_amount - invoice_amount) > 0.02:
                    add_issue(source, row, row_num, f"Taxable Amount + GST Amount = {taxable + gst_amount:,.2f}, but Invoice Amount = {invoice_amount:,.2f}.")

    return {
        "name_a": name_a, "name_b": name_b,
        "type_a": doc_a.get("kind", "Document"), "type_b": doc_b.get("kind", "Document"),
        "rows_a": len(data_a), "rows_b": len(data_b),
        "matched": exact_matched,
        "matched_records": sum(1 for key in index_a.keys() & index_b.keys() if len(index_a[key]) == 1 and len(index_b[key]) == 1),
        "key_column": key_label,
        "remarks": remarks[:500],
        "only_a": only_a[:500], "only_b": only_b[:500],
        "unmatched_a": only_a[:500], "unmatched_b": only_b[:500],
        "duplicate_keys": duplicate_keys[:500], "validation_issues": validation_issues[:500],
        "validation_truncated": len(validation_issues) > 500,
        "truncated": len(only_a) > 500 or len(only_b) > 500 or len(remarks) > 500,
        "notes": doc_a.get("notes", []) + doc_b.get("notes", []),
    }
@app.route("/export.csv", methods=["POST"])
@login_required
def export_csv():
    # Export only the report submitted from the authenticated results page; no report is stored.
    import json
    raw = request.form.get("report_json", "")
    if len(raw) > 2_000_000:
        abort(413)
    try:
        result = json.loads(raw)
    except Exception:
        abort(400)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Section", "Record Key", "File A", "File B", "Details"])
    for item in result.get("remarks", []):
        writer.writerow(["Changed record", item.get("key", ""), " | ".join(map(str, item.get("row_a", []))),
                         " | ".join(map(str, item.get("row_b", []))), item.get("remark", "")])
    for row in result.get("only_a", []):
        writer.writerow(["Only in A", "", " | ".join(map(str, row)), "", ""])
    for row in result.get("only_b", []):
        writer.writerow(["Only in B", "", "", " | ".join(map(str, row)), ""])
    for issue in result.get("validation_issues", []):
        writer.writerow(["Calculation warning", issue.get("key", ""), issue.get("source", ""),
                         f"Row {issue.get('row_number', '')}", issue.get("message", "")])
    for item in result.get("duplicate_keys", []):
        writer.writerow(["Ambiguous duplicate key", item.get("key", ""), f"Count: {item.get('count_a', 0)}",
                         f"Count: {item.get('count_b', 0)}", "Manual review required"])
    response = send_file(io.BytesIO(output.getvalue().encode("utf-8-sig")), mimetype="text/csv",
                         as_attachment=True, download_name="reconciliation_report.csv")
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
