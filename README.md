# Private Document Analyzer

A single-user, password-protected document comparison web app. It uses deterministic row comparison and local server-side parsers; it does **not** call an external AI API.

## Supported formats in this starter build

- Digital PDFs and scanned PDFs (Tesseract OCR fallback for pages without embedded text)
- XLSX, XLSM, XLTX, XLTM
- CSV and TSV
- DOCX
- TXT and RTF
- PNG, JPG/JPEG, TIFF, BMP and WEBP

Legacy XLS is intentionally not supported by this build. Save it as XLSX or CSV first. Password-protected PDFs and encrypted Office files are not supported. OCR/table extraction is imperfect and must be checked against source documents.

## Security behavior

- Login required for the UI and analysis endpoints.
- Password and session secret come from environment variables, not source code.
- HTTPS is expected in production; Render provides HTTPS for its hosted service.
- Uploads are limited to 25 MiB each and exactly two files per comparison.
- Temporary upload directory is created per request and removed automatically on normal exit and Python exceptions.
- No application database, persistent disk, report database, external AI, analytics or third-party frontend CDN.
- Responses use no-store cache headers and restrictive security headers.
- Application code avoids logging document contents or exception messages.
- CSV export is generated from the report posted by the authenticated browser; it is not saved as a server file.

## Important security limitations

This is a privacy-conscious starter, not a certified secure document-processing system. Server-side processing means files leave the phone and are handled by the hosting environment. Render/platform-level infrastructure, memory, backups, network telemetry, or provider operations are outside the application's direct control. Do not upload documents unless your organization permits cloud processing.

The login is a single shared account, not MFA. Use a long unique password. Do not expose the service publicly before configuring credentials and testing. For production handling of sensitive records, add MFA, stronger login throttling, security review, dependency scanning, and an explicit data-retention review.

The 25 MB limit is enforced by application code. Render's request limits and available memory vary by plan. OCR can be memory-intensive; the app processes PDF pages one at a time, but test with non-sensitive files before relying on it.

## Deploy to Render

1. Create a **private** GitHub repository and upload all project files.
2. In Render, choose **New + → Blueprint** and connect that repository, or create a Python Web Service manually.
3. The `render.yaml` configures the build/start commands and environment variables. The blueprint asks you to set `APP_PASSWORD` securely.
4. In Render environment settings, set:
   - `APP_USERNAME`: a username you choose (default `admin` in the blueprint)
   - `APP_PASSWORD`: a long, unique password
   - `SECRET_KEY`: use Render's generated value; if setting manually, use a random value of at least 32 bytes
5. Deploy and wait for `/health` to return `{"status":"ok"}`.
6. Open the service URL. Confirm it redirects to login. Test with dummy files first.
7. Confirm logout works, unsupported formats are rejected, oversized files are rejected, and the app remains functional after a failed upload.
8. Check Render logs to ensure they do not contain document content. Do not enable debug mode.

### Manual service configuration

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --workers 1 --threads 2 --timeout 180 --max-requests 100 --max-requests-jitter 10`
- Health check path: `/health`

## Local test (on your own PC)

Use Python 3.12 if available. Install Tesseract OCR as well for image/scanned-PDF OCR.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:APP_USERNAME = "admin"
$env:APP_PASSWORD = "replace-with-a-long-unique-password"
$env:SECRET_KEY = "replace-with-a-random-secret"
$env:COOKIE_SECURE = "false"
python app.py
```

Open `http://127.0.0.1:5000`. Local HTTP is only for local testing. Use HTTPS in production.

## How comparison works

The starter version compares normalized rows exactly (case-insensitive, whitespace-normalized) and preserves duplicate counts. It reports rows appearing only in A or only in B. It does not yet perform semantic invoice matching, fuzzy party-name matching, amount-tolerance matching, or automatic column-aware ledger reconciliation. Those should be added as separately tested rules.

## Before real confidential data

- Test using synthetic documents.
- Use a strong unique password.
- Keep GitHub repository private.
- Do not add uploaded documents, reports, `.env` files, or credentials to Git.
- Restrict who can access Render and GitHub accounts; enable MFA on both.
- Review Render's current plan, security, log retention, and service access settings.
- Confirm that cloud processing is allowed for the documents involved.
