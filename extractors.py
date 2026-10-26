import csv
import io
import re
from pathlib import Path

SUPPORTED_EXTENSIONS = {
    "pdf", "xlsx", "xlsm", "xltx", "xltm", "xls", "csv", "tsv",
    "txt", "docx", "rtf", "png", "jpg", "jpeg", "tif", "tiff", "bmp", "webp"
}

def _rows_from_text(text):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # PDFs often represent columns with runs of spaces or tabs.
        parts = re.split(r"\t+|\s{2,}", line)
        rows.append(parts if len(parts) > 1 else [line])
    return rows


def _extract_pdf(path):
    import fitz
    rows, notes = [], []
    with fitz.open(path) as pdf:
        if pdf.needs_pass:
            raise ValueError("Password-protected PDFs are not supported.")
        for page_num, page in enumerate(pdf, start=1):
            text = page.get_text("text") or ""
            if text.strip():
                rows.extend(_rows_from_text(text))
            else:
                # OCR only one page at a time to reduce peak RAM.
                try:
                    import pytesseract
                    from PIL import Image
                    pix = page.get_pixmap(matrix=fitz.Matrix(1.35, 1.35), alpha=False)
                    image = Image.open(io.BytesIO(pix.tobytes("png")))
                    ocr_text = pytesseract.image_to_string(image, config="--psm 6")
                    rows.extend(_rows_from_text(ocr_text))
                    notes.append(f"Page {page_num}: OCR was used; verify extracted values manually.")
                    image.close()
                    del pix
                except Exception:
                    notes.append(f"Page {page_num}: no readable text found or OCR unavailable.")
    return {"kind": "PDF", "rows": rows, "notes": notes}


def _extract_spreadsheet(path, suffix):
    rows = []
    notes = []
    if suffix == ".csv" or suffix == ".tsv":
        delimiter = "\t" if suffix == ".tsv" else ","
        # utf-8-sig handles common Excel CSV exports; fall back to cp1252.
        try:
            content = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            content = path.read_text(encoding="cp1252")
        reader = csv.reader(io.StringIO(content), delimiter=delimiter)
        rows = [list(row) for row in reader]
    else:
        try:
            import openpyxl
            wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    vals = ["" if v is None else str(v) for v in row]
                    if any(v.strip() for v in vals):
                        rows.append([f"[Sheet: {ws.title}]"] + vals)
            wb.close()
        except Exception:
            # Legacy .xls is not supported by openpyxl; provide a clear error.
            if suffix == ".xls":
                raise ValueError("Legacy .xls files are not supported in this build. Save as .xlsx or .csv and retry.")
            raise
    return {"kind": "Spreadsheet", "rows": rows, "notes": notes}


def _extract_docx(path):
    from docx import Document
    doc = Document(path)
    rows = []
    for p in doc.paragraphs:
        if p.text.strip():
            rows.append([p.text.strip()])
    for table_index, table in enumerate(doc.tables, start=1):
        for row in table.rows:
            rows.append([f"[Table {table_index}]"] + [cell.text.strip() for cell in row.cells])
    return {"kind": "DOCX", "rows": rows, "notes": []}


def _extract_rtf(path):
    try:
        from striprtf.striprtf import rtf_to_text
        text = path.read_text(encoding="utf-8", errors="replace")
        return {"kind": "RTF", "rows": _rows_from_text(rtf_to_text(text)), "notes": []}
    except Exception:
        raise ValueError("Could not read this RTF file. Try saving it as TXT or DOCX.")


def _extract_text(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    return {"kind": "Text", "rows": _rows_from_text(text), "notes": []}


def _extract_image(path):
    try:
        from PIL import Image, ImageOps
        import pytesseract
        with Image.open(path) as img:
            img = ImageOps.exif_transpose(img)
            img.thumbnail((2200, 2200))
            text = pytesseract.image_to_string(img, config="--psm 6")
        return {"kind": "Image/OCR", "rows": _rows_from_text(text), "notes": ["OCR was used; verify amounts and identifiers against the original image."]}
    except Exception:
        raise ValueError("Image OCR failed. Check the file or try a smaller image.")


def extract_document(path, original_name):
    suffix = Path(original_name).suffix.lower()
    if suffix == ".pdf":
        return _extract_pdf(path)
    if suffix in {".xlsx", ".xlsm", ".xltx", ".xltm", ".csv", ".tsv"}:
        return _extract_spreadsheet(path, suffix)
    if suffix == ".docx":
        return _extract_docx(path)
    if suffix == ".rtf":
        return _extract_rtf(path)
    if suffix == ".txt":
        return _extract_text(path)
    if suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}:
        return _extract_image(path)
    raise ValueError(f"Unsupported file type: {suffix or 'unknown'}")
