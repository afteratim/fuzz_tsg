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
