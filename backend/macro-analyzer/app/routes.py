"""
Macro Analyzer routes.

POST /api/macro-analyzer/analyze
    Accepts: multipart/form-data with a `file` field
    Returns: JSON analysis result from olevba
"""

import logging
import os
import tempfile

from flask import Blueprint, jsonify, request

from app.analyzer import analyze_file
from app import vt as vt_module

log = logging.getLogger("macro-analyzer.routes")
bp = Blueprint("macro", __name__)


@bp.get("/health")
def health():
    return jsonify({"status": "healthy"})


@bp.post("/analyze")
def analyze():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No 'file' field in request"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"success": False, "error": "Empty filename"}), 400

    # Preserve original extension so oletools can detect file type correctly.
    # zip-based formats (.docx, .xlsx, .pptx) need the right extension.
    suffix = os.path.splitext(f.filename)[-1].lower() or ".bin"
    allowed = {".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".xlsb",
               ".ppt", ".pptx", ".pptm", ".rtf", ".docm"}
    if suffix not in allowed:
        return jsonify({
            "success": False,
            "error": f"Unsupported extension '{suffix}'. Supported: {sorted(allowed)}",
        }), 400

    vt_api_key: str = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            f.save(tmp.name)
            tmp_path = tmp.name

        result = analyze_file(tmp_path, original_name=f.filename)

        # ── VirusTotal enrichment (optional — skipped if no API key) ──────────
        if vt_api_key:
            try:
                result["vt"] = vt_module.scan_file(tmp_path, vt_api_key)
            except Exception as vt_exc:
                log.warning(f"VT scan failed: {vt_exc}")
                result["vt"] = {"success": False, "error": str(vt_exc)}

        return jsonify({"success": True, **result})

    except Exception as exc:
        log.exception(f"analyze_file raised: {exc}")
        return jsonify({"success": False, "error": str(exc)}), 500

    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
