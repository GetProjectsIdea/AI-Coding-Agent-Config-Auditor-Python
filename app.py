"""Optional Flask web UI. Upload a .zip of a repo (or scan a bundled example)
and see the audit report in the browser. Nothing from the upload is executed."""
from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from flask import Flask, render_template, request

from agent_auditor import scan_path
from agent_auditor.demo import build_risky_repo
from agent_auditor.report import CHECKLIST, to_json

BASE = Path(__file__).resolve().parent
EXAMPLES = {"risky-repo": None, "safe-repo": BASE / "examples" / "safe-repo"}
MAX_UPLOAD = 20 * 1024 * 1024        # 20 MB zip
MAX_UNPACKED = 100 * 1024 * 1024     # 100 MB after extraction (zip-bomb guard)
MAX_MEMBERS = 5000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD


def safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a zip while blocking path traversal, symlinks and zip bombs."""
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        members = zf.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("Zip has too many files.")
        for m in members:
            name = m.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError(f"Unsafe path in zip: {m.filename}")
            if (m.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks
            total += m.file_size
            if total > MAX_UNPACKED:
                raise ValueError("Zip expands to more than 100 MB.")
            zf.extract(m, dest)


@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    if request.method == "POST":
        example = request.form.get("example")
        upload = request.files.get("repo_zip")
        tmp = None
        try:
            if example in EXAMPLES:
                folder = EXAMPLES[example]
                if folder is None:            # generated on demand, harmless placeholders
                    tmp = Path(tempfile.mkdtemp(prefix="agent-audit-web-"))
                    folder = build_risky_repo(tmp)
                result = scan_path(folder)
                result.root = "demo:risky-repo" if example == "risky-repo" else f"examples/{example}"
            elif upload and upload.filename:
                if not upload.filename.lower().endswith(".zip"):
                    raise ValueError("Please upload a .zip file of the repository.")
                tmp = Path(tempfile.mkdtemp(prefix="agent-audit-web-"))
                zpath = tmp / "upload.zip"
                upload.save(zpath)
                safe_extract(zpath, tmp / "repo")
                result = scan_path(tmp / "repo")
                result.root = upload.filename
            else:
                raise ValueError("Choose a .zip file or one of the example repos.")
            return render_template("report.html", r=result, checklist=CHECKLIST,
                                   raw_json=to_json(result))
        except (ValueError, zipfile.BadZipFile) as exc:
            error = str(exc)
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
    return render_template("index.html", error=error, checklist=CHECKLIST)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
