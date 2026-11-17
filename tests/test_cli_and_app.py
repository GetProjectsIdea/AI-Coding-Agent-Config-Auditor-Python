import io
import json
import zipfile

import pytest

from agent_auditor.cli import main
from agent_auditor.report import to_markdown
from agent_auditor import scan_path
from agent_auditor.safe_clone import safe_clone


def test_cli_json_and_exit_codes(examples, risky_repo, capsys):
    assert main([str(risky_repo), "-f", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "DANGEROUS"
    assert main([str(examples / "safe-repo"), "--no-color"]) == 0


def test_cli_writes_markdown(risky_repo, tmp_path):
    out = tmp_path / "report.md"
    main([str(risky_repo), "-f", "markdown", "-o", str(out)])
    assert "Safe-cloning checklist" in out.read_text()


def test_cli_bad_path_returns_2(tmp_path):
    assert main([str(tmp_path / "nope")]) == 2


def test_safe_clone_rejects_untrusted_urls():
    for url in ["file:///etc", "git@github.com:a/b.git", "https://evil.example/a/b", "ext::sh -c id"]:
        with pytest.raises(ValueError):
            safe_clone(url)


def test_markdown_report(risky_repo):
    md = to_markdown(scan_path(risky_repo))
    assert "| Critical |" in md


@pytest.fixture
def client():
    from app import app
    app.config["TESTING"] = True
    return app.test_client()


def test_web_index(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Safe-cloning checklist" in r.data


def test_web_example_scan(client):
    r = client.post("/", data={"example": "risky-repo"})
    assert r.status_code == 200 and b"DANGEROUS" in r.data


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    buf.seek(0)
    return buf


def test_web_zip_upload(client):
    data = {"repo_zip": (_zip({"AGENTS.md": "Run tests with pytest."}), "repo.zip")}
    r = client.post("/", data=data, content_type="multipart/form-data")
    assert r.status_code == 200 and b"LOOKS SAFE" in r.data


def test_web_blocks_zip_slip(client):
    data = {"repo_zip": (_zip({"../evil.md": "x"}), "bad.zip")}
    r = client.post("/", data=data, content_type="multipart/form-data")
    assert b"Unsafe path" in r.data


def test_cli_demo_flag(capsys):
    assert main(["--demo", "-f", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["root"] == "demo:risky-repo"


def test_project_itself_has_no_live_risky_agent_files():
    """The repo must never ship real risky agent files that an AI agent could auto-load."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    r = scan_path(root)
    assert r.verdict == "LOOKS SAFE", [f.to_dict() for f in r.findings if f.severity > 1]
