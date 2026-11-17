import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture
def examples():
    return ROOT / "examples"


@pytest.fixture
def make_repo(tmp_path):
    """Create a throw-away repo from a {relative_path: content} dict."""
    def _make(files: dict) -> Path:
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return tmp_path
    return _make


@pytest.fixture
def risky_repo(tmp_path_factory):
    from agent_auditor.demo import build_risky_repo
    return build_risky_repo(tmp_path_factory.mktemp("demo"))
