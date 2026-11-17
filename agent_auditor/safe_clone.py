"""Clone a git repository for inspection without running anything from it."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

ALLOWED = re.compile(r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[\w.\-]+/[\w.\-]+?(\.git)?/?$")


def safe_clone(url: str, dest: str | None = None) -> Path:
    """Shallow-clone `url` into a temp folder.

    * only https URLs on well-known hosts are accepted;
    * git hooks are disabled and submodules are not fetched;
    * nothing from the repo is installed or executed.
    """
    if not ALLOWED.match(url):
        raise ValueError("Only https://github.com, gitlab.com or bitbucket.org repo URLs are allowed.")
    target = Path(dest or tempfile.mkdtemp(prefix="agent-audit-")) / "repo"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
           "clone", "--depth", "1", "--no-recurse-submodules", "--quiet", url, str(target)]
    subprocess.run(cmd, check=True, env=env, timeout=120)
    return target
