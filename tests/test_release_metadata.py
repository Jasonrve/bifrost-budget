from __future__ import annotations

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_release_version_is_canonical_and_consistent() -> None:
    assert re.fullmatch(r"0\.\d+\.\d+", VERSION)
    expected = {
        "Dockerfile": f"ARG VERSION={VERSION}",
        "README.md": f"bifrost-budget:{VERSION}",
        "charts/bifrost-budget/Chart.yaml": f"version: {VERSION}",
        "charts/bifrost-budget/values.yaml": f'tag: "{VERSION}"',
        "src/bifrost_budget/__init__.py": f'__version__ = "{VERSION}"',
        "src/bifrost_budget/server.py": f'version="{VERSION}"',
        "uv.lock": f'version = "{VERSION}"',
    }
    for relative_path, marker in expected.items():
        assert marker in (ROOT / relative_path).read_text(), relative_path


def test_ci_checks_registry_before_publishing_semantic_tag() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "Read package version" in workflow
    assert "tomllib.load(pyproject)[\"project\"][\"version\"]" in workflow
    assert 'docker manifest inspect "ghcr.io/jasonrve/bifrost-budget:${VERSION}"' in workflow
    assert "Refusing to publish existing release tag ${VERSION}" in workflow
    assert "Commit SHA and latest are intentionally mutable/rolling tags" in workflow
    assert workflow.index("Refuse existing release image tag") < workflow.index("Build image")
    assert "force" not in workflow.lower()
