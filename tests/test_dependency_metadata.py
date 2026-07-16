"""Dependency metadata regression tests."""

from __future__ import annotations

import runpy
from pathlib import Path
from unittest.mock import patch

from packaging.requirements import Requirement


ROOT = Path(__file__).resolve().parents[1]


def _runtime_requirements() -> list[str]:
    """读取唯一运行时依赖清单，并忽略空行和注释。"""

    return [
        line
        for raw_line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    ]


def _setup_metadata() -> dict[str, object]:
    """拦截 setuptools.setup 调用，以只读方式取得包元数据。"""

    captured: dict[str, object] = {}

    def capture_setup(**kwargs: object) -> None:
        # setup.py 的参数在此被捕获，不执行构建或安装副作用。
        captured.update(kwargs)

    with patch("setuptools.setup", side_effect=capture_setup):
        runpy.run_path(str(ROOT / "setup.py"), run_name="__main__")
    return captured


def test_setup_uses_the_runtime_dependency_source() -> None:
    """验证 setup.py 与 requirements.txt 暴露完全相同的运行时依赖。"""

    metadata = _setup_metadata()

    assert metadata["install_requires"] == _runtime_requirements()
    assert metadata["python_requires"] == ">=3.11"


def test_runtime_dependencies_are_direct_and_versioned() -> None:
    """验证直接依赖完整且不再使用会漂移的 VCS 地址。"""

    requirements = [Requirement(item) for item in _runtime_requirements()]
    by_name = {requirement.name.lower(): requirement for requirement in requirements}

    assert set(by_name) == {
        "cryptography",
        "flask",
        "flask-bcrypt",
        "flask-jwt-extended",
        "flask-pymongo",
        "openai",
        "pymongo",
        "pyyaml",
        "requests",
        "simple-parsing",
        "smolagents",
    }
    assert all(requirement.url is None for requirement in requirements)

    smolagents = by_name["smolagents"]
    assert smolagents.specifier.contains("1.19.0")
    assert not smolagents.specifier.contains("1.18.0")
    assert not smolagents.specifier.contains("2.0.0")


def test_source_distribution_includes_dependency_source() -> None:
    """验证源码包会携带 setup.py 构建时需要的依赖清单。"""

    manifest_lines = {
        line.strip()
        for line in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    assert "include requirements.txt" in manifest_lines
