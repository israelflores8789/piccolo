# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_dependency_metadata.py — Runtime and build dependency pins."""

import tomllib
from pathlib import Path


def test_runtime_and_build_metadata_pin_dependency_versions() -> None:
    metadata = tomllib.loads(Path("pyproject.toml").read_text())
    requirements = [
        *metadata["project"]["dependencies"],
        *metadata["project"]["optional-dependencies"]["gcp"],
        *metadata["dependency-groups"]["dev"],
        *metadata["build-system"]["requires"],
    ]
    assert all("==" in requirement for requirement in requirements)
    assert "pytest==9.1.1" in requirements
