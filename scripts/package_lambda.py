#!/usr/bin/env python3
"""Build and package bill_shock_guard into build/lambda for Terraform deployment."""

import pathlib
import shutil
import sys


def package() -> None:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src" / "bill_shock_guard"
    build_dir = repo_root / "build" / "lambda"
    target_dir = build_dir / "bill_shock_guard"

    if not src_dir.is_dir():
        print(f"Error: Source directory not found at {src_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Packaging {src_dir} -> {target_dir}...")
    shutil.rmtree(build_dir, ignore_errors=True)
    build_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_dir, target_dir, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    print("Package built successfully.")


if __name__ == "__main__":
    package()
