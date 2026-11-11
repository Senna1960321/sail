#!/usr/bin/env python3
"""Install repository hooks without changing core.hooksPath or replacing hooks."""

import argparse
import os
from pathlib import Path
import subprocess
import sys


def git(*args, allowed=(0,)):
    result = subprocess.run(["git", *args], capture_output=True, check=False)
    if result.returncode not in allowed:
        raise RuntimeError("cannot inspect Git hook configuration")
    return os.fsdecode(result.stdout).rstrip("\n")


def install(dispatcher):
    root = Path(git("rev-parse", "--show-toplevel"))
    common = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))
    hooks = common / "hooks"
    configured = git("config", "--get", "core.hooksPath", allowed=(0, 1))
    if configured and not dispatcher:
        raise RuntimeError("core.hooksPath is configured; use --via-dispatcher only if it delegates repository hooks")
    copies = []
    for name in ("pre-commit", "commit-msg"):
        source = root / "tools/hooks" / name
        target = hooks / name
        data = source.read_bytes()
        if target.is_symlink() or (target.exists() and target.read_bytes() != data):
            raise RuntimeError("existing repository hook would be replaced; integrate the template manually")
        copies.append((target, data))
    hooks.mkdir(parents=True, exist_ok=True)
    for target, data in copies:
        if not target.exists():
            with target.open("xb") as output:
                output.write(data)
        target.chmod(0o755)
    print("Installed repository commit hooks; core.hooksPath unchanged.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--via-dispatcher", action="store_true",
                        help="the configured hooksPath already delegates to the common Git directory's hooks")
    args = parser.parse_args()
    try:
        install(args.via_dispatcher)
    except (OSError, RuntimeError) as error:
        # OS errors may include private paths.
        print(str(error) if isinstance(error, RuntimeError) else "Cannot install commit hooks.", file=sys.stderr)
        sys.exit(1)
