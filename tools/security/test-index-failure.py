#!/usr/bin/env python3
"""Prove cargo-deny's native index-failure override without altering shared data."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

root = Path(__file__).resolve().parents[2]
lock = tomllib.loads((root / "Cargo.lock").read_text())
package = next(p for p in lock["package"] if p["name"] == "itoa")
cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
deny = shutil.which("cargo-deny")
assert deny, "install the pinned cargo-deny first"
version = subprocess.check_output([deny, "--version"], text=True).strip()
assert version == "cargo-deny 0.20.2", version
archive = next(
    p for p in (cargo_home / "registry/cache").glob(f"*/itoa-{package['version']}.crate")
    if hashlib.sha256(p.read_bytes()).hexdigest() == package["checksum"]
)


def diagnostics(text):
    def walk(value):
        if isinstance(value, dict):
            if value.get("code") == "index-failure":
                yield value
            for child in value.values():
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)

    for line in text.splitlines():
        try:
            yield from walk(json.loads(line))
        except json.JSONDecodeError:
            pass


with tempfile.TemporaryDirectory(prefix="sail-security-index-") as temporary:
    fixture = Path(temporary)
    vendor = fixture / "vendor"
    vendor.mkdir()
    # A real, checksum-verified crate permits Cargo metadata to resolve offline.
    # Only this negative fixture gets an empty Cargo home: it deliberately has
    # no registry index, while the product's shared cache remains untouched.
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            assert parts[0] == f"itoa-{package['version']}"
            assert ".." not in parts and not Path(member.name).is_absolute()
            destination = vendor.joinpath(*parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                assert member.isfile(), "unexpected crate archive entry"
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(tar.extractfile(member).read())
    crate = vendor / f"itoa-{package['version']}"
    checksums = {
        p.relative_to(crate).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in crate.rglob("*") if p.is_file()
    }
    (crate / ".cargo-checksum.json").write_text(json.dumps({
        "package": package["checksum"], "files": checksums,
    }))
    (fixture / "src").mkdir()
    (fixture / "src/lib.rs").write_text("// Metadata-only fixture; never compiled.\n")
    (fixture / "Cargo.toml").write_text(
        '[package]\nname="index-fixture"\nversion="0.0.0"\nedition="2021"\n'
        f'[dependencies]\nitoa="={package["version"]}"\n'
    )
    (fixture / ".cargo").mkdir()
    (fixture / ".cargo/config.toml").write_text(
        '[source.crates-io]\nreplace-with="vendored"\n'
        f'[source.vendored]\ndirectory={json.dumps(str(vendor))}\n'
    )
    # Reuse only the already prepared official advisory DB, read-only/offline.
    # No alternate advisory source or ignored diagnostic is introduced.
    policy = (root / "tools/security/deny.toml").read_text().replace(
        "[advisories]\n",
        "[advisories]\ndb-path=" + json.dumps(str(cargo_home / "advisory-dbs")) + "\n",
    )
    (fixture / "deny.toml").write_text(policy)
    env = dict(os.environ, CARGO_HOME=str(fixture / "empty-cargo-home"))
    subprocess.run(["cargo", "generate-lockfile", "--offline"],
                   cwd=fixture, env=env, check=True)
    command = [deny, "--offline", "--locked", "--format", "json",
               "--manifest-path", str(fixture / "Cargo.toml"),
               "--config", str(fixture / "deny.toml"), "check"]
    for phase, override, expected, severity in [
        ("default", [], 0, "warning"),
        ("strict", ["--deny", "index-failure"], 1, "error"),
    ]:
        result = subprocess.run(command + override + ["advisories"], cwd=fixture,
                                env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        print(f"NATIVE_INDEX_PHASE={phase} EXIT={result.returncode}", flush=True)
        print(result.stdout, end="", flush=True)
        found = list(diagnostics(result.stdout))
        assert result.returncode == expected, (phase, result.returncode)
        assert found, (phase, "the actual index-failure code was not observed")
        assert all(d.get("severity") == severity for d in found), (phase, found)

print("native index-failure regression: PASS (warning exit 0; denied error exit 1)")
