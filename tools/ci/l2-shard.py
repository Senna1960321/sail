#!/usr/bin/env python3
"""Runs one shard of sail's integration test binaries (layer L2, see
docs/testing.md).

    python3 tools/ci/l2-shard.py INDEX COUNT

Builds every test binary under sail/tests (`cargo test -p sail --features
auto-reload,inbound-sail,outbound-sail --test '*' --no-run`), lists each
one's tests, and runs those whose `<binary>::<test>` name hashes
(CRC-32) to INDEX modulo COUNT, by exact name. The split depends on the names alone: the same tree gives the
same shards on every run and every machine, and a new test lands in one
shard without moving the others. `0 1` runs all of them.

Each binary's share runs through `cargo test --test <binary> -- --exact
<names>`, so that its tests get cargo's own environment and working
directory; the build is done by then. Ignored tests (L3) stay ignored. A
binary with no test in the shard is not started (with no name, it would
run all of them). Any failing binary fails the shard, after every binary
has run.
"""

import json
import os
import subprocess
import sys
import zlib

# What sail-ffi turns on, as the tests have always run with it; and Sail/1
# (sail#60), experimental and off by default, for its tests to run.
CARGO_TEST = [
    "cargo",
    "test",
    "--locked",
    "-p",
    "sail",
    "--features",
    "auto-reload,inbound-sail,outbound-sail",
]
BUILD = CARGO_TEST + ["--test", "*", "--no-run", "--message-format=json-render-diagnostics"]


def binaries():
    out = subprocess.run(BUILD, stdout=subprocess.PIPE, check=True, text=True).stdout
    found = []
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-artifact" or not msg.get("executable"):
            continue
        if not msg["profile"]["test"]:
            continue
        found.append(
            (
                msg["target"]["name"],
                msg["executable"],
                os.path.dirname(msg["manifest_path"]),
            )
        )
    return sorted(found)


def tests(exe, cwd, env):
    out = subprocess.run(
        [exe, "--list", "--format", "terse"],
        stdout=subprocess.PIPE,
        check=True,
        text=True,
        cwd=cwd,
        env=env,
    ).stdout
    return [line[: -len(": test")] for line in out.splitlines() if line.endswith(": test")]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    index, count = int(sys.argv[1]), int(sys.argv[2])
    if not 0 <= index < count:
        sys.exit("INDEX must be in 0..COUNT")
    failed = []
    for name, exe, cwd in binaries():
        env = dict(os.environ, CARGO_MANIFEST_DIR=cwd)
        listed = tests(exe, cwd, env)
        mine = [t for t in listed if zlib.crc32(f"{name}::{t}".encode()) % count == index]
        print(f"::group::{name}: {len(mine)} of {len(listed)} tests", flush=True)
        if mine:
            run = CARGO_TEST + ["--test", name, "--", "--exact", *mine]
            if subprocess.run(run).returncode != 0:
                failed.append(name)
        print("::endgroup::", flush=True)
    if failed:
        print(f"::error::shard {index} of {count}: failed in {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
