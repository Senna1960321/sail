#!/usr/bin/env python3
"""Inspect Git snapshots with the existing grep -E policy, failing closed."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

GENERIC = (r"/Users/[A-Za-z0-9._-]+/|/home/[a-z][a-z0-9_-]*/|"
           r"(^|[^A-Za-z0-9_.*])/root/[A-Za-z0-9._-]|"
           r"/private/(tmp|var)/|claude-[0-9]+/")
BAD_PATHS = r"(^|/)(evidence|validation)/|\.log$"


class CheckError(Exception):
    pass


def run(command, data=None, allowed=(0,), env=None):
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, env=env)
    if result.returncode not in allowed:
        # Arguments and stderr can contain the rejected material too.
        raise CheckError("cannot inspect repository or evaluate patterns")
    return result.stdout


def git(*args, allowed=(0,)):
    env = os.environ.copy()
    env["GIT_LITERAL_PATHSPECS"] = "1"
    return run(["git", *args], allowed=allowed, env=env)


def nul(data):
    if data and not data.endswith(b"\0"):
        raise CheckError("incomplete Git path list")
    return data[:-1].split(b"\0") if data else []


def lf_lines(data):
    lines = data.split(b"\n")
    return lines[:-1] if lines[-1] == b"" else lines


class Guard:
    def __init__(self):
        self.patterns = GENERIC
        explicit = os.environ.get("SAIL_SENSITIVE_PATTERNS")
        local = Path(explicit) if explicit else Path.home() / ".config/sail/sensitive-patterns"
        if explicit or local.exists():
            extra = [line for line in local.read_text().splitlines()
                     if line.strip() and not line.lstrip().startswith("#")]
            if extra:
                self.patterns += "|" + "|".join(extra)
        self.matching([], self.patterns)  # Validate even with no files.
        self.failed = False

    @staticmethod
    def matching(lines, pattern):
        output = run(["grep", "-nE", "--", pattern],
                     b"\n".join(lines) + (b"\n" if lines else b""), allowed=(0, 1))
        matches = []
        for line in output.splitlines():
            number, separator, _ = line.partition(b":")
            if not separator or not number.isdigit():
                raise CheckError("cannot read pattern results")
            matches.append(int(number) - 1)
        return matches

    def has(self, data):
        return bool(self.matching(lf_lines(data), self.patterns))

    def report(self, location):
        print("sensitive-check: " + location)
        self.failed = True

    def paths(self, paths):
        # A Git filename can contain a newline; never scan its quoted display.
        parts, owners = [], []
        for path in paths:
            fragments = path.split(b"\n")
            parts.extend(fragments)
            owners.extend([path] * len(fragments))
        hits = self.matching(parts, BAD_PATHS + "|" + self.patterns)
        for _ in set(owners[n] for n in hits):
            self.report("rejected tracked path")  # The name may itself be private.

    def location(self, path, number):
        name = "(redacted path)" if self.has(path) else json.dumps(os.fsdecode(path))
        return f"{name}:{number}"

    def content(self, path, data):
        if b"\0" in data:  # Preserve the text-only policy of git grep -I.
            return
        lines = lf_lines(data)
        for n in self.matching(lines, self.patterns):
            if b"sensitive-check: allow" not in lines[n]:
                self.report(self.location(path, n + 1))

    def identities(self):
        for name in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
            value = git("var", name)
            identity = re.fullmatch(rb"(.*) <(.*)> -?[0-9]+ [+-][0-9]{4}\n?", value)
            if identity is None:
                raise CheckError("cannot read proposed identity")
            if any(self.has(field) for field in identity.groups()):
                self.report("proposed " + name)

    def snapshot(self, staged):
        entries = nul(git("ls-files", "--stage", "-z") if staged
                      else git("ls-tree", "-rz", "HEAD"))
        paths, links = [], []
        for entry in entries:
            meta, path = entry.split(b"\t", 1)
            fields = meta.split()
            if staged and fields[2] != b"0":
                raise CheckError("cannot inspect an unmerged index")
            paths.append(path)
            if fields[0] == b"120000":
                links.append(path)
        self.paths(paths)
        args = (["--cached", "-lzIE", self.patterns] if staged
                else ["-lzIE", self.patterns, "HEAD"])
        hits = nul(git("grep", *args, "--", ".", allowed=(0, 1)))
        if not staged:
            hits = [path.removeprefix(b"HEAD:") for path in hits]
        revision = ":0:" if staged else "HEAD:"
        for path in sorted(set(hits + links)):
            self.content(path, git("show", revision + os.fsdecode(path)))
        if staged:
            self.identities()

    def message(self, path):
        # Git's cleanup mode is caller-controlled, including verbatim.
        if self.has(Path(path).read_bytes()):
            self.report("proposed commit message")
        self.identities()

    def changes(self, base, head):
        base, head = (git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
                      .decode("ascii").strip() for ref in (base, head))
        self.paths(nul(git("diff", "--name-only", "--diff-filter=A", "--no-renames", "-z", base, head)))
        paths = nul(git("diff", "--name-only", "--no-renames", "-z", base, head))
        texts, locations = [], []
        for path in paths:
            diff = git("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames",
                       "--unified=0", base, head, "--", os.fsdecode(path))
            number = None
            for line in lf_lines(diff):
                hunk = re.match(rb"^@@ -[0-9,]+ \+([0-9]+)(?:,[0-9]+)? @@", line)
                if hunk:
                    number = int(hunk[1])
                elif number is not None and line.startswith(b"+"):
                    if b"sensitive-check: allow" not in line:
                        texts.append(line[1:])
                        locations.append((path, number))
                    number += 1
        for n in self.matching(texts, self.patterns):
            self.report(self.location(*locations[n]))
        for commit in git("rev-list", base + ".." + head).decode("ascii").splitlines():
            short = git("rev-parse", "--short", commit).decode("ascii").strip()
            if self.has(git("log", "-1", "--format=%B", commit)):
                self.report("commit " + short + ": message")
            if self.has(git("log", "-1", "--format=%an%n%ae%n%cn%n%ce", commit)):
                self.report("commit " + short + ": author or committer")


def main(args):
    if len(args) == 2 and args[0] == "message":
        args = ["message", str(Path(args[1]).absolute())]
    guard = Guard()
    # Direct invocations from a subdirectory must inspect the whole
    # repository too. Relative message and local-rule paths refer to the
    # caller's directory and were resolved/read before changing it.
    os.chdir(os.fsdecode(git("rev-parse", "--show-toplevel").rstrip(b"\n")))
    if args == ["index"]:
        guard.snapshot(True)
    elif args == ["tree"]:
        guard.snapshot(False)
    elif len(args) == 2 and args[0] == "message":
        guard.message(args[1])
    elif len(args) == 3 and args[0] == "range":
        guard.changes(args[1], args[2])
    else:
        raise CheckError("invalid arguments")
    if guard.failed:
        print("sensitive-check: failed; keep such content outside the repository", file=sys.stderr)
        return 1
    print("sensitive-check: ok")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (CheckError, OSError, ValueError, UnicodeError, IndexError):
        print("sensitive-check: cannot complete inspection; refusing", file=sys.stderr)
        sys.exit(1)
