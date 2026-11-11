# Local commit checks

The commit hooks need Git, Python 3.9 or later, a POSIX shell and `grep`.
Install them once per clone:

```sh
python3 tools/install-commit-hooks.py
```

The installer writes only `pre-commit` and `commit-msg` in the repository's
common Git directory. It refuses to replace a different existing hook and
does not change local or global `core.hooksPath`. Linked worktrees share
these hooks; install from the checkout containing these tools.

If an existing global hook dispatcher already forwards to the repository's
common Git directory's hooks, use `--via-dispatcher`. This flag does not
install or change that dispatcher. For any other custom `core.hooksPath`,
integrate the templates in `tools/hooks/` with its existing hooks instead.

`pre-commit` checks the entire staged text snapshot, filenames and the
proposed author/committer identities. Unstaged edits cannot hide staged
content; Git's temporary index for a partial commit is respected.
`commit-msg` checks the complete proposed message, including comment lines
retained by `--cleanup=verbatim`, and identities again. Failed Git commands,
unreadable inputs and invalid patterns refuse the commit.

The existing `tree` command checks HEAD, and `range BASE HEAD` checks added
lines/paths plus commit messages and identities. Rules are extended regular
expressions. Optional local rules live in the user's Sail configuration
directory, or in the file named by `SAIL_SENSITIVE_PATTERNS`; an explicitly
named file must be readable. Findings show locations, never matched text.
The `sensitive-check: allow` marker exempts a text-content line, not a path,
message or identity. Binary bodies are outside this text check.

These are local checks, not a security boundary: Git can skip hooks, and
someone can modify a local hook. CI and the push-time range check remain
necessary. Run the portable regressions with:

```sh
python3 tools/test-sensitive-check.py
```
