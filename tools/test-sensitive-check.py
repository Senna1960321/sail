#!/usr/bin/env python3
"""Real Git commits in throwaway repositories; no network or compilation."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent
GIT = shutil.which("git")
SECRET = "/" + "home" + "/" + "guard-fixture" + "/" + "private"
TOKEN = "guard-fixture-token"


class Commits(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sail-guard-test-")
        self.addCleanup(self.temp.cleanup)
        self.outer = Path(self.temp.name)
        self.repo = self.outer / "repo space"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.patterns = self.outer / "patterns"
        self.patterns.write_text("")
        self.global_config = self.outer / "global-config"
        self.global_config.write_text("")
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.global_config),
                        SAIL_SENSITIVE_PATTERNS=str(self.patterns),
                        GIT_AUTHOR_NAME="Guard Test", GIT_AUTHOR_EMAIL="guard@example.invalid",
                        GIT_COMMITTER_NAME="Guard Test", GIT_COMMITTER_EMAIL="guard@example.invalid")
        self.git("init", "-q")
        (self.repo / "tools/hooks").mkdir(parents=True)
        for name in ("sensitive-check.sh", "sensitive-check.py", "install-commit-hooks.py"):
            shutil.copy2(SOURCE / name, self.repo / "tools" / name)
        for name in ("pre-commit", "commit-msg"):
            shutil.copy2(SOURCE / "hooks" / name, self.repo / "tools/hooks" / name)
        self.command(["python3", "tools/install-commit-hooks.py"])
        self.git("add", "tools")
        self.git("commit", "-qm", "Initialize guard")

    def command(self, args, expected=True, extra=None, cwd=None):
        env = self.env.copy()
        env.update(extra or {})
        result = subprocess.run(args, cwd=cwd or self.repo, env=env, capture_output=True)
        self.assertEqual(result.returncode == 0, expected, "unexpected command outcome")
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr, "finding text escaped")
        return result

    def git(self, *args, **kwargs):
        return self.command([GIT, *args], **kwargs)

    def scan(self, *args, **kwargs):
        return self.command(["sh", str(self.repo / "tools/sensitive-check.sh"), *args], **kwargs)

    def stage(self, text="ordinary content", name="sample.txt"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")
        self.git("--literal-pathspecs", "add", "--", name)

    def refused(self, args=("-qm", "Test change"), extra=None):
        before = self.git("rev-parse", "HEAD").stdout
        self.git("commit", *args, expected=False, extra=extra)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout, before)

    def test_staged_content_hidden_by_unstaged_edit(self):
        self.stage(SECRET)
        (self.repo / "sample.txt").write_text("clean worktree\n")
        self.refused()

    def test_clean_index_is_not_replaced_by_dirty_worktree(self):
        self.stage()
        (self.repo / "sample.txt").write_text(SECRET)
        self.git("commit", "-qm", "Clean snapshot")
        self.assertEqual(self.git("show", "HEAD:sample.txt").stdout, b"ordinary content\n")

    def test_partial_commit_uses_gits_temporary_index(self):
        self.stage(SECRET, "held.txt")
        self.stage(name="included.txt")
        self.git("commit", "--only", "-qm", "Partial snapshot", "--", "included.txt")
        self.git("cat-file", "-e", "HEAD:held.txt", expected=False)
        self.assertIn(b"held.txt", self.git("diff", "--cached", "--name-only").stdout)

    def test_subdirectory_invocations_inspect_the_whole_index(self):
        directory = self.repo / "nested"
        directory.mkdir()
        self.stage(TOKEN)
        (directory / "rules").write_text(TOKEN + "\n")
        result = self.scan("index", cwd=directory, expected=False,
                           extra={"SAIL_SENSITIVE_PATTERNS": "rules"})
        self.assertIn(b"sample.txt", result.stdout)

    def test_relative_message_path_is_resolved_before_changing_directory(self):
        directory = self.repo / "nested"
        directory.mkdir()
        (directory / "draft").write_text(SECRET)
        result = self.scan("message", "draft", cwd=directory, expected=False)
        self.assertIn(b"proposed commit message", result.stdout)

    def test_messages_include_verbatim_comments_and_allow_markers(self):
        self.stage()
        for message in (SECRET, "# " + SECRET, SECRET + " sensitive-check: allow"):
            with self.subTest(kind=message.startswith("#")):
                self.refused(("--cleanup=verbatim", "-qm", message))

    def test_proposed_author_and_committer(self):
        self.stage()
        for identity in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
            with self.subTest(identity=identity):
                self.refused(extra={identity: SECRET})
        self.refused(("-qm", "Explicit author", "--author", SECRET + " <guard@example.invalid>"))

    def test_amend_checks_the_reused_author(self):
        self.stage()
        self.git("commit", "-qm", "Legacy author", extra={"GIT_AUTHOR_NAME": TOKEN})
        self.patterns.write_text(TOKEN + "\n")
        self.refused(("--amend", "-qm", "New message"))

    def test_anchored_local_rules_check_identity_fields(self):
        self.stage()
        self.patterns.write_text("^" + TOKEN + "$\n")
        self.refused(extra={"GIT_AUTHOR_NAME": TOKEN})
        email = TOKEN + "@example.invalid"
        self.patterns.write_text("^" + email.replace(".", r"\.") + "$\n")
        self.refused(extra={"GIT_COMMITTER_EMAIL": email})

    def test_paths_and_newline_quoted_names(self):
        for name in ("evidence/result.txt", "validation/result.txt", "output.log", "evidence/line\nbreak.txt"):
            with self.subTest(kind=name.split("/")[0]):
                self.stage(name=name)
                self.refused()
                self.git("reset", "--hard", "-q", "HEAD")
        self.stage(name="quoted\nname.txt")
        self.git("commit", "-qm", "A legal filename")

    def test_symlink_target_is_staged_text(self):
        (self.repo / "link").symlink_to(SECRET)
        self.git("add", "link")
        self.refused()

    def test_allow_marker_is_only_a_content_exemption(self):
        self.stage(SECRET + " sensitive-check: allow")
        self.git("commit", "-qm", "Documented fixture")

    def test_tree_reads_head_not_worktree(self):
        self.stage(TOKEN)
        self.git("commit", "-qm", "Legacy snapshot")
        self.patterns.write_text(TOKEN + "\n")
        (self.repo / "sample.txt").write_text("clean worktree\n")
        self.scan("tree", expected=False)

    def test_range_checks_added_lines_messages_and_identities(self):
        base = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.stage(TOKEN)
        self.git("commit", "-qm", "Legacy " + TOKEN, extra={"GIT_AUTHOR_NAME": TOKEN})
        self.patterns.write_text(TOKEN + "\n")
        result = self.scan("range", base, "HEAD", expected=False)
        for location in (b'sample.txt', b': message', b': author or committer'):
            self.assertIn(location, result.stdout)
        self.assertNotIn(TOKEN.encode(), result.stdout + result.stderr)

    def test_range_does_not_rescan_unchanged_content(self):
        self.stage(TOKEN)
        self.git("commit", "-qm", "Old fixture")
        base = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.stage(TOKEN + "\nnew ordinary line")
        self.git("commit", "-qm", "Ordinary addition")
        self.patterns.write_text(TOKEN + "\n")
        self.scan("range", base, "HEAD")

    def test_range_uses_literal_filenames_not_pathspec_magic(self):
        base = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.stage(TOKEN, ":(literal)sample.txt")
        self.git("commit", "-qm", "Legacy filename")
        self.patterns.write_text(TOKEN + "\n")
        self.scan("range", base, "HEAD", expected=False)

    def fake_git(self, subcommand):
        directory = self.outer / "bin"
        directory.mkdir(exist_ok=True)
        shim = directory / "git"
        shim.write_text('#!/bin/sh\nif [ "$1" = ' + shlex.quote(subcommand) +
                        ' ]; then exit 128; fi\nexec ' + shlex.quote(GIT) + ' "$@"\n')
        shim.chmod(0o755)
        # Git prepends its exec-path before invoking hooks. Replace that
        # too, so the failed plumbing command is actually reached.
        return {"PATH": str(directory) + os.pathsep + self.env["PATH"],
                "GIT_EXEC_PATH": str(directory)}

    def test_git_inspection_errors_refuse_real_commits(self):
        for subcommand in ("rev-parse", "ls-files", "grep", "var"):
            with self.subTest(command=subcommand):
                self.stage("ordinary " + subcommand)
                self.refused(extra=self.fake_git(subcommand))

    def test_bad_revisions_and_git_range_errors_are_not_clean(self):
        self.scan("range", "missing-revision", "HEAD", expected=False)
        self.scan("range", "--no-index", "HEAD", expected=False)
        for subcommand in ("diff", "rev-list"):
            with self.subTest(command=subcommand):
                self.scan("range", "HEAD", "HEAD", expected=False, extra=self.fake_git(subcommand))

    def test_commit_metadata_errors_and_missing_local_rules_refuse(self):
        base = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.stage()
        self.git("commit", "-qm", "Ordinary change")
        self.scan("range", base, "HEAD", expected=False, extra=self.fake_git("log"))
        self.scan("message", ".git/COMMIT_EDITMSG", expected=False, extra=self.fake_git("var"))
        self.scan("index", expected=False,
                  extra={"SAIL_SENSITIVE_PATTERNS": str(self.outer / "missing-rules")})

    def test_invalid_patterns_and_unreadable_message_refuse(self):
        self.patterns.write_text("[\n")
        self.stage()
        self.refused()
        self.patterns.write_text("")
        self.scan("message", "missing-message", expected=False)

    def test_installer_refuses_existing_hook_without_overwriting(self):
        hook = self.repo / ".git/hooks/commit-msg"
        hook.write_text("#!/bin/sh\nexit 0\n")
        self.command(["python3", "tools/install-commit-hooks.py"], expected=False)
        self.assertEqual(hook.read_text(), "#!/bin/sh\nexit 0\n")

    def test_global_dispatcher_is_preserved_and_delegates(self):
        dispatcher = self.outer / "dispatcher"
        dispatcher.mkdir()
        for name in ("pre-commit", "commit-msg"):
            hook = dispatcher / name
            hook.write_text('#!/bin/sh\nname=$(basename "$0")\n'
                            'exec "$(git rev-parse --git-common-dir)/hooks/$name" "$@"\n')
            hook.chmod(0o755)
        self.git("config", "--global", "core.hooksPath", str(dispatcher))
        before = self.global_config.read_bytes()
        self.command(["python3", "tools/install-commit-hooks.py"], expected=False)
        self.command(["python3", "tools/install-commit-hooks.py", "--via-dispatcher"])
        self.assertEqual(self.global_config.read_bytes(), before)
        self.stage(SECRET)
        self.refused()

    def test_linked_worktree_installs_to_common_hooks(self):
        worktree = self.outer / "linked"
        self.git("worktree", "add", "-qb", "linked", str(worktree))
        self.command(["python3", "tools/install-commit-hooks.py"], cwd=worktree)
        (worktree / "sample.txt").write_text(SECRET)
        self.git("add", "sample.txt", cwd=worktree)
        self.git("commit", "-qm", "Linked snapshot", cwd=worktree, expected=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
