#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/leaf-security-test.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT

expect_exit() {
  local expected="$1"
  shift
  set +e
  "$@"
  local actual=$?
  set -e
  if [[ $actual -ne $expected ]]; then
    echo "expected exit $expected, got $actual: $*" >&2
    exit 1
  fi
}

bash -n "$script_dir/check.sh" "$script_dir/capture-baseline.sh"
PYTHONPYCACHEPREFIX="$test_root/pycache" python3 -m py_compile "$script_dir/check_sources.py"

# Build a repository-free fixture: without .git, tracking is not relevant, so
# an unchanged policy/manifest/lock set must pass the content checks.
fixture="$test_root/fixture"
mkdir -p \
  "$fixture/tools/security" \
  "$fixture/sail" \
  "$fixture/sail-cli" \
  "$fixture/sail-ffi" \
  "$fixture/sail-netstack" \
  "$fixture/sail-plugins/shadowsocks"
cp "$script_dir/check_sources.py" "$script_dir/policy.toml" "$fixture/tools/security/"
cp "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$fixture/"
cp "$repo_root/sail/Cargo.toml" "$fixture/sail/"
cp "$repo_root/sail-cli/Cargo.toml" "$fixture/sail-cli/"
cp "$repo_root/sail-ffi/Cargo.toml" "$fixture/sail-ffi/"
cp "$repo_root/sail-netstack/Cargo.toml" "$fixture/sail-netstack/"
cp "$repo_root/sail-plugins/shadowsocks/Cargo.toml" "$fixture/sail-plugins/shadowsocks/"
python3 "$fixture/tools/security/check_sources.py" >/dev/null

python3 - "$fixture/Cargo.toml" <<'PY'
from pathlib import Path
import re
import sys

# The first pinned revision, whichever it is, becomes a branch: a pin that
# moves must not leave this case testing nothing.
path = Path(sys.argv[1])
text, count = re.subn(r'rev = "[0-9a-f]{40}"', 'branch = "main"', path.read_text(), count=1)
if count != 1:
    sys.exit("no pinned revision in Cargo.toml to unpin")
path.write_text(text)
PY
expect_exit 1 python3 "$fixture/tools/security/check_sources.py"

# Mock Cargo's external subcommand protocol to exercise fail-closed result
# classification without a network or scanner installation.
mock_bin="$test_root/mock-bin"
mkdir -p "$mock_bin"
printf '%s\n' '#!/usr/bin/env bash' 'echo "cargo-audit 0.22.2"' >"$mock_bin/cargo-audit"
chmod +x "$mock_bin/cargo-audit"

write_mock_cargo() {
  local message="$1"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    "echo '$message' >&2" \
    'exit 1' >"$mock_bin/cargo"
  chmod +x "$mock_bin/cargo"
}

expect_exit 2 env PATH="$mock_bin:/usr/bin:/bin" \
  SECURITY_LOCKFILE="$test_root/missing.lock" "$script_dir/check.sh" audit

write_mock_cargo 'error: Operation not permitted (os error 1)'
expect_exit 2 env PATH="$mock_bin:/usr/bin:/bin" \
  SECURITY_LOCKFILE="$repo_root/Cargo.lock" "$script_dir/check.sh" audit

write_mock_cargo 'failed to download: Could not resolve host'
expect_exit 3 env PATH="$mock_bin:/usr/bin:/bin" \
  SECURITY_LOCKFILE="$repo_root/Cargo.lock" "$script_dir/check.sh" audit

write_mock_cargo 'RUSTSEC-2026-0001: vulnerability found'
expect_exit 1 env PATH="$mock_bin:/usr/bin:/bin" \
  SECURITY_LOCKFILE="$repo_root/Cargo.lock" "$script_dir/check.sh" audit

# An informational unsound advisory exits zero unless the scanner is told
# to deny it. Exercise the actual cargo argument contract, not log wording.
cat >"$mock_bin/cargo" <<'MOCK'
#!/usr/bin/env bash
for ((i=1; i<=$#; i++)); do
  if [[ "${!i}" == --deny ]]; then
    next=$((i + 1))
    if [[ "${!next}" == unsound ]]; then
      echo 'RUSTSEC-2026-0001: unsound advisory denied' >&2
      exit 1
    fi
  fi
done
echo 'warning: unsound advisory (informational by default)' >&2
exit 0
MOCK
chmod +x "$mock_bin/cargo"
expect_exit 1 env PATH="$mock_bin:/usr/bin:/bin" \
  SECURITY_LOCKFILE="$repo_root/Cargo.lock" "$script_dir/check.sh" audit

echo "security self-tests: PASS"
