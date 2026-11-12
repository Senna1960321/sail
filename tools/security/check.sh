#!/usr/bin/env bash
set -uo pipefail

readonly EXIT_FINDINGS=1
readonly EXIT_ERROR=2
readonly EXIT_UNAVAILABLE=3
readonly AUDIT_VERSION="0.22.2"
readonly DENY_VERSION="0.20.2"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"

usage() {
  echo "usage: $0 [all|sources|audit|licenses]" >&2
}

tool_version() {
  local command_name="$1"
  "$command_name" --version 2>/dev/null | awk '{print $2}'
}

require_tool() {
  local command_name="$1"
  local expected="$2"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "security-check: UNAVAILABLE: $command_name $expected is not installed" >&2
    return "$EXIT_UNAVAILABLE"
  fi
  local actual
  actual="$(tool_version "$command_name")"
  if [[ "$actual" != "$expected" ]]; then
    echo "security-check: UNAVAILABLE: $command_name version $actual found; require $expected" >&2
    return "$EXIT_UNAVAILABLE"
  fi
}

classify_failure() {
  local scanner="$1"
  local log="$2"
  if grep -Eiq 'operation not permitted|permission denied|read-only file system' "$log"; then
    echo "security-check: ERROR: $scanner was blocked by filesystem permissions" >&2
    return "$EXIT_ERROR"
  fi
  if grep -Eiq 'could not resolve|failed to (fetch|download)|network failure|timed? out|unable to access|could not connect|connection refused' "$log"; then
    echo "security-check: UNAVAILABLE: $scanner could not reach a required service" >&2
    return "$EXIT_UNAVAILABLE"
  fi
  if grep -Eq '(^|[^A-Z])RUSTSEC-[0-9]{4}-[0-9]{4}|Vulnerabilit(y|ies) found|error\[' "$log"; then
    echo "security-check: FAIL: $scanner reported policy findings" >&2
    return "$EXIT_FINDINGS"
  fi
  echo "security-check: ERROR: $scanner failed before producing classified findings" >&2
  return "$EXIT_ERROR"
}

run_logged() {
  local scanner="$1"
  shift
  local log
  log="$(mktemp "${TMPDIR:-/tmp}/leaf-security.XXXXXX")" || return "$EXIT_ERROR"
  "$@" 2>&1 | tee "$log"
  local scanner_rc=${PIPESTATUS[0]}
  if [[ $scanner_rc -eq 0 ]]; then
    rm -f -- "$log"
    echo "security-check: PASS: $scanner"
    return 0
  fi
  classify_failure "$scanner" "$log"
  local classified=$?
  rm -f -- "$log"
  return "$classified"
}

run_sources() {
  python3 "$script_dir/check_sources.py"
}

run_audit() {
  require_tool cargo-audit "$AUDIT_VERSION" || return $?
  local lockfile="${SECURITY_LOCKFILE:-$repo_root/Cargo.lock}"
  if [[ ! -f "$lockfile" ]]; then
    echo "security-check: ERROR: Cargo.lock is required for cargo-audit: $lockfile" >&2
    return "$EXIT_ERROR"
  fi
  # Both scanners must inspect the repository graph. A copied lockfile is
  # accepted only when it is byte-identical, then the canonical file is used.
  if ! cmp -s "$lockfile" "$repo_root/Cargo.lock"; then
    echo "security-check: ERROR: audit requires the repository Cargo.lock or an identical copy" >&2
    return "$EXIT_ERROR"
  fi
  lockfile="$repo_root/Cargo.lock"
  require_tool cargo-deny "$DENY_VERSION" || return $?
  # Unsound advisories are warnings by default; they must fail this gate.
  local -a audit_args=(cargo audit --deny unsound --file "$lockfile")
  # The advisories deny.toml allows, each with its reason there.
  local id
  for id in $(grep -oE 'id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' "$script_dir/deny.toml" | grep -oE 'RUSTSEC-[0-9-]+'); do
    audit_args+=(--ignore "$id")
  done
  if [[ -n "${CARGO_AUDIT_DB:-}" ]]; then
    audit_args+=(--db "$CARGO_AUDIT_DB")
  fi
  run_logged "cargo-audit advisories" "${audit_args[@]}" || return $?
  # Independently require readable local registry entries. This native
  # check does not attest to a fresh online yank query; cargo-audit can
  # return zero after an online lookup error, which remains incomplete.
  run_logged "cargo-deny advisories" \
    cargo deny --locked --manifest-path "$repo_root/Cargo.toml" \
      --config "$script_dir/deny.toml" check --deny index-failure advisories
}

run_licenses() {
  require_tool cargo-deny "$DENY_VERSION" || return $?
  run_logged "cargo-deny licenses/sources" \
    cargo deny --locked --manifest-path "$repo_root/Cargo.toml" \
      --config "$script_dir/deny.toml" check licenses sources
}

run_all() {
  local findings=0
  local errors=0
  local unavailable=0
  local rc
  for check in run_sources run_audit run_licenses; do
    "$check"
    rc=$?
    case "$rc" in
      0) ;;
      "$EXIT_FINDINGS") findings=1 ;;
      "$EXIT_UNAVAILABLE") unavailable=1 ;;
      *) errors=1 ;;
    esac
  done
  if [[ $findings -ne 0 ]]; then return "$EXIT_FINDINGS"; fi
  if [[ $unavailable -ne 0 ]]; then return "$EXIT_UNAVAILABLE"; fi
  if [[ $errors -ne 0 ]]; then return "$EXIT_ERROR"; fi
  return 0
}

case "${1:-all}" in
  all) run_all ;;
  sources) run_sources ;;
  audit) run_audit ;;
  licenses) run_licenses ;;
  *) usage; exit 64 ;;
esac
