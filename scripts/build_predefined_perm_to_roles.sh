#!/usr/bin/env bash
set -euo pipefail

# build_predefined_perm_to_roles.sh
#
# Build a JSON mapping of:
#   permission -> [predefined roles containing that permission]
#
# Usage:
#   ./build_predefined_perm_to_roles.sh perms.txt > perm_to_roles.json
#
# Optional:
#   JOBS=8 ./build_predefined_perm_to_roles.sh perms.txt > perm_to_roles.json
#
# Input file format:
#   - one permission per line
#   - blank lines ignored
#   - lines starting with # ignored
#
# Notes:
#   - Progress/debug output goes to STDERR
#   - Final JSON goes to STDOUT
#   - Parallelism is used only for the expensive "gcloud iam roles describe" phase

PERMS_FILE="${1:-}"
JOBS="${JOBS:-8}"

if [[ -z "${PERMS_FILE}" || ! -f "${PERMS_FILE}" ]]; then
  echo "Usage: $0 <perms.txt>" >&2
  exit 1
fi

if ! command -v gcloud >/dev/null 2>&1; then
  echo "[X] gcloud not found in PATH" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[X] jq not found in PATH" >&2
  exit 1
fi

if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || [[ "$JOBS" -lt 1 ]]; then
  echo "[X] JOBS must be a positive integer" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ROLES_FILE="$TMPDIR/predefined_roles.txt"
ROLE_JSON_DIR="$TMPDIR/role_json"
MATCH_DIR="$TMPDIR/matches"
FAILED_FILE="$TMPDIR/failed_roles.txt"

mkdir -p "$ROLE_JSON_DIR" "$MATCH_DIR"
: > "$FAILED_FILE"

echo "[*] Reading permissions from: $PERMS_FILE" >&2
mapfile -t PERMISSIONS < <(
  grep -v '^[[:space:]]*#' "$PERMS_FILE" \
    | sed 's/[[:space:]]*$//' \
    | grep -v '^[[:space:]]*$' || true
)

if [[ "${#PERMISSIONS[@]}" -eq 0 ]]; then
  echo "[X] No permissions found in input file" >&2
  exit 1
fi

echo "[*] Loaded ${#PERMISSIONS[@]} permission(s)" >&2
for perm in "${PERMISSIONS[@]}"; do
  echo "    - $perm" >&2
done

declare -A TARGET_PERMS=()
declare -A PERM_TO_FILE=()

for perm in "${PERMISSIONS[@]}"; do
  TARGET_PERMS["$perm"]=1
  safe_perm_name="$(printf '%s' "$perm" | sed 's#[^A-Za-z0-9_.-]#_#g')"
  PERM_TO_FILE["$perm"]="$MATCH_DIR/$safe_perm_name.txt"
  : > "${PERM_TO_FILE[$perm]}"
done

echo "[*] Listing predefined IAM roles..." >&2
gcloud iam roles list --format="value(name)" | sort -u > "$ROLES_FILE"

mapfile -t ROLES < "$ROLES_FILE"
ROLE_COUNT="${#ROLES[@]}"

if [[ "$ROLE_COUNT" -eq 0 ]]; then
  echo "[X] No predefined roles returned by gcloud iam roles list" >&2
  exit 1
fi

echo "[*] Found $ROLE_COUNT predefined role(s)" >&2
echo "[*] Caching role metadata with JOBS=$JOBS ..." >&2

fetch_role() {
  local role="$1"
  local out_dir="$2"
  local fail_file="$3"
  local safe_name out_file tmp_file

  safe_name="$(printf '%s' "$role" | sed 's#[/:]#_#g')"
  out_file="$out_dir/$safe_name.json"
  tmp_file="$out_file.tmp"

  if gcloud iam roles describe "$role" --format=json > "$tmp_file" 2>/dev/null; then
    mv "$tmp_file" "$out_file"
  else
    rm -f "$tmp_file"
    echo "$role" >> "$fail_file"
    return 1
  fi
}

export -f fetch_role

active=0
queued=0

for role in "${ROLES[@]}"; do
  queued=$((queued + 1))
  printf '\r[*] Describing roles [%d/%d] %s' "$queued" "$ROLE_COUNT" "$role" >&2

  bash -c 'fetch_role "$@"' _ "$role" "$ROLE_JSON_DIR" "$FAILED_FILE" &
  active=$((active + 1))

  if (( active >= JOBS )); then
    if ! wait -n; then
      :
    fi
    active=$((active - 1))
  fi
done

while (( active > 0 )); do
  if ! wait -n; then
    :
  fi
  active=$((active - 1))
done

printf '\r[*] Describing roles [%d/%d] complete%*s\n' "$ROLE_COUNT" "$ROLE_COUNT" 20 "" >&2

FAILED_COUNT=0
if [[ -s "$FAILED_FILE" ]]; then
  FAILED_COUNT="$(sort -u "$FAILED_FILE" | wc -l | tr -d ' ')"
fi

if [[ "$FAILED_COUNT" -gt 0 ]]; then
  echo "[!] Failed to describe $FAILED_COUNT role(s)" >&2
  sort -u "$FAILED_FILE" | sed 's/^/    - /' >&2
fi

shopt -s nullglob
ROLE_JSON_FILES=( "$ROLE_JSON_DIR"/*.json )
shopt -u nullglob

CACHED_COUNT="${#ROLE_JSON_FILES[@]}"
if [[ "$CACHED_COUNT" -eq 0 ]]; then
  echo "[X] No role metadata was cached successfully" >&2
  exit 1
fi

echo "[*] Cached metadata for $CACHED_COUNT role(s)" >&2
echo "[*] One-pass local matching: scanning each cached role once and checking all target permissions..." >&2

checked=0
total_matches=0

for role_json in "${ROLE_JSON_FILES[@]}"; do
  checked=$((checked + 1))

  role_name="$(jq -r '.name // empty' "$role_json")"
  if [[ -z "$role_name" ]]; then
    continue
  fi

  printf '\r[*] CHECKING ROLE [%d/%d] %s' "$checked" "$CACHED_COUNT" "$role_name" >&2

  while IFS= read -r included_perm; do
    [[ -z "$included_perm" ]] && continue

    if [[ -n "${TARGET_PERMS[$included_perm]:-}" ]]; then
      echo "$role_name" >> "${PERM_TO_FILE[$included_perm]}"
      total_matches=$((total_matches + 1))
      printf '\n    [+] MATCH: %s -> %s\n' "$role_name" "$included_perm" >&2
    fi
  done < <(jq -r '.includedPermissions[]?' "$role_json")
done

printf '\n' >&2

echo "[*] Building final JSON mapping..." >&2

first=true
printf '{\n'
for perm in "${PERMISSIONS[@]}"; do
  if [[ "$first" == true ]]; then
    first=false
  else
    printf ',\n'
  fi

  json_key="$(printf '%s' "$perm" | jq -R .)"

  if [[ -s "${PERM_TO_FILE[$perm]}" ]]; then
    json_val="$(
      sort -u "${PERM_TO_FILE[$perm]}" \
        | jq -R . \
        | jq -s .
    )"
  else
    json_val='[]'
  fi

  printf '  %s: %s' "$json_key" "$json_val"
done
printf '\n}\n'

echo "[*] Done" >&2
echo "[*] Permissions processed: ${#PERMISSIONS[@]}" >&2
echo "[*] Predefined roles listed: $ROLE_COUNT" >&2
echo "[*] Role metadata cached successfully: $CACHED_COUNT" >&2
echo "[*] Raw permission->role matches found: $total_matches" >&2
