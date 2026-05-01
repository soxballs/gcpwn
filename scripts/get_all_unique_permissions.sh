#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID=""
ORG_ID=""
OUTFILE="all_unique_permissions.txt"
THREADS=10

usage() {
  cat <<'EOF'
Usage:
  ./get_all_unique_permissions.sh
  ./get_all_unique_permissions.sh --threads 15
  ./get_all_unique_permissions.sh --project my-project
  ./get_all_unique_permissions.sh --organization 123456789012
  ./get_all_unique_permissions.sh --project my-project --organization 123456789012
  ./get_all_unique_permissions.sh --output /tmp/perms.txt --threads 15

Description:
  Collects all IAM permissions from:
    - predefined roles
    - optional custom project roles
    - optional custom organization roles

  Then outputs one unique sorted permission list.

Options:
  --project <PROJECT_ID>         Include custom roles from a project
  --organization <ORG_ID>        Include custom roles from an organization
  --output <FILE>                Output file path
  --threads <N>                  Parallel describe workers (default: 10)
  -h, --help                     Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)
      PROJECT_ID="${2:-}"
      shift 2
      ;;
    --organization)
      ORG_ID="${2:-}"
      shift 2
      ;;
    --output)
      OUTFILE="${2:-}"
      shift 2
      ;;
    --threads)
      THREADS="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

for cmd in gcloud jq xargs sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] Required command not found: $cmd" >&2
    exit 1
  fi
done

if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
  echo "[!] --threads must be a positive integer" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
ROLE_FILE="$TMPDIR/roles.txt"
JSON_DIR="$TMPDIR/role_json"
PERM_FILE="$TMPDIR/perms.txt"
FAILED_FILE="$TMPDIR/failed_roles.txt"

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$JSON_DIR"
touch "$ROLE_FILE" "$PERM_FILE" "$FAILED_FILE"

echo "[*] Collecting predefined roles..." >&2
gcloud iam roles list --format="value(name)" >> "$ROLE_FILE"

if [[ -n "$PROJECT_ID" ]]; then
  echo "[*] Collecting custom project roles from: $PROJECT_ID" >&2
  gcloud iam roles list --project="$PROJECT_ID" --format="value(name)" >> "$ROLE_FILE"
fi

if [[ -n "$ORG_ID" ]]; then
  echo "[*] Collecting custom organization roles from: $ORG_ID" >&2
  gcloud iam roles list --organization="$ORG_ID" --format="value(name)" >> "$ROLE_FILE"
fi

sort -u "$ROLE_FILE" -o "$ROLE_FILE"

ROLE_COUNT="$(wc -l < "$ROLE_FILE" | tr -d ' ')"
echo "[*] Found $ROLE_COUNT unique roles. Describing with $THREADS threads..." >&2

export JSON_DIR FAILED_FILE

xargs -P "$THREADS" -I '{}' bash -c '
  set -u

  role_name="$1"
  json_dir="$2"
  failed_file="$3"

  role_hash="$(printf "%s" "$role_name" | sha256sum | awk "{print \$1}")"
  outfile="$json_dir/${role_hash}.json"

  log() {
    echo "$1" >&2
  }

  if [[ "$role_name" == roles/* ]]; then
    if ! gcloud iam roles describe "$role_name" --format=json > "$outfile" 2>/dev/null; then
      log "[!] Failed predefined role: $role_name"
      echo "$role_name" >> "$failed_file"
      rm -f "$outfile"
      exit 0
    fi

  elif [[ "$role_name" == projects/*/roles/* ]]; then
    role_id="${role_name##*/}"
    project_id="$(echo "$role_name" | cut -d/ -f2)"

    if ! gcloud iam roles describe "$role_id" --project="$project_id" --format=json > "$outfile" 2>/dev/null; then
      log "[!] Failed project custom role: $role_name"
      echo "$role_name" >> "$failed_file"
      rm -f "$outfile"
      exit 0
    fi

  elif [[ "$role_name" == organizations/*/roles/* ]]; then
    role_id="${role_name##*/}"
    org_id="$(echo "$role_name" | cut -d/ -f2)"

    if ! gcloud iam roles describe "$role_id" --organization="$org_id" --format=json > "$outfile" 2>/dev/null; then
      log "[!] Failed organization custom role: $role_name"
      echo "$role_name" >> "$failed_file"
      rm -f "$outfile"
      exit 0
    fi

  else
    log "[!] Skipping unrecognized role format: $role_name"
    echo "$role_name" >> "$failed_file"
    exit 0
  fi
' _ '{}' "$JSON_DIR" "$FAILED_FILE" < "$ROLE_FILE"

JSON_COUNT="$(find "$JSON_DIR" -type f -name '*.json' | wc -l | tr -d ' ')"
FAILED_COUNT="$(sort -u "$FAILED_FILE" | sed '/^$/d' | wc -l | tr -d ' ')"

echo "[*] Successfully described $JSON_COUNT roles" >&2
echo "[*] Failed/skipped roles: $FAILED_COUNT" >&2

echo "[*] Extracting permissions with jq..." >&2
find "$JSON_DIR" -type f -name '*.json' -print0 \
  | xargs -0 jq -r '.includedPermissions[]?' \
  | sort -u > "$OUTFILE"

PERM_COUNT="$(wc -l < "$OUTFILE" | tr -d ' ')"
echo "[+] Wrote $PERM_COUNT unique permissions to $OUTFILE" >&2

if [[ "$FAILED_COUNT" -gt 0 ]]; then
  FAIL_OUT="${OUTFILE}.failed_roles.txt"
  sort -u "$FAILED_FILE" | sed '/^$/d' > "$FAIL_OUT"
  echo "[*] Wrote failed/skipped roles to $FAIL_OUT" >&2
fi
