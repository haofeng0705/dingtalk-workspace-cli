#!/usr/bin/env bash
set -euo pipefail

require_env() {
  name="$1"
  value="${!name:-}"
  if [ -z "$value" ]; then
    printf 'missing required environment variable: %s\n' "$name" >&2
    exit 2
  fi
}

for name in \
  AONE_TRIGGER_URL \
  AONE_PRIVATE_TOKEN \
  GITHUB_REPOSITORY \
  GITHUB_PR_NUMBER \
  GITHUB_BASE_SHA \
  GITHUB_HEAD_SHA \
  GITHUB_HEAD_REPOSITORY \
  CORRELATION_ID \
  GITHUB_OUTPUT
do
  require_env "$name"
done

if [[ "$AONE_TRIGGER_URL" != https://* ]] &&
  [[ ! "$AONE_TRIGGER_URL" =~ ^http://(127\.0\.0\.1|localhost):[0-9]+(/|$) ]]; then
  printf '%s\n' 'AONE_TRIGGER_URL must use HTTPS (loopback HTTP is allowed only for tests)' >&2
  exit 2
fi

if [[ ! "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  printf 'invalid GitHub repository: %s\n' "$GITHUB_REPOSITORY" >&2
  exit 2
fi

if [[ ! "$GITHUB_HEAD_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  printf 'invalid GitHub head repository: %s\n' "$GITHUB_HEAD_REPOSITORY" >&2
  exit 2
fi

if [[ ! "$GITHUB_PR_NUMBER" =~ ^[1-9][0-9]*$ ]]; then
  printf 'invalid GitHub pull request number: %s\n' "$GITHUB_PR_NUMBER" >&2
  exit 2
fi

for sha_name in GITHUB_BASE_SHA GITHUB_HEAD_SHA; do
  sha="${!sha_name}"
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'invalid %s: expected a 40-character lowercase hexadecimal commit SHA\n' "$sha_name" >&2
    exit 2
  fi
done

request_file="$(mktemp "${TMPDIR:-/tmp}/dws-aone-request.XXXXXX")"
response_file="$(mktemp "${TMPDIR:-/tmp}/dws-aone-response.XXXXXX")"
trap 'rm -f "$request_file" "$response_file"' EXIT HUP INT TERM

jq -n \
  --arg branch main \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg pr_number "$GITHUB_PR_NUMBER" \
  --arg base_sha "$GITHUB_BASE_SHA" \
  --arg head_sha "$GITHUB_HEAD_SHA" \
  --arg head_repository "$GITHUB_HEAD_REPOSITORY" \
  --arg correlation_id "$CORRELATION_ID" \
  '{
    branch: $branch,
    commitId: null,
    tag: null,
    mrId: null,
    params: {
      GITHUB_REPOSITORY: $repository,
      GITHUB_PR_NUMBER: $pr_number,
      GITHUB_BASE_SHA: $base_sha,
      GITHUB_HEAD_SHA: $head_sha,
      GITHUB_HEAD_REPOSITORY: $head_repository,
      CORRELATION_ID: $correlation_id
    },
    callbacks: []
  }' >"$request_file"

http_code="$(
  curl --silent --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    --output "$response_file" \
    --write-out '%{http_code}' \
    --request POST \
    --header "private-token: $AONE_PRIVATE_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-binary "@$request_file" \
    "$AONE_TRIGGER_URL"
)"

case "$http_code" in
  2??) ;;
  *)
    printf 'Aone trigger returned HTTP %s\n' "$http_code" >&2
    exit 1
    ;;
esac

if ! jq -e '.success == true' "$response_file" >/dev/null; then
  printf '%s\n' 'Aone trigger response did not report success' >&2
  exit 1
fi

run_id="$(jq -r '.data.id // .data.pipelineRunId // .data.runId // empty' "$response_file")"
case "$run_id" in
  ''|*[!0-9]*)
    printf '%s\n' 'Aone trigger response is missing a numeric run id' >&2
    exit 1
    ;;
esac

{
  printf 'run_id=%s\n' "$run_id"
  printf 'correlation_id=%s\n' "$CORRELATION_ID"
} >>"$GITHUB_OUTPUT"

printf 'Aone evaluation run %s accepted for PR #%s at %s.\n' \
  "$run_id" "$GITHUB_PR_NUMBER" "$GITHUB_HEAD_SHA"
