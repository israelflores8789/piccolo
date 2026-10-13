#!/usr/bin/env bash

# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

# apply-rulesets.sh — create or update repository rulesets from
# .github/rulesets/*.json. Idempotent: matches existing rulesets
# by name and updates them in place, creating only what's missing.
#
# Requires: gh (authenticated as a repo admin) and jq.
# Usage: ./apply-rulesets.sh
set -euo pipefail
shopt -s nullglob

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
[[ "$repo" == "israelflores8789/piccolo" ]] || { echo "unexpected repo: $repo (expected israelflores8789/piccolo)" >&2; exit 1; }

for file in "$script_dir"/*.json; do
  name="$(jq --raw-output .name "$file")"
  id="$(gh api "repos/$repo/rulesets?per_page=100" --paginate \
  | jq -r --arg name "$name" '[.[] | select(.name == $name) | .id] | .[0] // empty')"

  body="$(jq 'del(.source_type)' "$file")"   # drop if API 422s without this
  if [[ -n "$id" ]]; then
    printf '%s' "$body" | gh api --method PUT "repos/$repo/rulesets/$id" --input - >/dev/null
    echo "updated ruleset: $name (id $id)"
  else
    printf '%s' "$body" | gh api --method POST "repos/$repo/rulesets" --input - >/dev/null
    echo "created ruleset: $name"
  fi
done
