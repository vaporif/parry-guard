#!/usr/bin/env bash
set -euo pipefail

status=0
for bin in "$@"; do
  otool -L "$bin"
  bad=$(otool -L "$bin" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)' || true)
  if [[ -n "$bad" ]]; then
    echo "::error::$bin links non-system dylibs:"
    echo "$bad"
    status=1
  fi
done
exit $status
