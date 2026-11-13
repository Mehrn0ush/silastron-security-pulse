#!/usr/bin/env bash
# Push the current HEAD to a branch, safe against a concurrent push: fetch, rebase onto the remote branch,
# push, and try again up to three times. A rebase conflict (someone changed the same file) fails at once
# and leaves the work tree clean. Nothing here changes repository settings or forces a push.
#
# usage: push-with-retry.sh [branch]   (default: main)
set -uo pipefail

branch="${1:-main}"
remote="${REMOTE:-origin}"
max_attempts=3

for attempt in $(seq 1 "$max_attempts"); do
  git fetch --quiet "$remote" "$branch" || { echo "fetch failed (attempt $attempt)"; continue; }
  if ! git rebase "$remote/$branch"; then
    git rebase --abort || true
    echo "rebase onto $remote/$branch conflicts; not pushing" >&2
    exit 1
  fi
  if git push "$remote" "HEAD:$branch"; then
    exit 0
  fi
  echo "push rejected (attempt $attempt of $max_attempts)"
done

echo "giving up after $max_attempts attempts" >&2
exit 1
