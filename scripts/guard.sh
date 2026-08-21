#!/usr/bin/env bash
# F-01b: immutability guard.
#
# Fails if any commit in the PR range (BASE_REF...HEAD) touches protected
# paths. Rules:
#   *_test.go        — never, unless the commit message contains [test-authoring]
#   testdata/        — never (covers testdata/oracle/)
#   internal/model/  — never, once the "model-freeze" tag exists
#   go.mod, go.sum   — never, unless the commit message contains [deps]
#
# Usage: BASE_REF=<branch> scripts/guard.sh
set -u

BASE_REF="${BASE_REF:-main}"

fail() {
	echo "::error::guard: $1"
	exit 1
}

base_sha="$(git merge-base "origin/$BASE_REF" HEAD 2>/dev/null)" \
	|| base_sha="$(git merge-base "$BASE_REF" HEAD)" \
	|| { echo "guard: cannot resolve base ref '$BASE_REF'" >&2; exit 2; }

commits="$(git rev-list "$base_sha..HEAD")"
[ -z "$commits" ] && { echo "guard: no new commits; OK"; exit 0; }

frozen=0
if git rev-parse -q --verify "refs/tags/model-freeze" >/dev/null; then
	frozen=1
fi

for c in $commits; do
	msg="$(git log -1 --format=%B "$c")"
	while IFS= read -r f; do
		[ -z "$f" ] && continue
		case "$f" in
		*_test.go)
			[[ "$msg" == *"[test-authoring]"* ]] \
				|| fail "$c: $f — *_test.go files are off-limits; commit message must contain [test-authoring]"
			;;
		testdata/*)
			fail "$c: $f — testdata/ is off-limits (fixtures are the specification)"
			;;
		internal/model/*)
			[ "$frozen" = 1 ] \
				&& fail "$c: $f — internal/model/ is frozen (tag model-freeze exists)"
			;;
		go.mod|go.sum)
			[[ "$msg" == *"[deps]"* ]] \
				|| fail "$c: $f — go.mod/go.sum changes require [deps] in the commit message"
			;;
		esac
	done <<-EOF
$(git diff-tree --root --no-commit-id --name-only -r "$c")
EOF
done

echo "guard: OK — no protected-path violations in ${base_sha}..HEAD"
