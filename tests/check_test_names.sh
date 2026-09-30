#!/usr/bin/env bash
# Fails when the suite's test names differ from tests/TESTS.golden.
#
# CI selects tests by name and nextest partitions them by name hash, so a
# renamed or dropped test must show up as a reviewed change to the golden file.
# After adding, renaming or removing a test, regenerate it with:
#
#   tests/check_test_names.sh --update
set -euo pipefail
cd "$(dirname "$0")/.."

list() {
    cargo nextest list --features integration-test --run-ignored all \
        --message-format oneline | LC_ALL=C sort
}

if [ "${1:-}" = "--update" ]; then
    list > tests/TESTS.golden
    echo "tests/TESTS.golden updated: $(wc -l < tests/TESTS.golden) tests"
    exit 0
fi

current=$(mktemp)
trap 'rm -f "$current"' EXIT
list > "$current"
if ! diff -u tests/TESTS.golden "$current"; then
    echo "Test names differ from tests/TESTS.golden (- golden, + current)." >&2
    echo "If the change is intended, run tests/check_test_names.sh --update." >&2
    exit 1
fi
echo "Test names match tests/TESTS.golden ($(wc -l < "$current") tests)."
