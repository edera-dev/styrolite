#!/bin/sh
set -e

REAL_SCRIPT="$(realpath "${0}")"
cd "$(dirname "${REAL_SCRIPT}")/../.."

# Pulled from the flags resembling the google style guide here
# https://github.com/mvdan/sh/blob/master/cmd/shfmt/shfmt.1.scd#examples
FLAGS="--indent 2 --case-indent --binary-next-line --list"

if [ -z "${STYROLITE_SHFMT_WRITE}" ]; then
  echo "Running shfmt in diff mode..."
  FLAGS="${FLAGS} --diff"
else
  echo "Running shfmt in write mode..."
  FLAGS="${FLAGS} --write"
fi

echo "shfmt $FLAGS"

# shellcheck disable=SC2086
find . -not -path '*/.*' -type f -name '*.sh' -print0 | xargs -0 shfmt $FLAGS
