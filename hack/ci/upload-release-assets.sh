#!/bin/sh
set -e

retry() {
  for i in $(seq 1 10); do
    if "${@}"; then
      return 0
    else
      sleep "${i}"
    fi
  done
  "${@}"
}

if [ -z "${STYROLITE_TAG_NAME}" ]; then
  echo "STYROLITE_TAG_NAME env is missing"
  exit 1
fi

cd target/assets

retry gh release upload "${STYROLITE_TAG_NAME}" --clobber ./*
