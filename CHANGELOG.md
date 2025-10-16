# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/edera-dev/styrolite/releases/tag/v0.1.1) - 2025-10-16

### Added

- add automation for release and publish
- add ci for actions and code
- add dependabot
- add cargo makefile
- add helper scripts for CI
- allow users to specify a config without a mount namespace

### Fixed

- adopt rust edition 2024 and fix clippy

### Other

- address zizmor findings
- *(fmt)* format autofix.sh
- *(deps)* update deps and bump rust to v1.89.0
- pin rust toolchain to 1.88.0
- format to rust 1.88.0 specifications
- update dependencies and bump version to 0.1.1
- Merge pull request #5 from bleggett/bleggett/skip-pointless-setid-warn
- Don't change uid/gid if we're already there
- add styrolite logo asset
- format code with rust 2024
- run cargo fmt
- add Apache-2.0 license
- add README
- initial commit
