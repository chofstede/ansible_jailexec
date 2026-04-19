# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-04-19

This release is a ground-up refactor of the plugin. The external behavior is unchanged for correct configurations, but the implementation is roughly a quarter the size, inherits all options from Ansible's built-in `ssh` plugin, and ships with a much tighter test suite.

### Changed
- Plugin now subclasses `ansible.plugins.connection.ssh.Connection` and merges the live SSH plugin's options into its own `DOCUMENTATION` at import time. This keeps every SSH option (`ansible_ssh_port`, `ansible_ssh_private_key_file`, `ansible_ssh_common_args`, `ControlPersist`, jump hosts, `password_mechanism`, …) in sync with whichever `ansible-core` is installed.
- Jail-root resolution (`jls -j <name> path`) is now lazy: it runs on the first file transfer instead of at connect time, saving one round trip for exec-only workloads.
- `put_file` now completes in a single extra exec (`mkdir -p … && mv …`) instead of two.
- Every argument crossing the SSH wire is `shlex.quote`d through a shared helper; remote paths use `posixpath`.
- Error messages are now concise and actionable. See README "Common error messages".

### Added
- Plugin-specific options: `jail_name`, `jail_host`, `jail_user`, `privilege_escalation`. `privilege_escalation` is validated by Ansible's `choices` mechanism.
- Input validation: jail names match `^[A-Za-z0-9_][A-Za-z0-9._-]*$` and are length-capped at 255. Put/fetch paths reject any `..` component.
- Unit test suite with 62 tests and 100% coverage.
- `MANIFEST.in` so sdists include `README.md`, `LICENSE`, `CHANGELOG.md`, and tests.
- Bandit scan in CI.

### Removed
- Custom retry loop and ad-hoc SSH handling. The inherited SSH plugin's `ControlPersist` is sufficient.
- Hand-rolled connection pooling. Same rationale.
- `ansible_jail_remote_tmp` option. Staging uses a random `/tmp/ansible-jailexec-<hex>` name on the host; no knob is needed.

### Requirements
- Python 3.9+
- `ansible-core >= 2.14`

## [1.0.0] - 2025-08-01

Initial public release.
