# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-06-10

**Security release, upgrading is strongly recommended.** The file-transfer mechanism was rewritten to run inside the jail and the release was verified end-to-end against a real FreeBSD 15.0 jail host (`tests/integration/smoke-test.yml`).

### Security
- **Closed a jail-escape vector in file transfers.** `put_file` used to run `mkdir -p` and `mv` **on the host**, as root, against `<jail root>/<destination>`. Because those commands resolve symlinks, a compromised jail could plant a symlink (e.g. its `/usr/local/etc` pointing at the host's `/etc`) and turn any playbook copy through that path into a root-owned write to an arbitrary host file. Transfers now execute **inside** the jail (`jexec <jail> /bin/sh -c 'mkdir -p ... && cat > dest' < staged-file`), so every path resolves within the jail's chroot and cannot reach the host filesystem. `fetch_file` reads through `jexec` the same way.

### Fixed
- The default jail name is now the **inventory hostname**, as documented. Previously it fell back to the connection address, so an inventory line like `web ansible_host=192.0.2.10 ...` ran `jexec "192.0.2.10"` and failed with `jexec: jail "192.0.2.10" not found`. An explicit `ansible_jail_name` still wins.
- The bundled integration-test files were stale: `test-inventory.ini.example` used `ansible_host` instead of the required `ansible_jail_host` and set `ansible_become=yes` globally (which needs doas *inside* the jail); `smoke-test.yml` referenced facts with `gather_facts: no`. The smoke test now also round-trips a file through `put_file`/`slurp`/`fetch_file`.
- `ansible_jail_user` is now passed as `jexec -U` (resolved in the **jail's** password database) instead of `-u` (the **host's**). Previously a user like `postgres` that exists only inside the jail failed with `jexec: : unknown user`, and a same-named host user with a different UID ran with the wrong credentials.
- `fetch_file` now goes through privilege escalation. Previously it pulled the file over SFTP as the plain SSH user from the host-side path, so files readable only by root inside the jail could not be fetched at all.
- Plugin-internal commands (transfer plumbing, staging cleanup) now pass `sudoable=False` to the SSH layer. With `become: yes` plus a become password, the SSH plugin used to wait for a privilege-escalation prompt that never appears on these internal commands and timed out; this also stops them from allocating an unnecessary `-tt` pseudo-terminal.

### Changed
- **Transfers now run as `ansible_jail_user` inside the jail** instead of always as root on the host. This matches the standard connection-plugin contract (transferred files are owned by the connection user, and permission fix-ups work). If you relied on copying to root-owned paths while `ansible_jail_user` was non-root, add `become: yes` to those tasks.
- **Host-side privilege requirements shrank to `jexec` alone.** The `jls`, `mkdir`, `mv`, and `rm` doas/sudo rules are no longer used and can be removed from `doas.conf`/`sudoers`.
- The jail-root probe (`jls -j <name> path`) is gone entirely; the plugin issues zero extra round trips before the first task regardless of workload.
- `fetch_file` stages through the host (created with `umask 077`) and costs two extra round trips compared to 1.x; `put_file` round trips are unchanged.
- Jails must provide `/bin/sh` and `cat` (both are part of the FreeBSD base system; `exec_command` already required `/bin/sh`).

### Deprecated
- `ansible_jail_root` is now ignored and produces a warning when set. The on-host jail path is no longer used for anything, and the nested/VNET-jail probe problem it worked around (#4) no longer exists.

## [1.3.0] - 2026-06-05

### Added
- `none` choice for `ansible_jail_privilege_escalation`. When set, the plugin invokes `jls`/`jexec`/`mkdir`/`mv`/`rm` directly with no `doas`/`sudo` wrapper. Use it when you already SSH to the jail host as root and have no privilege-escalation helper installed; previously the hardcoded `doas`/`sudo` prefix failed with `doas: not found` (exit 127), surfacing as a misleading "Failed to create temporary directory" error. Reported in #3.

## [1.2.0] - 2026-04-19

### Added
- `ansible_jail_root` option to override the on-host filesystem path of the jail instead of probing it with `jls -j <name> path`. Useful for nested or VNET jail setups where the probe returns an unexpected path. Thanks to @grisuthedragon for suggesting the feature in #4.

## [1.1.0] - 2026-04-19

This release is a ground-up refactor of the plugin. The external behavior is unchanged for correct configurations, but the implementation is roughly a quarter the size, inherits all options from Ansible's built-in `ssh` plugin, and ships with a much tighter test suite.

### Changed
- Plugin now subclasses `ansible.plugins.connection.ssh.Connection` and merges the live SSH plugin's options into its own `DOCUMENTATION` at import time. This keeps every SSH option (`ansible_ssh_port`, `ansible_ssh_private_key_file`, `ansible_ssh_common_args`, `ControlPersist`, jump hosts, `password_mechanism`, ...) in sync with whichever `ansible-core` is installed.
- Jail-root resolution (`jls -j <name> path`) is now lazy: it runs on the first file transfer instead of at connect time, saving one round trip for exec-only workloads.
- `put_file` now completes in a single extra exec (`mkdir -p ... && mv ...`) instead of two.
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
