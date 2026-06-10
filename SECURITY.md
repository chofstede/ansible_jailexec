# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | ✅ |
| < 2.0   | ❌ (contains a known jail-escape vulnerability, see below) |

## Reporting a vulnerability

Please report security issues **privately**, not via public issues or pull requests:

- Preferred: open a private report through GitHub Security Advisories
  ([Report a vulnerability](https://github.com/chofstede/ansible_jailexec/security/advisories/new)).
- Alternatively, email the maintainer at `christian@hofstede.it`.

Please include enough detail to reproduce (plugin version, `ansible-core` version,
inventory shape, and the behavior observed). You will receive an acknowledgement, and
we will coordinate a fix and disclosure timeline with you.

## Known advisories

- **< 2.0.0: jail escape via symlink in `put_file`.** File transfers resolved paths on
  the host and performed root-owned `mv` operations that followed symlinks placed inside
  a jail, allowing arbitrary root-owned writes on the host. Fixed in 2.0.0 by performing
  all transfers inside the jail via `jexec`. See
  [`docs/security/advisory-2.0.0-jail-escape.md`](docs/security/advisory-2.0.0-jail-escape.md).
