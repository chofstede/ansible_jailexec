# Security Advisory: jail escape via symlink in `put_file` (fixed in 2.0.0)

| | |
|---|---|
| **Affected** | `ansible-jailexec` (the `jailexec` connection plugin), all releases `< 2.0.0` |
| **Fixed in** | `2.0.0` |
| **Severity** | High |
| **CWE** | CWE-59 (Improper Link Resolution Before File Access / symlink following), CWE-61 |
| **Vector (CVSS 3.1)** | `AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H` (scope-changed: jail → host) |

## Summary

Through version 1.3.0, the plugin's `put_file` implementation resolved a transfer's
destination to a path on the **jail host** (`<jail filesystem root> + <destination>`)
and then created directories and moved the staged file into place by running, **as
root on the host**:

```
doas jexec ...        # NO — exec went through jexec, but the transfer did not:
doas mkdir -p <jail_root>/<dir>
doas mv <staged> <jail_root>/<dest>
```

`mkdir` and `mv` resolve symbolic links. Because the path was assembled and operated
on **outside** the jail, a symlink that exists **inside** the jail's filesystem was
followed by the host-side, root-privileged `mv`. A user who controls content inside a
jail (the jail's own root, or any process able to create a symlink in a directory an
Ansible task later writes to) could therefore cause a privileged write to an arbitrary
path on the **host**, outside the jail.

This breaks the core guarantee of the plugin: that tasks are confined to the target
jail.

## Impact

An attacker with control over a jail managed by this plugin can escalate to arbitrary
**host** file writes as root, and (in 2.0.0's corrected read path, by analogy in older
versions wherever a privileged read occurred) influence what is read. Arbitrary
root-owned writes on the host are readily escalated to full host compromise (e.g.
writing to `/etc/crontab`, `/usr/local/etc/rc.d`, an `authorized_keys` file, etc.).

Preconditions:
- The operator runs a playbook with a `copy`/`template`/`fetch`-style task (anything
  using `put_file`) targeting the jail.
- The attacker can place a symlink inside the jail at or above the task's destination
  path before the transfer runs.

## The fix (2.0.0)

File transfers now run **inside** the jail through `jexec`, so every path is resolved
within the jail's chroot and cannot reference the host filesystem:

- `put_file`: `jexec <jail> /bin/sh -c 'mkdir -p <dir> && cat > <dest>' < <staged>`
- `fetch_file`: `jexec <jail> /bin/sh -c 'cat < <src>' > <staged>`, then download

A symlink inside the jail can at most redirect the write/read to another location
**inside the same jail** — which the jail's own user already controls — and can no
longer reach the host.

## Workarounds

There is no configuration-level workaround in affected versions; upgrade to 2.0.0.
As defense in depth, treat any jail as untrusted and avoid running file-transfer tasks
against jails you do not fully control until upgraded.

## Remediation

Upgrade to `ansible-jailexec >= 2.0.0`. For the common `ansible_jail_user=root`
configuration no inventory changes are required; see the README "Upgrading from 1.x"
section. Host-side `doas`/`sudo` rules can be reduced to a single `jexec` entry.

## Credit

Found during a security review of the plugin.

## Timeline

- 2026-06-10 — Issue identified during code review; fix developed and released as 2.0.0.
