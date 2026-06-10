# Ansible FreeBSD Jail Connection Plugin

[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![ansible-core: 2.14+](https://img.shields.io/badge/ansible--core-2.14+-red.svg)](https://docs.ansible.com/)
[![CI](https://github.com/chofstede/ansible_jailexec/workflows/CI/badge.svg)](https://github.com/chofstede/ansible_jailexec/actions)

An Ansible connection plugin that runs tasks **inside a FreeBSD jail** by SSH-ing to the jail host and wrapping every command in `jexec`. You do **not** need direct SSH access to the jail itself — the jail needs no sshd, no Python-over-SSH setup, no network address of its own.

The plugin inherits from Ansible's built-in `ssh` connection plugin, so every SSH option (control persist, jump hosts, key files, custom ports, etc.) works unchanged.

## Features

- **Inherits the full SSH plugin**: options are merged from the live `ssh` plugin at import time, so the plugin stays in sync with whichever `ansible-core` is installed.
- **Everything happens inside the jail**: commands *and file transfers* run through `jexec`, confined to the jail's chroot. A symlink planted inside a jail can never redirect a privileged write or read onto a host path.
- **Safe by construction**: jail names are validated, paths are traversal-checked and normalized, and every shell argument is `shlex.quote`d.
- **Minimal host footprint**: the SSH user needs a `doas`/`sudo` rule for exactly one command — `jexec`.
- **Zero extra round trips for exec-only workloads**: no probing at connect time; `put_file` costs a single extra exec.
- **`doas`, `sudo`, or `none`** for host-side privilege escalation around `jexec`.

## Demo

![Plugin in Action](screenshot.png)
*Executing Ansible tasks inside FreeBSD jails through the `jailexec` connection plugin.*

## How it works

For every task, the plugin opens a normal SSH session to the **jail host** (reusing ControlPersist connections like the stock `ssh` plugin) and runs:

```
doas jexec [-U <jail_user>] <jail_name> /bin/sh -c '<command>'
```

File transfers stage through the host and complete inside the jail:

- **put_file**: upload to a random `/tmp/ansible-jailexec-<hex>` name on the host via SFTP, then `doas jexec <jail> /bin/sh -c 'mkdir -p <dir> && cat > <dest>' < <staged>` — the write resolves entirely within the jail's filesystem namespace.
- **fetch_file**: `doas jexec <jail> /bin/sh -c 'cat < <src>' > <staged>` (staged copy created with `umask 077`), then download via SFTP and remove the staged copy.

## Requirements

- **Control machine**: Python 3.9+, `ansible-core >= 2.14`
- **Jail host**: FreeBSD with `jexec` available, and `doas` or `sudo` configured for the SSH user (not needed if you SSH in as root — see `ansible_jail_privilege_escalation=none`)
- **Jails**: must be running, with `/bin/sh` and `cat` available (both ship in the FreeBSD base system), plus Python for Ansible modules as usual

## Installation

### As a user plugin

```bash
curl -O https://raw.githubusercontent.com/chofstede/ansible_jailexec/main/jailexec.py
mkdir -p ~/.ansible/plugins/connection/
mv jailexec.py ~/.ansible/plugins/connection/
```

### As a project plugin

```bash
mkdir -p connection_plugins/
curl -o connection_plugins/jailexec.py \
     https://raw.githubusercontent.com/chofstede/ansible_jailexec/main/jailexec.py
```

Then point Ansible at it from `ansible.cfg`:

```ini
[defaults]
connection_plugins = ./connection_plugins
```

### Via pip

```bash
pip install ansible-jailexec
```

(Installs `jailexec.py` as a top-level module; Ansible's plugin loader will still need it under a `connection_plugins/` path, or set `ANSIBLE_CONNECTION_PLUGINS` to the install location.)

## Quick start

### 1. Inventory

```ini
[freebsd_jails]
web-jail  ansible_connection=jailexec  ansible_jail_host=jail-host.example.com
db-jail   ansible_connection=jailexec  ansible_jail_host=jail-host.example.com  ansible_jail_user=postgres
app-jail  ansible_connection=jailexec  ansible_jail_host=jail-host.example.com  ansible_ssh_port=30822
```

The inventory hostname (`web-jail`, `db-jail`, …) doubles as the jail name unless you override it with `ansible_jail_name`. Setting `ansible_host` does not affect the jail name — it is an SSH-level alias for the jail host's address, like `ansible_jail_host`.

### 2. Ping

```bash
ansible -i hosts.ini freebsd_jails -m ping
```

Expected:

```
web-jail | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```

### 3. Run tasks

```bash
ansible -i hosts.ini freebsd_jails -m ansible.builtin.command -a "uname -a"
ansible -i hosts.ini freebsd_jails -m community.general.pkgng -a "name=nginx state=present"
```

## Configuration reference

### Plugin-specific options

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ansible_jail_host` | ✅ | — | Hostname or IP of the FreeBSD host that runs the jail. |
| `ansible_jail_name` | | inventory hostname | Override the jail name if it differs from the inventory hostname. |
| `ansible_jail_user` | | `root` | User to run commands (and file transfers) as inside the jail, resolved against the **jail's** password database (`jexec -U`). |
| `ansible_jail_privilege_escalation` | | `doas` | Host-side privilege escalation for `jexec`. One of `doas`, `sudo`, `none`. Use `none` when you already SSH to the host as root and have no `doas`/`sudo`. |
| `ansible_jail_root` | | — | **Deprecated, ignored since 2.0.0.** Transfers run inside the jail via `jexec`, so the jail's on-host path is no longer needed. Setting it only produces a warning. |

### SSH options

The plugin inherits **every** option of the built-in `ssh` connection plugin — `ansible_ssh_port`, `ansible_ssh_private_key_file`, `ansible_ssh_common_args`, `ansible_ssh_extra_args`, `ControlPersist`, jump hosts, and so on.

For the full list, see:

```bash
ansible-doc -t connection ssh
```

### Privilege escalation: two independent layers

There are **two** places where privileges can be escalated, and it's easy to conflate them:

1. **`ansible_jail_privilege_escalation`** (this plugin) — runs `jexec` **on the host** as root so the plugin can enter the jail. Default: `doas`. Set it to `none` when the SSH user is already root on the host (so no `doas`/`sudo` is installed); the plugin then invokes `jexec` directly.
2. **Ansible `become`** (`become: yes`, `--become`, `ansible_become_method`) — runs the **task payload inside the jail** under a different user. Use this if `ansible_jail_user` is non-root and the task needs root inside the jail.

Typical setup: leave `ansible_jail_user=root` (the default) and skip `become` entirely; the plugin's own privilege escalation is already enough.

Note that with a non-root `ansible_jail_user`, file transfers also run as that user inside the jail — copying to root-owned locations then requires `become`, exactly as it would over plain SSH.

## FreeBSD host setup

The SSH user needs to run exactly one command as root: `jexec`.

Add it to `doas`:

```
# /usr/local/etc/doas.conf
permit nopass ansible as root cmd jexec
```

or to `sudoers` (edit with `visudo`):

```
ansible ALL=(root) NOPASSWD: /usr/sbin/jexec
```

> Upgrading from 1.x? The `jls`, `mkdir`, `mv`, and `rm` rules that earlier versions needed are no longer used and can be removed.

## Playbook example

```yaml
---
- name: Configure FreeBSD jails
  hosts: freebsd_jails
  gather_facts: true
  tasks:
    - name: Install nginx
      community.general.pkgng:
        name: nginx
        state: present

    - name: Ship configuration
      ansible.builtin.copy:
        src: nginx.conf
        dest: /usr/local/etc/nginx/nginx.conf
        backup: true
      notify: restart nginx

    - name: Enable and start nginx
      ansible.builtin.service:
        name: nginx
        state: started
        enabled: true

  handlers:
    - name: restart nginx
      ansible.builtin.service:
        name: nginx
        state: restarted
```

## Upgrading from 1.x

Version 2.0.0 moves all file transfers *inside* the jail (see [Security considerations](#security-considerations) and the [CHANGELOG](CHANGELOG.md)). For typical setups (`ansible_jail_user=root`) no inventory change is needed. Things to check:

- **doas/sudoers** can be trimmed to the single `jexec` rule shown above.
- **`ansible_jail_root`** is ignored (with a warning) — simply remove it; the path-mapping problem it worked around no longer exists.
- **`ansible_jail_user`** is now resolved in the *jail's* password database (`jexec -U`), as the documentation always promised. If you depended on the host's password database (`jexec -u` semantics), align the user accounts or use `become`.
- **Transfers run as `ansible_jail_user`**, no longer silently as root. Non-root jail users writing to root-owned paths need `become: yes`.

## Troubleshooting

Enable verbose mode:

```bash
ansible -vvv -i hosts.ini freebsd_jails -m ping
```

Plugin log lines are prefixed with `jailexec:`:

```
jailexec: exec [web-jail]: /bin/sh -c 'echo hi'
jailexec: put_file /local/nginx.conf -> jail:/usr/local/etc/nginx/nginx.conf
jailexec: fetch_file jail:/var/log/nginx/access.log -> /tmp/access.log
```

### Common error messages

| Message | Cause | Fix |
|---------|-------|-----|
| `ansible_jail_host is not set for jail 'X'` | Missing inventory variable. | Add `ansible_jail_host=<host>` to inventory. |
| `jexec: jail "X" not found` (in task stderr) | The jail isn't running, or the name is wrong. | `jls` on the host; `service jail onestart X`; check `ansible_jail_name`. |
| `doas: not found` / `sudo: not found` (exit 127) | No privilege-escalation helper on the host. | Install/configure `doas`, or set `ansible_jail_privilege_escalation=none` when SSH-ing in as root. |
| `doas: Operation not permitted` / `sudo: a password is required` | The SSH user has no (passwordless) rule for `jexec`. | Add the `doas.conf`/`sudoers` rule shown above. |
| `Invalid jail name 'X': …` | Jail name contains shell-unsafe characters or starts with `-`/`.`. | Rename, or use `ansible_jail_name` to override. |
| `Path contains '..' traversal: X` | A module tried to `put_file`/`fetch_file` with `..` in the path. | Use absolute paths without `..` segments. |
| `put_file to jail:X failed: …` | Writing inside the jail failed (permissions, read-only filesystem, full disk). | Check the path and `ansible_jail_user`'s rights inside the jail; use `become` for root-owned paths. |
| `fetch_file from jail:X failed: …` | Reading inside the jail failed (missing file, permissions). | Verify the path exists and is readable by `ansible_jail_user`. |
| `ansible_jail_root is deprecated and ignored` (warning) | Leftover 1.x inventory variable. | Remove `ansible_jail_root`; it is no longer needed. |

## Security considerations

- **Transfers are confined to the jail**: `put_file` and `fetch_file` execute `mkdir`/`cat` *inside* the jail via `jexec`, so all path resolution happens within the jail's chroot. A symlink planted inside a (potentially compromised) jail cannot redirect a privileged write or read to a host path. (Versions before 2.0.0 performed root-owned `mv` operations on host-side paths and were vulnerable to exactly that — upgrade.)
- **Input validation**: jail names are matched against `^[A-Za-z0-9_][A-Za-z0-9._-]*$` and length-capped at 255. Paths are rejected if any component is `..`, and are normalized to absolute in-jail paths.
- **Shell safety**: every argument crossing the SSH wire is `shlex.quote`d; the user-supplied command is the final argument to `/bin/sh -c` and is *not* further interpreted by the plugin. Fetched files are read with `cat < file` redirection, ruling out option injection.
- **File staging**: transfers stage in `/tmp` on the host under a random name (`ansible-jailexec-<hex>`, 96 bits of randomness). Fetched files are staged with `umask 077` so they are never world-readable; staged files are removed even when the transfer fails.
- **Minimal escalation surface**: the only command the SSH user runs via `doas`/`sudo` is `jexec`.
- **No new network ports**: everything rides the existing SSH connection, including control-persist reuse.
- **Internal plumbing never engages `become`**: plugin-internal commands run with `sudoable=False`, so they neither wait for become prompts nor allocate pseudo-terminals.

## Development

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run the test suite with coverage (gate: 100%)
pytest

# Format / lint / security scan (same as CI)
black jailexec.py tests/
isort jailexec.py tests/
flake8 jailexec.py --max-line-length=100 --extend-ignore=E203,W503
bandit -r jailexec.py
```

See [`tests/integration/README.md`](tests/integration/README.md) for end-to-end tests against a real FreeBSD host.

## License

BSD 2-Clause — see [LICENSE](LICENSE).

## Support

- Issues: https://github.com/chofstede/ansible_jailexec/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
