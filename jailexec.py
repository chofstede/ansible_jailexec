#!/usr/bin/env python3
# Copyright (c) 2025 Christian Hofstede-Kuhn <christian@hofstede.it>
# SPDX-License-Identifier: BSD-2-Clause

"""FreeBSD jail connection plugin for Ansible.

Opens an SSH session to a FreeBSD jail host (inheriting Ansible's built-in
ssh connection plugin) and wraps every command with ``jexec`` so Ansible
operates *inside* the target jail without needing direct SSH access to it.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex

import yaml
from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.plugins.connection import ssh as _ssh_module
from ansible.plugins.connection.ssh import Connection as SSHConnection
from ansible.utils.display import Display

display = Display()

# Static stub so ``ansible-doc -t connection jailexec`` can read the plugin
# (ansible-doc parses the source file as AST and only understands literal
# strings). The full option set is built below and assigned over the top via
# ``globals()`` -- the AST walker only inspects ``ast.Assign`` nodes with a
# simple Name target, so a plain function-call *expression* statement is
# invisible to it. At runtime, the plugin loader reads the merged version.
DOCUMENTATION = """
    name: jailexec
    short_description: Execute tasks in FreeBSD jails via jexec over SSH
    description:
        - Opens an SSH session to a FreeBSD jail host and wraps every command
          with jexec so Ansible runs inside the target jail without needing
          direct SSH into the jail.
        - Inherits all options from the built-in ssh connection plugin.
    author: Christian Hofstede-Kuhn <christian@hofstede.it>
    version_added: "1.1.0"
    options:
        jail_name:
            description: Jail name. Defaults to the inventory hostname.
            type: str
            vars:
                - name: ansible_jail_name
        jail_host:
            description: Hostname or IP of the FreeBSD host that runs the jail.
            type: str
            required: true
            vars:
                - name: ansible_jail_host
        jail_root:
            description:
                - Absolute on-host filesystem path of the jail, used as the
                  base for put_file and fetch_file.
                - If unset, the plugin probes the host with
                  ``jls -j <name> path`` on the first file transfer.
                - Set this for nested or VNET jail setups where the probe
                  does not return the expected path.
            type: str
            version_added: "1.2.0"
            vars:
                - name: ansible_jail_root
        jail_user:
            description: User to run commands as inside the jail.
            type: str
            default: root
            vars:
                - name: ansible_jail_user
        privilege_escalation:
            description: Command used on the jail host to run jexec as root.
            type: str
            default: doas
            choices: [doas, sudo]
            vars:
                - name: ansible_jail_privilege_escalation
"""


def _extend_with_ssh_options(doc):
    """Merge SSH plugin options into our DOCUMENTATION at import time.

    Pulling options from the live SSH plugin (rather than freezing a copy)
    keeps us in sync with whichever ansible-core version is installed; newer
    ansible-core releases have added options (e.g. ``password_mechanism``)
    that older snapshots didn't know about, and a frozen list would cause
    ``get_option`` to return None and trigger type errors downstream.
    """
    ssh_doc = yaml.safe_load(_ssh_module.DOCUMENTATION) or {}
    our_doc = yaml.safe_load(doc) or {}
    merged = dict(ssh_doc.get("options") or {})
    merged.update(our_doc.get("options") or {})
    our_doc["options"] = merged
    return yaml.safe_dump(our_doc, sort_keys=False)


globals().update(DOCUMENTATION=_extend_with_ssh_options(DOCUMENTATION))


MAX_JAIL_NAME_LENGTH = 255
JAIL_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
PRIVESC_CHOICES = ("doas", "sudo")
# /tmp is on the remote jail host, not the Ansible controller. File names are
# randomized via ``os.urandom`` in ``put_file``, which defeats predictable-name
# attacks. Bandit's B108 check is about local-tmp usage and does not apply.
STAGING_DIR = "/tmp"  # nosec B108
STAGING_PREFIX = "ansible-jailexec-"


def validate_jail_name(name):
    """Reject empty, overlong, or shell-unsafe jail names."""
    if not name or not str(name).strip():
        raise AnsibleConnectionFailure("Jail name cannot be empty")
    name = str(name).strip()
    if len(name) > MAX_JAIL_NAME_LENGTH:
        raise AnsibleConnectionFailure(
            f"Jail name too long (max {MAX_JAIL_NAME_LENGTH}): {name!r}"
        )
    if not JAIL_NAME_RE.match(name):
        raise AnsibleConnectionFailure(
            f"Invalid jail name {name!r}: must start with a letter, digit or "
            "underscore and contain only letters, digits, dots, underscores "
            "or hyphens."
        )
    return name


def ensure_no_traversal(path):
    """Reject paths containing a ``..`` component (path traversal)."""
    if path and ".." in path.replace("\\", "/").split("/"):
        raise AnsibleError(f"Path contains '..' traversal: {path}")


def validate_jail_root(path):
    """Normalize and validate a user-provided jail-root override.

    Must be a non-empty absolute POSIX path without any ``..`` components.
    """
    path = (path or "").strip()
    if not path:
        raise AnsibleConnectionFailure("ansible_jail_root cannot be empty")
    if not path.startswith("/"):
        raise AnsibleConnectionFailure(
            f"ansible_jail_root must be an absolute path, got {path!r}"
        )
    ensure_no_traversal(path)
    return posixpath.normpath(path)


def _decode(data):
    """Return ``data`` as a str. Bytes are decoded leniently; None becomes ''."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def _shelljoin(*argv):
    """Shell-join a command + args safely for transport over SSH."""
    return " ".join(shlex.quote(str(a)) for a in argv)


class Connection(SSHConnection):
    """SSH to a jail host, run commands inside the jail via jexec."""

    transport = "jailexec"
    has_pipelining = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._jail_root = None

    # ---- options ---------------------------------------------------------

    @property
    def jail_name(self):
        name = self.get_option("jail_name") or self._play_context.remote_addr
        return validate_jail_name(name)

    @property
    def jail_user(self):
        # Normalize None / blank / whitespace-only to "root".
        return (self.get_option("jail_user") or "").strip() or "root"

    @property
    def privesc(self):
        # ansible-core >= 2.20 rejects off-``choices`` values at ``set_option``
        # time; older releases defer the check, so validate here too.
        value = self.get_option("privilege_escalation")
        if value not in PRIVESC_CHOICES:
            raise AnsibleConnectionFailure(
                f"Invalid privilege_escalation {value!r}: "
                f"must be one of {', '.join(PRIVESC_CHOICES)}"
            )
        return value

    # ---- connect / lifecycle --------------------------------------------

    def _connect(self):
        if self._connected:
            return self

        jail_host = (self.get_option("jail_host") or "").strip()
        if not jail_host:
            raise AnsibleConnectionFailure(
                f"ansible_jail_host is not set for jail {self.jail_name!r}"
            )
        # Redirect the inherited SSH plugin at the jail *host* instead of the
        # jail (inventory) name. This is the one hook we need -- everything
        # else comes from the SSH base class.
        self.set_option("host", jail_host)
        super()._connect()
        # SSH's _connect is a no-op on _connected, but ConnectionBase's
        # exec_command/put_file/fetch_file are wrapped with @ensure_connect,
        # which re-enters self._connect() whenever _connected is False. We
        # flip it here so the jail-root probe issued on first file op (via
        # super().exec_command) doesn't recurse into us.
        self._connected = True
        return self

    def close(self):
        self._jail_root = None
        super().close()

    # ---- jail metadata ---------------------------------------------------

    def _resolve_jail_root(self):
        """Look up and cache the on-host filesystem path of the jail.

        If ``ansible_jail_root`` is set, that value is used verbatim and no
        SSH probe happens. Otherwise the path is resolved via
        ``jls -j <name> path`` on the first file operation, then cached.
        """
        if self._jail_root:
            return self._jail_root

        override = self.get_option("jail_root")
        if override:
            self._jail_root = validate_jail_root(override)
            display.vvv(
                f"jailexec: jail {self.jail_name!r} root is {self._jail_root} "
                "(from ansible_jail_root)",
                host=self.jail_name,
            )
            return self._jail_root

        name = self.jail_name
        rc, stdout, stderr = super().exec_command(
            _shelljoin(self.privesc, "jls", "-j", name, "path")
        )
        if rc != 0:
            msg = _decode(stderr).strip() or "jail not found or inaccessible"
            raise AnsibleConnectionFailure(f"Cannot access jail {name!r}: {msg}")
        lines = _decode(stdout).strip().splitlines()
        root = lines[0].strip() if lines else ""
        if not root:
            raise AnsibleConnectionFailure(
                f"Jail {name!r} returned no filesystem root (is it running?)"
            )
        self._jail_root = root
        display.vvv(f"jailexec: jail {name!r} root is {root}", host=name)
        return root

    def _jail_path(self, path):
        """Map a path inside the jail to its absolute path on the host."""
        ensure_no_traversal(path)
        root = self._resolve_jail_root()
        return posixpath.normpath(posixpath.join(root, path.lstrip("/")))

    # ---- exec / transfer -------------------------------------------------

    def exec_command(self, cmd, in_data=None, sudoable=True):
        if not cmd or not str(cmd).strip():
            raise AnsibleError("Command cannot be empty")

        argv = [self.privesc, "jexec"]
        if self.jail_user != "root":
            argv += ["-u", self.jail_user]
        argv += [self.jail_name, "/bin/sh", "-c", cmd]
        wrapped = _shelljoin(*argv)

        display.vvv(f"jailexec: exec [{self.jail_name}]: {cmd}", host=self.jail_name)
        return super().exec_command(wrapped, in_data=in_data, sudoable=sudoable)

    def put_file(self, in_path, out_path):
        dest = self._jail_path(out_path)
        dest_dir = posixpath.dirname(dest)
        staged = posixpath.join(STAGING_DIR, f"{STAGING_PREFIX}{os.urandom(12).hex()}")

        display.vvv(
            f"jailexec: put_file {in_path} -> jail:{out_path}", host=self.jail_name
        )
        super().put_file(in_path, staged)
        # Single round-trip: mkdir + move. Both go through privilege
        # escalation because the destination lives inside the jail root,
        # which is typically only writable by root on the host.
        pe = shlex.quote(self.privesc)
        move = (
            f"{pe} mkdir -p {shlex.quote(dest_dir)} && "
            f"{pe} mv {shlex.quote(staged)} {shlex.quote(dest)}"
        )
        rc, _, stderr = super().exec_command(move)
        if rc != 0:
            # Best-effort cleanup of the orphan staged file; ignore failures.
            super().exec_command(f"rm -f {shlex.quote(staged)}")
            raise AnsibleError(
                f"put_file to jail:{out_path} failed: "
                f"{_decode(stderr).strip() or 'unknown error'}"
            )

    def fetch_file(self, in_path, out_path):
        src = self._jail_path(in_path)
        display.vvv(
            f"jailexec: fetch_file jail:{in_path} -> {out_path}", host=self.jail_name
        )
        super().fetch_file(src, out_path)
