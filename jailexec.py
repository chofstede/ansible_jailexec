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
            description:
                - Jail name. Defaults to the inventory hostname (not to
                  ansible_host, which is the address of the jail host).
            type: str
            vars:
                # Later entries win: an explicit ansible_jail_name overrides
                # the inventory_hostname default.
                - name: inventory_hostname
                - name: ansible_jail_name
        jail_host:
            description: Hostname or IP of the FreeBSD host that runs the jail.
            type: str
            required: true
            vars:
                - name: ansible_jail_host
        jail_root:
            description:
                - Deprecated and ignored since 2.0.0. File transfers now run
                  inside the jail via jexec, so the plugin no longer needs
                  the jail's on-host filesystem path.
                - Setting it produces a warning and has no other effect.
            type: str
            version_added: "1.2.0"
            vars:
                - name: ansible_jail_root
        jail_user:
            description:
                - User to run commands as inside the jail, resolved against
                  the jail's password database (``jexec -U``).
            type: str
            default: root
            vars:
                - name: ansible_jail_user
        privilege_escalation:
            description:
                - Command used on the jail host to run jexec as root.
                - Set to C(none) to invoke jexec directly with no wrapper.
                  Use this when you already SSH to the host as root (so no
                  doas/sudo is installed or needed).
            type: str
            default: doas
            choices: [doas, sudo, none]
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
PRIVESC_CHOICES = ("doas", "sudo", "none")
# /tmp is on the remote jail host, not the Ansible controller. File names are
# randomized via ``os.urandom`` in ``_staging_path``, which defeats
# predictable-name attacks. Bandit's B108 check is about local-tmp usage and
# does not apply.
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

    def _privesc_argv(self):
        """Argv prefix for privilege escalation; empty when set to ``none``.

        Hosts reached as root (e.g. via a hardware-backed key) often have no
        doas/sudo installed, so prepending one would fail with ``not found``.
        ``none`` runs jexec directly.
        """
        value = self.privesc
        return [] if value == "none" else [value]

    def _jexec_argv(self):
        """Shared ``[doas] jexec [-U user] <jail>`` prefix for remote calls.

        ``-U`` resolves the user against the *jail's* password database;
        ``-u`` would consult the host's, which is not what jail_user means.
        """
        argv = [*self._privesc_argv(), "jexec"]
        if self.jail_user != "root":
            argv += ["-U", self.jail_user]
        argv.append(self.jail_name)
        return argv

    # ---- connect / lifecycle --------------------------------------------

    def _connect(self):
        if self._connected:
            return self

        jail_host = (self.get_option("jail_host") or "").strip()
        if not jail_host:
            raise AnsibleConnectionFailure(
                f"ansible_jail_host is not set for jail {self.jail_name!r}"
            )
        if self.get_option("jail_root"):
            display.warning(
                "ansible_jail_root is deprecated and ignored: file transfers "
                "now run inside the jail via jexec, so the jail's on-host "
                "path is no longer needed."
            )
        # Redirect the inherited SSH plugin at the jail *host* instead of the
        # jail (inventory) name. This is the one hook we need -- everything
        # else comes from the SSH base class.
        self.set_option("host", jail_host)
        super()._connect()
        # SSH's _connect is a no-op on _connected, but ConnectionBase's
        # exec_command/put_file/fetch_file are wrapped with @ensure_connect,
        # which re-enters self._connect() whenever _connected is False. We
        # flip it here so the internal commands issued by put_file/fetch_file
        # (via super().exec_command) don't recurse into us.
        self._connected = True
        return self

    # ---- paths -----------------------------------------------------------

    @staticmethod
    def _in_jail_path(path):
        """Normalize to an absolute path as seen from inside the jail."""
        path = str(path or "")
        if not path.strip():
            raise AnsibleError("Path cannot be empty")
        ensure_no_traversal(path)
        return posixpath.normpath("/" + path.lstrip("/"))

    @staticmethod
    def _staging_path():
        return posixpath.join(STAGING_DIR, f"{STAGING_PREFIX}{os.urandom(12).hex()}")

    # ---- exec / transfer -------------------------------------------------

    def exec_command(self, cmd, in_data=None, sudoable=True):
        if not cmd or not str(cmd).strip():
            raise AnsibleError("Command cannot be empty")

        wrapped = _shelljoin(*self._jexec_argv(), "/bin/sh", "-c", cmd)

        display.vvv(f"jailexec: exec [{self.jail_name}]: {cmd}", host=self.jail_name)
        return super().exec_command(wrapped, in_data=in_data, sudoable=sudoable)

    def put_file(self, in_path, out_path):
        dest = self._in_jail_path(out_path)
        staged = self._staging_path()

        display.vvv(
            f"jailexec: put_file {in_path} -> jail:{out_path}", host=self.jail_name
        )
        super().put_file(in_path, staged)
        # The write happens *inside* the jail: jexec confines mkdir/cat to
        # the jail's root, so a symlink planted inside the jail cannot
        # redirect a privileged write onto a host path. The staged file is
        # handed over as stdin, opened host-side by the unprivileged SSH
        # login shell. Single extra round trip on the happy path.
        inner = (
            f"mkdir -p {shlex.quote(posixpath.dirname(dest))} && "
            f"cat > {shlex.quote(dest)}"
        )
        transfer = (
            f"{_shelljoin(*self._jexec_argv(), '/bin/sh', '-c', inner)}"
            f" < {shlex.quote(staged)} && rm -f {shlex.quote(staged)}"
        )
        # sudoable=False keeps the SSH layer from waiting for an Ansible
        # become prompt (and from allocating a tty) on plugin-internal
        # commands; same below.
        rc, _, stderr = super().exec_command(transfer, sudoable=False)
        if rc != 0:
            # Best-effort cleanup of the orphan staged file; ignore failures.
            super().exec_command(f"rm -f {shlex.quote(staged)}", sudoable=False)
            raise AnsibleError(
                f"put_file to jail:{out_path} failed: "
                f"{_decode(stderr).strip() or 'unknown error'}"
            )

    def fetch_file(self, in_path, out_path):
        src = self._in_jail_path(in_path)
        staged = self._staging_path()

        display.vvv(
            f"jailexec: fetch_file jail:{in_path} -> {out_path}", host=self.jail_name
        )
        # Mirror image of put_file: read inside the jail (symlinks cannot
        # leak host files, and root-only files are readable when jail_user
        # is root), stage on the host, then pull the staged copy over SFTP.
        # ``cat < src`` instead of an argument rules out option injection;
        # umask keeps the staged copy private to the SSH user.
        inner = f"cat < {shlex.quote(src)}"
        read = (
            f"umask 077; {_shelljoin(*self._jexec_argv(), '/bin/sh', '-c', inner)}"
            f" > {shlex.quote(staged)}"
        )
        rc, _, stderr = super().exec_command(read, sudoable=False)
        if rc != 0:
            super().exec_command(f"rm -f {shlex.quote(staged)}", sudoable=False)
            raise AnsibleError(
                f"fetch_file from jail:{in_path} failed: "
                f"{_decode(stderr).strip() or 'unknown error'}"
            )
        try:
            super().fetch_file(staged, out_path)
        finally:
            super().exec_command(f"rm -f {shlex.quote(staged)}", sudoable=False)
