"""Pytest fixtures for the jailexec plugin tests.

The plugin inherits from Ansible's SSH connection plugin, so most tests work
by creating a Connection via the plugin loader and patching the SSH base
class's network-touching methods (``_connect``, ``exec_command``,
``put_file``, ``fetch_file``) at the class level.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Make the plugin importable from tests/ without installation.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("ANSIBLE_CONNECTION_PLUGINS", ROOT)


@pytest.fixture
def make_conn():
    """Factory that returns a Connection with SSH I/O stubbed out.

    The factory accepts an optional dict of option overrides (e.g. jail_host,
    jail_user, ...). The returned connection has a ``ssh_exec`` MagicMock
    that records every call the plugin delegates to the SSH base class.
    """
    from ansible.playbook.play_context import PlayContext
    from ansible.plugins.connection.ssh import Connection as SSHConnection
    from ansible.plugins.loader import connection_loader

    import jailexec

    created = []

    def _make(options=None, remote_addr="testjail"):
        ssh_exec = MagicMock(return_value=(0, b"/jail/testjail\n", b""))
        ssh_put = MagicMock(return_value=None)
        ssh_fetch = MagicMock(return_value=None)
        ssh_close = MagicMock(return_value=None)
        ssh_connect_mock = MagicMock()

        # Our _connect marks the session connected itself (SSH's _connect is
        # a no-op in ansible-core 2.20+); mirror that here so the idempotent-
        # connect guard behaves like it does at runtime. We keep a MagicMock
        # alongside for call-count assertions.
        def _fake_connect(self):
            self._connected = True
            ssh_connect_mock(self)

        patches = [
            patch.object(SSHConnection, "exec_command", ssh_exec),
            patch.object(SSHConnection, "put_file", ssh_put),
            patch.object(SSHConnection, "fetch_file", ssh_fetch),
            patch.object(SSHConnection, "_connect", _fake_connect),
            patch.object(SSHConnection, "close", ssh_close),
        ]
        for p in patches:
            p.start()
            created.append(p)

        pc = PlayContext()
        pc.remote_addr = remote_addr
        conn = connection_loader.get("jailexec", pc, None)
        conn.set_option("jail_host", "jail-host.example.com")
        for k, v in (options or {}).items():
            conn.set_option(k, v)

        conn.ssh_exec = ssh_exec
        conn.ssh_put = ssh_put
        conn.ssh_fetch = ssh_fetch
        conn.ssh_connect_mock = ssh_connect_mock
        conn.ssh_close_mock = ssh_close
        return conn

    yield _make

    for p in created:
        p.stop()
