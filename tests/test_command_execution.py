"""Tests for exec_command command wrapping."""

from __future__ import annotations

import shlex

import pytest
from ansible.errors import AnsibleError


def _last_exec_cmd(conn):
    """Return the command string from the most recent SSH exec_command call."""
    args, _ = conn.ssh_exec.call_args
    return args[0]


class TestExecWrapping:
    def test_wraps_string_command(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn.ssh_exec.reset_mock()
        conn.ssh_exec.return_value = (0, b"hi\n", b"")

        conn.exec_command("echo hi")

        cmd = _last_exec_cmd(conn)
        parts = shlex.split(cmd)
        assert parts == ["doas", "jexec", "testjail", "/bin/sh", "-c", "echo hi"]

    def test_includes_jail_user_when_not_root(self, make_conn):
        conn = make_conn({"jail_user": "postgres"})
        conn._connect()
        conn.ssh_exec.reset_mock()

        conn.exec_command("psql -l")

        parts = shlex.split(_last_exec_cmd(conn))
        assert parts == [
            "doas",
            "jexec",
            "-u",
            "postgres",
            "testjail",
            "/bin/sh",
            "-c",
            "psql -l",
        ]

    def test_uses_sudo_when_configured(self, make_conn):
        conn = make_conn({"privilege_escalation": "sudo"})
        conn._connect()
        conn.ssh_exec.reset_mock()

        conn.exec_command("true")

        parts = shlex.split(_last_exec_cmd(conn))
        assert parts[0] == "sudo"

    def test_empty_command_rejected(self, make_conn):
        conn = make_conn()
        conn._connect()
        with pytest.raises(AnsibleError, match="Command cannot be empty"):
            conn.exec_command("")
        with pytest.raises(AnsibleError, match="Command cannot be empty"):
            conn.exec_command("   \t\n")

    def test_forwards_in_data_and_sudoable(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn.ssh_exec.reset_mock()

        conn.exec_command("cat", in_data=b"payload", sudoable=False)

        _, kw = conn.ssh_exec.call_args
        assert kw == {"in_data": b"payload", "sudoable": False}

    def test_allows_shell_metacharacters_in_cmd(self, make_conn):
        """Regression: the old plugin rejected any '..' in commands."""
        conn = make_conn()
        conn._connect()
        conn.ssh_exec.reset_mock()
        conn.ssh_exec.return_value = (0, b"", b"")

        # All of these should pass through unchanged as the argument to sh -c.
        for cmd in ["ls ..", "make test && echo ok", "echo $HOME", "find .. -name x"]:
            conn.exec_command(cmd)
            parts = shlex.split(_last_exec_cmd(conn))
            assert parts[-1] == cmd
