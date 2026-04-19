"""Tests for put_file / fetch_file."""

from __future__ import annotations

import re
import shlex

import pytest
from ansible.errors import AnsibleError


def _connect_with_cached_root(make_conn, options=None):
    """Open a connection and pre-seed the jail-root cache.

    The jail-root probe is lazy -- it fires on the first file op. Tests that
    are *only* about file-op round-trip shape want to pin the root so the
    probe doesn't show up in assertions about call counts / commands.
    """
    conn = make_conn(options)
    conn._connect()
    conn._jail_root = "/jail/testjail"
    conn.ssh_exec.reset_mock()
    return conn


class TestPutFile:
    def test_stages_then_moves_in_one_round_trip(self, make_conn):
        conn = _connect_with_cached_root(make_conn)
        conn.ssh_exec.return_value = (0, b"", b"")

        conn.put_file("/local/foo", "/etc/foo.conf")

        # 1 put_file (scp) + 1 exec_command (mkdir && mv)
        conn.ssh_put.assert_called_once()
        assert conn.ssh_exec.call_count == 1

        in_path, staged = conn.ssh_put.call_args.args
        assert in_path == "/local/foo"
        assert re.match(r"/tmp/ansible-jailexec-[0-9a-f]+$", staged)

        move_cmd = conn.ssh_exec.call_args.args[0]
        # Both halves use privilege escalation and target the jail root.
        assert "doas mkdir -p /jail/testjail/etc" in move_cmd
        assert "doas mv" in move_cmd
        assert "/jail/testjail/etc/foo.conf" in move_cmd

    def test_probes_jail_root_on_first_file_op(self, make_conn):
        """First file op pays the probe cost; subsequent ones don't."""
        conn = make_conn()
        conn._connect()
        # jls probe then mkdir+mv.
        conn.ssh_exec.side_effect = [
            (0, b"/jail/testjail\n", b""),
            (0, b"", b""),
        ]

        conn.put_file("/local/foo", "/etc/foo.conf")

        assert conn.ssh_exec.call_count == 2
        assert conn.ssh_exec.call_args_list[0].args[0] == "doas jls -j testjail path"
        assert conn._jail_root == "/jail/testjail"

    def test_rejects_traversal(self, make_conn):
        conn = _connect_with_cached_root(make_conn)
        with pytest.raises(AnsibleError, match="traversal"):
            conn.put_file("/local/x", "/etc/../foo")

    def test_cleans_up_on_move_failure(self, make_conn):
        conn = _connect_with_cached_root(make_conn)
        # First call (mkdir+mv) fails; second (cleanup rm) succeeds.
        conn.ssh_exec.side_effect = [
            (1, b"", b"mv: permission denied"),
            (0, b"", b""),
        ]

        with pytest.raises(AnsibleError, match="put_file .* failed"):
            conn.put_file("/local/x", "/etc/foo")

        assert conn.ssh_exec.call_count == 2
        assert "rm -f" in conn.ssh_exec.call_args_list[-1].args[0]


class TestFetchFile:
    def test_single_round_trip(self, make_conn):
        conn = _connect_with_cached_root(make_conn)
        conn.ssh_fetch.reset_mock()

        conn.fetch_file("/etc/hosts", "/local/hosts")

        conn.ssh_fetch.assert_called_once_with(
            "/jail/testjail/etc/hosts", "/local/hosts"
        )
        # No extra exec_command round-trips (no test -f pre-check).
        conn.ssh_exec.assert_not_called()

    def test_rejects_traversal(self, make_conn):
        conn = _connect_with_cached_root(make_conn)
        with pytest.raises(AnsibleError, match="traversal"):
            conn.fetch_file("/etc/../shadow", "/local/x")
