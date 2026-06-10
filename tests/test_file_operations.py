"""Tests for put_file / fetch_file.

Transfers run *inside* the jail (``jexec ... /bin/sh -c 'cat ...'``) with the
host-side staging file wired up via shell redirection. This keeps privileged
writes/reads confined to the jail's chroot, so symlinks planted inside the
jail cannot redirect them onto host paths.
"""

from __future__ import annotations

import re

import pytest
from ansible.errors import AnsibleError

STAGED = r"/tmp/ansible-jailexec-[0-9a-f]+"


def _connected(make_conn, options=None):
    conn = make_conn(options)
    conn._connect()
    conn.ssh_exec.reset_mock()
    return conn


class TestPutFile:
    def test_stages_then_writes_inside_jail_in_one_round_trip(self, make_conn):
        conn = _connected(make_conn)

        conn.put_file("/local/foo", "/etc/foo.conf")

        # 1 put_file (sftp) + 1 exec_command (jexec mkdir + cat + rm).
        conn.ssh_put.assert_called_once()
        assert conn.ssh_exec.call_count == 1

        in_path, staged = conn.ssh_put.call_args.args
        assert in_path == "/local/foo"
        assert re.fullmatch(STAGED, staged)

        cmd = conn.ssh_exec.call_args.args[0]
        m = re.fullmatch(
            r"doas jexec testjail /bin/sh -c "
            r"'mkdir -p /etc && cat > /etc/foo\.conf' "
            rf"< ({STAGED}) && rm -f \1",
            cmd,
        )
        assert m, cmd
        # stdin is wired to the very file that was staged.
        assert m.group(1) == staged
        # Internal commands must not engage become prompt handling.
        assert conn.ssh_exec.call_args.kwargs == {"sudoable": False}

    def test_nonroot_jail_user_writes_as_that_user(self, make_conn):
        conn = _connected(make_conn, {"jail_user": "postgres"})

        conn.put_file("/local/foo", "/var/db/foo")

        cmd = conn.ssh_exec.call_args.args[0]
        assert "doas jexec -U postgres testjail" in cmd

    def test_none_privesc_omits_wrapper(self, make_conn):
        conn = _connected(make_conn, {"privilege_escalation": "none"})

        conn.put_file("/local/foo", "/etc/foo.conf")

        cmd = conn.ssh_exec.call_args.args[0]
        assert cmd.startswith("jexec testjail ")
        assert "doas" not in cmd and "sudo" not in cmd

    def test_relative_dest_is_rooted_at_jail_root(self, make_conn):
        conn = _connected(make_conn)

        conn.put_file("/local/x", "etc/foo")

        cmd = conn.ssh_exec.call_args.args[0]
        assert "cat > /etc/foo" in cmd

    def test_quotes_unsafe_destination_paths(self, make_conn):
        import shlex

        conn = _connected(make_conn)

        conn.put_file("/local/x", "/etc/with space/foo;rm")

        # Unwrap the outer quoting; the in-jail script must quote both paths.
        tokens = shlex.split(conn.ssh_exec.call_args.args[0])
        assert tokens[:5] == ["doas", "jexec", "testjail", "/bin/sh", "-c"]
        assert tokens[5] == (
            "mkdir -p '/etc/with space' && cat > '/etc/with space/foo;rm'"
        )

    def test_rejects_traversal(self, make_conn):
        conn = _connected(make_conn)
        with pytest.raises(AnsibleError, match="traversal"):
            conn.put_file("/local/x", "/etc/../foo")
        conn.ssh_put.assert_not_called()

    def test_cleans_up_on_write_failure(self, make_conn):
        conn = _connected(make_conn)
        # First call (jexec cat) fails; second (cleanup rm) succeeds.
        conn.ssh_exec.side_effect = [
            (1, b"", b"cat: permission denied"),
            (0, b"", b""),
        ]

        with pytest.raises(AnsibleError, match="put_file .* failed"):
            conn.put_file("/local/x", "/etc/foo")

        assert conn.ssh_exec.call_count == 2
        rm_call = conn.ssh_exec.call_args_list[-1]
        assert re.fullmatch(rf"rm -f {STAGED}", rm_call.args[0])
        assert rm_call.kwargs == {"sudoable": False}


class TestFetchFile:
    def test_reads_inside_jail_then_fetches_staged_copy(self, make_conn):
        conn = _connected(make_conn)

        conn.fetch_file("/etc/hosts", "/local/hosts")

        # 1 exec (jexec cat -> staging) + 1 fetch (sftp) + 1 exec (cleanup).
        assert conn.ssh_exec.call_count == 2

        read_call = conn.ssh_exec.call_args_list[0]
        m = re.fullmatch(
            r"umask 077; doas jexec testjail /bin/sh -c "
            rf"'cat < /etc/hosts' > ({STAGED})",
            read_call.args[0],
        )
        assert m, read_call.args[0]
        assert read_call.kwargs == {"sudoable": False}

        conn.ssh_fetch.assert_called_once_with(m.group(1), "/local/hosts")
        assert conn.ssh_exec.call_args_list[1].args[0] == f"rm -f {m.group(1)}"

    def test_fetch_honors_jail_user(self, make_conn):
        conn = _connected(make_conn, {"jail_user": "www"})

        conn.fetch_file("/var/log/nginx/access.log", "/local/access.log")

        read_cmd = conn.ssh_exec.call_args_list[0].args[0]
        assert "doas jexec -U www testjail" in read_cmd

    def test_read_failure_cleans_staging_and_raises(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_exec.side_effect = [
            (1, b"", b"cat: /nope: No such file or directory"),
            (0, b"", b""),
        ]

        with pytest.raises(AnsibleError, match="fetch_file .* failed"):
            conn.fetch_file("/nope", "/local/x")

        conn.ssh_fetch.assert_not_called()
        assert re.fullmatch(
            rf"rm -f {STAGED}", conn.ssh_exec.call_args_list[-1].args[0]
        )

    def test_staging_removed_even_if_sftp_fetch_fails(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_fetch.side_effect = AnsibleError("sftp blew up")

        with pytest.raises(AnsibleError, match="sftp blew up"):
            conn.fetch_file("/etc/hosts", "/local/hosts")

        assert re.fullmatch(
            rf"rm -f {STAGED}", conn.ssh_exec.call_args_list[-1].args[0]
        )

    def test_rejects_traversal(self, make_conn):
        conn = _connected(make_conn)
        with pytest.raises(AnsibleError, match="traversal"):
            conn.fetch_file("/etc/../shadow", "/local/x")
        conn.ssh_exec.assert_not_called()
