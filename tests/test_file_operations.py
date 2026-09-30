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

STAGING = r"/tmp/ansible-jailexec-[0-9a-f]{24}"
STAGED = rf"{STAGING}/payload"


def _connected(make_conn, options=None):
    conn = make_conn(options)
    conn._connect()
    conn.ssh_exec.reset_mock()
    return conn


def _assert_cleanup(call, staging):
    assert call.args[0] == f"rm -rf {staging}"
    assert call.kwargs == {"sudoable": False}


class TestPutFile:
    def test_stages_in_private_dir_then_writes_inside_jail(self, make_conn):
        conn = _connected(make_conn)

        conn.put_file("/local/foo", "/etc/foo.conf")

        # exec (private staging dir) + put (sftp) + exec (jexec cat + rm).
        conn.ssh_put.assert_called_once()
        assert conn.ssh_exec.call_count == 2

        mkdir_call, transfer_call = conn.ssh_exec.call_args_list
        m = re.fullmatch(rf"umask 077 && mkdir ({STAGING})", mkdir_call.args[0])
        assert m, mkdir_call.args[0]
        staging = m.group(1)

        # The upload goes *into* the 0700 directory, never bare into /tmp.
        in_path, staged = conn.ssh_put.call_args.args
        assert in_path == "/local/foo"
        assert staged == f"{staging}/payload"

        assert transfer_call.args[0] == (
            "doas jexec testjail /bin/sh -c "
            "'mkdir -p /etc && cat > /etc/foo.conf' "
            f"< {staged} && rm -rf {staging}"
        )
        # Internal commands must not engage become prompt handling.
        assert mkdir_call.kwargs == {"sudoable": False}
        assert transfer_call.kwargs == {"sudoable": False}

    def test_staging_dir_is_created_before_upload(self, make_conn):
        conn = _connected(make_conn)
        order = []
        conn.ssh_exec.side_effect = lambda cmd, **kw: (
            order.append(("exec", cmd.split()[0])) or (0, b"", b"")
        )
        conn.ssh_put.side_effect = lambda *a, **kw: order.append(("put", None))

        conn.put_file("/local/foo", "/etc/foo.conf")

        assert order == [("exec", "umask"), ("put", None), ("exec", "doas")]

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
        conn.ssh_exec.assert_not_called()

    def test_staging_dir_failure_aborts_before_upload(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_exec.side_effect = [(1, b"", b"mkdir: File exists")]

        with pytest.raises(AnsibleError, match="staging directory .*File exists"):
            conn.put_file("/local/x", "/etc/foo")

        # Never upload into a directory we did not create ourselves.
        conn.ssh_put.assert_not_called()
        assert conn.ssh_exec.call_count == 1

    def test_cleans_up_on_upload_failure(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_put.side_effect = AnsibleError("sftp blew up")

        with pytest.raises(AnsibleError, match="sftp blew up"):
            conn.put_file("/local/x", "/etc/foo")

        assert conn.ssh_exec.call_count == 2
        staging = conn.ssh_put.call_args.args[1].rsplit("/", 1)[0]
        _assert_cleanup(conn.ssh_exec.call_args_list[-1], staging)

    def test_cleans_up_on_write_failure(self, make_conn):
        conn = _connected(make_conn)
        # mkdir succeeds, jexec cat fails, cleanup rm succeeds.
        conn.ssh_exec.side_effect = [
            (0, b"", b""),
            (1, b"", b"cat: permission denied"),
            (0, b"", b""),
        ]

        with pytest.raises(AnsibleError, match="put_file .* failed"):
            conn.put_file("/local/x", "/etc/foo")

        assert conn.ssh_exec.call_count == 3
        staging = conn.ssh_put.call_args.args[1].rsplit("/", 1)[0]
        _assert_cleanup(conn.ssh_exec.call_args_list[-1], staging)


class TestFetchFile:
    def test_reads_inside_jail_into_private_dir_then_fetches(self, make_conn):
        conn = _connected(make_conn)

        conn.fetch_file("/etc/hosts", "/local/hosts")

        # 1 exec (mkdir + jexec cat -> staging) + 1 fetch (sftp) + 1 cleanup.
        assert conn.ssh_exec.call_count == 2

        read_call = conn.ssh_exec.call_args_list[0]
        m = re.fullmatch(
            rf"umask 077 && mkdir ({STAGING}) && doas jexec testjail /bin/sh -c "
            r"'cat < /etc/hosts' > (\S+)",
            read_call.args[0],
        )
        assert m, read_call.args[0]
        staging, staged = m.groups()
        assert staged == f"{staging}/payload"
        assert read_call.kwargs == {"sudoable": False}

        conn.ssh_fetch.assert_called_once_with(staged, "/local/hosts")
        _assert_cleanup(conn.ssh_exec.call_args_list[1], staging)

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
            rf"rm -rf {STAGING}", conn.ssh_exec.call_args_list[-1].args[0]
        )

    def test_staging_removed_even_if_sftp_fetch_fails(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_fetch.side_effect = AnsibleError("sftp blew up")

        with pytest.raises(AnsibleError, match="sftp blew up"):
            conn.fetch_file("/etc/hosts", "/local/hosts")

        assert re.fullmatch(
            rf"rm -rf {STAGING}", conn.ssh_exec.call_args_list[-1].args[0]
        )

    def test_rejects_traversal(self, make_conn):
        conn = _connected(make_conn)
        with pytest.raises(AnsibleError, match="traversal"):
            conn.fetch_file("/etc/../shadow", "/local/x")
        conn.ssh_exec.assert_not_called()


class TestHostTransport:
    """``ssh_transfer_method=piped`` moves data via ``self.exec_command``.

    Those calls must reach the *host* unwrapped; routed through jexec, the
    staged file would land in the jail's /tmp (world-readable and never
    cleaned up) and the host-side transfer step would fail.
    """

    def test_piped_put_runs_dd_on_host(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_put.side_effect = lambda in_path, out_path: conn.exec_command(
            f"dd of={out_path} bs=65536", in_data=b"secret", sudoable=False
        )

        conn.put_file("/local/x", "/etc/foo")

        mkdir_call, dd_call, transfer_call = conn.ssh_exec.call_args_list
        staged = conn.ssh_put.call_args.args[1]
        assert dd_call.args[0] == f"dd of={staged} bs=65536"
        assert dd_call.kwargs == {"in_data": b"secret", "sudoable": False}

    def test_piped_fetch_runs_dd_on_host(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_fetch.side_effect = lambda in_path, out_path: conn.exec_command(
            f"dd if={in_path} bs=65536", sudoable=False
        )

        conn.fetch_file("/etc/hosts", "/local/hosts")

        staged = conn.ssh_fetch.call_args.args[0]
        assert conn.ssh_exec.call_args_list[1].args[0] == f"dd if={staged} bs=65536"

    def test_exec_is_wrapped_again_after_transfer(self, make_conn):
        conn = _connected(make_conn)
        conn.ssh_put.side_effect = AnsibleError("sftp blew up")
        with pytest.raises(AnsibleError):
            conn.put_file("/local/x", "/etc/foo")
        conn.ssh_exec.reset_mock()

        conn.exec_command("id")

        assert conn.ssh_exec.call_args.args[0] == "doas jexec testjail /bin/sh -c id"
