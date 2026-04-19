"""Tests for connection lifecycle, properties, and jail-root resolution."""

from __future__ import annotations

import pytest
from ansible.errors import AnsibleConnectionFailure


class TestConnect:
    def test_redirects_ssh_to_jail_host(self, make_conn):
        conn = make_conn({"jail_host": "jail.example"})
        conn._connect()
        assert conn.get_option("host") == "jail.example"
        conn.ssh_connect_mock.assert_called_once()

    def test_missing_jail_host_errors(self, make_conn):
        conn = make_conn()
        conn.set_option("jail_host", "  ")
        with pytest.raises(AnsibleConnectionFailure, match="ansible_jail_host"):
            conn._connect()

    def test_connect_is_idempotent(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn._connect()
        conn.ssh_connect_mock.assert_called_once()

    def test_connect_does_not_probe_eagerly(self, make_conn):
        """Regression: connect must not issue an SSH round trip.

        The jail-root probe is deferred until the first file operation so that
        exec-only workloads don't pay for the lookup and so that probing can't
        recurse through ``@ensure_connect``.
        """
        conn = make_conn()
        conn._connect()
        assert conn._connected is True
        assert conn._jail_root is None
        conn.ssh_exec.assert_not_called()

    def test_close_resets_cache(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn._jail_root = "/jail/testjail"
        conn.close()
        assert conn._jail_root is None
        conn.ssh_close_mock.assert_called_once()


class TestJailRootProbe:
    def test_caches_across_calls(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn.ssh_exec.return_value = (0, b"/jail/testjail\n", b"")

        assert conn._resolve_jail_root() == "/jail/testjail"
        assert conn._resolve_jail_root() == "/jail/testjail"
        conn.ssh_exec.assert_called_once()

    def test_uses_privesc_and_jail_name(self, make_conn):
        conn = make_conn(
            {"privilege_escalation": "sudo", "jail_name": "blog"},
        )
        conn._connect()
        conn.ssh_exec.return_value = (0, b"/jails/blog\n", b"")

        conn._resolve_jail_root()

        cmd = conn.ssh_exec.call_args.args[0]
        assert cmd == "sudo jls -j blog path"

    def test_missing_jail_fails_clearly(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn.ssh_exec.return_value = (1, b"", b"jls: jail not found\n")
        with pytest.raises(AnsibleConnectionFailure, match="Cannot access jail"):
            conn._resolve_jail_root()

    def test_empty_root_fails(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn.ssh_exec.return_value = (0, b"", b"")
        with pytest.raises(AnsibleConnectionFailure, match="no filesystem root"):
            conn._resolve_jail_root()

    def test_whitespace_only_root_fails(self, make_conn):
        """Regression: ``b"\\n"`` used to IndexError before the fix."""
        conn = make_conn()
        conn._connect()
        conn.ssh_exec.return_value = (0, b"\n", b"")
        with pytest.raises(AnsibleConnectionFailure, match="no filesystem root"):
            conn._resolve_jail_root()


class TestProperties:
    def test_jail_name_from_inventory(self, make_conn):
        conn = make_conn(remote_addr="blog")
        assert conn.jail_name == "blog"

    def test_jail_name_override(self, make_conn):
        conn = make_conn({"jail_name": "explicit"}, remote_addr="ignored")
        assert conn.jail_name == "explicit"

    def test_jail_user_default(self, make_conn):
        assert make_conn().jail_user == "root"

    def test_jail_user_blank_falls_back_to_root(self, make_conn):
        conn = make_conn({"jail_user": "   "})
        assert conn.jail_user == "root"

    def test_privesc_default(self, make_conn):
        assert make_conn().privesc == "doas"

    def test_privesc_sudo(self, make_conn):
        conn = make_conn({"privilege_escalation": "sudo"})
        assert conn.privesc == "sudo"

    def test_privesc_invalid_is_rejected(self, make_conn):
        """Bad ``privilege_escalation`` values must never reach a shell.

        ansible-core >= 2.20 raises AnsibleOptionsError inside ``set_option``
        for values outside ``choices``; older versions defer the check, so the
        plugin validates again when reading ``self.privesc``. Either layer is
        fine -- as long as one of them refuses to hand back ``"su"``.
        """
        from ansible.errors import AnsibleOptionsError

        conn = make_conn()
        try:
            conn.set_option("privilege_escalation", "su")
        except AnsibleOptionsError:
            return  # ansible-core >= 2.20 path
        with pytest.raises(
            AnsibleConnectionFailure, match="Invalid privilege_escalation"
        ):
            _ = conn.privesc
