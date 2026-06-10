"""Tests for connection lifecycle and properties."""

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

    def test_connect_issues_no_remote_commands(self, make_conn):
        """Connect must stay free of extra SSH round trips."""
        conn = make_conn()
        conn._connect()
        assert conn._connected is True
        conn.ssh_exec.assert_not_called()

    def test_close_delegates_to_ssh(self, make_conn):
        conn = make_conn()
        conn._connect()
        conn.close()
        conn.ssh_close_mock.assert_called_once()


class TestJailRootDeprecation:
    """``ansible_jail_root`` is obsolete: transfers run inside the jail now."""

    @pytest.fixture
    def warnings(self, monkeypatch):
        import jailexec

        captured = []
        monkeypatch.setattr(
            jailexec.display, "warning", lambda msg, **kw: captured.append(msg)
        )
        return captured

    def test_setting_jail_root_warns_and_still_connects(self, make_conn, warnings):
        conn = make_conn({"jail_root": "/mnt/jails/web"})
        conn._connect()
        assert conn._connected is True
        assert any("ansible_jail_root is deprecated" in w for w in warnings)

    def test_no_warning_when_unset(self, make_conn, warnings):
        conn = make_conn()
        conn._connect()
        assert warnings == []


class TestProperties:
    def test_jail_name_from_inventory(self, make_conn):
        conn = make_conn(remote_addr="blog")
        assert conn.jail_name == "blog"

    def test_jail_name_override(self, make_conn):
        conn = make_conn({"jail_name": "explicit"}, remote_addr="ignored")
        assert conn.jail_name == "explicit"

    def test_jail_name_is_inventory_hostname_not_ansible_host(self, make_conn):
        """Regression: with ``ansible_host`` set, remote_addr is the host's
        address, and the plugin used to run ``jexec <ip>`` instead of using
        the inventory hostname as the jail name."""
        conn = make_conn(remote_addr="192.0.2.10")
        conn.set_options(
            var_options={
                "ansible_jail_host": "192.0.2.10",
                "inventory_hostname": "wiki",
            }
        )
        assert conn.jail_name == "wiki"

    def test_explicit_jail_name_beats_inventory_hostname(self, make_conn):
        conn = make_conn()
        conn.set_options(
            var_options={
                "ansible_jail_host": "jail-host.example.com",
                "inventory_hostname": "wiki",
                "ansible_jail_name": "blog",
            }
        )
        assert conn.jail_name == "blog"

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

    def test_privesc_none(self, make_conn):
        conn = make_conn({"privilege_escalation": "none"})
        assert conn.privesc == "none"

    def test_privesc_argv_empty_when_none(self, make_conn):
        conn = make_conn({"privilege_escalation": "none"})
        assert conn._privesc_argv() == []

    def test_privesc_argv_wraps_when_set(self, make_conn):
        assert make_conn().privesc == "doas"
        assert make_conn()._privesc_argv() == ["doas"]

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

    def test_privesc_runtime_guard(self, make_conn, monkeypatch):
        """Runtime guard must fire even if ``set_option`` accepted the value.

        On ansible-core >= 2.20, ``set_option`` rejects out-of-choices values
        before they land. This test bypasses that layer to exercise the
        defense-in-depth raise inside the ``privesc`` property, which covers
        ansible-core < 2.20 where choices enforcement is deferred.
        """
        conn = make_conn()
        monkeypatch.setattr(conn, "get_option", lambda name: "su")
        with pytest.raises(
            AnsibleConnectionFailure, match="Invalid privilege_escalation"
        ):
            _ = conn.privesc
