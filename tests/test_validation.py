"""Tests for the pure validation helpers."""

from __future__ import annotations

import pytest
from ansible.errors import AnsibleConnectionFailure, AnsibleError

from jailexec import (
    JAIL_NAME_RE,
    _decode,
    ensure_no_traversal,
    validate_jail_name,
    validate_jail_root,
)


class TestValidateJailName:
    @pytest.mark.parametrize(
        "name",
        [
            "jail",
            "web-01",
            "db_01",
            "jail.01",
            "_underscore_leading",
            "0starts-with-digit",
            "a" * 255,
        ],
    )
    def test_valid(self, name):
        assert validate_jail_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "   ",
            "\t\n",
            None,
            "-leading-hyphen",
            ".leading-dot",
            "has space",
            "has;semi",
            "has|pipe",
            "has$dollar",
            "has`tick",
            "has(paren)",
            "../escape",
            "a" * 256,
        ],
    )
    def test_invalid(self, name):
        with pytest.raises(AnsibleConnectionFailure):
            validate_jail_name(name)

    def test_strips_whitespace(self):
        assert validate_jail_name("  jail  ") == "jail"


class TestEnsureNoTraversal:
    @pytest.mark.parametrize(
        "path",
        [
            "",
            None,
            "/tmp/foo",
            "/tmp/foo..bar",  # .. as substring, not a path component
            "relative/path",
            "/a/b/c..d/e",
        ],
    )
    def test_ok(self, path):
        ensure_no_traversal(path)

    @pytest.mark.parametrize(
        "path",
        [
            "../etc/passwd",
            "/tmp/../etc",
            "a/b/../../c",
            "..",
        ],
    )
    def test_rejected(self, path):
        with pytest.raises(AnsibleError, match="traversal"):
            ensure_no_traversal(path)


def test_jail_name_regex_pattern():
    # Sanity check of the regex itself.
    assert JAIL_NAME_RE.match("abc-123.test_ok")
    assert not JAIL_NAME_RE.match("-bad")
    assert not JAIL_NAME_RE.match(".bad")


class TestValidateJailRoot:
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("/jail/web", "/jail/web"),
            ("  /jail/web  ", "/jail/web"),
            ("/jail/web/", "/jail/web"),
            ("/jail//web", "/jail/web"),
            ("/", "/"),
        ],
    )
    def test_valid(self, path, expected):
        assert validate_jail_root(path) == expected

    @pytest.mark.parametrize("path", ["", "   ", None])
    def test_empty_rejected(self, path):
        with pytest.raises(AnsibleConnectionFailure, match="cannot be empty"):
            validate_jail_root(path)

    @pytest.mark.parametrize("path", ["relative/path", "jail/web", "./jail"])
    def test_relative_rejected(self, path):
        with pytest.raises(AnsibleConnectionFailure, match="absolute path"):
            validate_jail_root(path)

    @pytest.mark.parametrize("path", ["/jail/../etc", "/../escape", "/a/b/../c"])
    def test_traversal_rejected(self, path):
        with pytest.raises(AnsibleError, match="traversal"):
            validate_jail_root(path)


class TestDecode:
    def test_none_becomes_empty_string(self):
        assert _decode(None) == ""

    def test_bytes_are_utf8_decoded(self):
        assert _decode(b"hello\n") == "hello\n"

    def test_bytes_with_invalid_utf8_do_not_raise(self):
        # Replacement characters keep the pipeline moving instead of crashing
        # on malformed output from jls/doas.
        decoded = _decode(b"\xff\xfeok")
        assert decoded.endswith("ok")

    def test_str_passes_through(self):
        assert _decode("already a str") == "already a str"
