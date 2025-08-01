"""
Unit tests for jail-specific operations.

Tests jail verification, path transformation, jail root detection,
and other jail-specific functionality.
"""

import pytest
from unittest.mock import Mock, patch
from ansible.errors import AnsibleConnectionFailure, AnsibleError

# Import test utilities
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)


class TestJailVerification:
    """Test jail verification functionality."""
    
    def test_verify_jail_access_success(self, jail_connection, mock_ssh_connection, test_helper):
        """Test successful jail verification."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup successful jail verification
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j testjail': (0, b"testjail running", b"")
        })
        
        # Should not raise any exception
        jail_connection._verify_jail_access()
    
    def test_verify_jail_access_jail_not_found(self, jail_connection, mock_ssh_connection, test_helper):
        """Test jail verification when jail doesn't exist."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "nonexistent"
        jail_connection.privilege_escalation = "doas"
        
        # Setup jail not found response
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j nonexistent': (1, b"", b"No such jail: nonexistent"),
            'doas jls -h name': (0, b"jail1\njail2\ntestjail", b"")
        })
        
        with pytest.raises(AnsibleConnectionFailure, match="not found"):
            jail_connection._verify_jail_access()
    
    def test_verify_jail_access_permission_denied(self, jail_connection, mock_ssh_connection, test_helper):
        """Test jail verification with permission denied."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup permission denied response
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j testjail': (1, b"", b"Permission denied")
        })
        
        with pytest.raises(AnsibleConnectionFailure, match="Permission denied"):
            jail_connection._verify_jail_access()
    
    def test_verify_jail_access_no_ssh_connection(self, jail_connection):
        """Test jail verification without SSH connection."""
        jail_connection._host_connection = None
        
        with pytest.raises(AnsibleConnectionFailure, match="No SSH connection available"):
            jail_connection._verify_jail_access()
    
    def test_verify_jail_access_command_execution_fails(self, jail_connection, mock_ssh_connection, test_helper):
        """Test jail verification when command execution itself fails."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Make exec_command raise an exception
        mock_ssh_connection.exec_command = Mock(side_effect=Exception("SSH failure"))
        
        with pytest.raises(AnsibleConnectionFailure, match="Failed to execute jail verification command"):
            jail_connection._verify_jail_access()
    
    def test_verify_jail_access_with_retry(self, jail_connection, mock_ssh_connection, test_helper):
        """Test jail verification retry logic."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # First call fails, second succeeds
        call_count = 0
        def exec_command_side_effect(cmd):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (1, b"", b"Temporary failure")
            return (0, b"testjail running", b"")
        
        mock_ssh_connection.exec_command = Mock(side_effect=exec_command_side_effect)
        
        # Should succeed after retry
        jail_connection._verify_jail_access()
        
        assert call_count == 2


class TestPathTransformation:
    """Test path transformation functionality."""
    
    def test_transform_path_home_directory(self, jail_connection):
        """Test transformation of home directory paths."""
        jail_connection.remote_tmp = "/tmp/.ansible/tmp"
        
        # Test various home directory formats
        test_cases = [
            ("~/file.txt", "/tmp/.ansible/tmp/file.txt"),
            ("~user/file.txt", "/tmp/.ansible/tmp/file.txt"),
            ("~root/config", "/tmp/.ansible/tmp/config"),
            ("/absolute/~/path", "/absolute/~/path"),  # Only leading ~ should transform
        ]
        
        for input_path, expected in test_cases:
            result = jail_connection._transform_path(input_path)
            assert result == expected
    
    def test_transform_path_empty_input(self, jail_connection):
        """Test path transformation with empty input."""
        result = jail_connection._transform_path("")
        assert result == ""
        
        result = jail_connection._transform_path(None)
        assert result is None
    
    def test_transform_path_security_validation(self, jail_connection):
        """Test that path transformation validates security."""
        jail_connection.remote_tmp = "/tmp/.ansible/tmp"
        
        # Test dangerous paths are rejected
        dangerous_paths = [
            "../etc/passwd",
            "~/../../etc/shadow",
            "~user/$(malicious)",
            "~root/path|pipe"
        ]
        
        for path in dangerous_paths:
            with pytest.raises(AnsibleError, match="dangerous pattern"):
                jail_connection._transform_path(path)
    
    def test_transform_path_preserves_safe_paths(self, jail_connection, safe_paths):
        """Test that safe paths are preserved correctly."""
        jail_connection.remote_tmp = "/tmp/.ansible/tmp"
        
        for path in safe_paths:
            # Should not raise any exception
            result = jail_connection._transform_path(path)
            # Result should be a string
            assert isinstance(result, str)


class TestJailRootDetection:
    """Test jail root directory detection."""
    
    def test_get_jail_root_success(self, jail_connection, mock_ssh_connection, test_helper):
        """Test successful jail root detection."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup successful jail root detection
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j testjail path': (0, b"/jail/testjail\n", b"")
        })
        
        result = jail_connection._get_jail_root()
        
        assert result == "/jail/testjail"
        # Should be cached
        assert jail_connection._jail_root_cache == "/jail/testjail"
    
    def test_get_jail_root_cached(self, jail_connection, mock_ssh_connection):
        """Test that jail root is returned from cache when available."""
        jail_connection._jail_root_cache = "/cached/jail/root"
        jail_connection._host_connection = mock_ssh_connection
        
        result = jail_connection._get_jail_root()
        
        assert result == "/cached/jail/root"
        # Should not have made any SSH calls
        mock_ssh_connection.exec_command.assert_not_called() if hasattr(mock_ssh_connection.exec_command, 'assert_not_called') else None
    
    def test_get_jail_root_command_fails(self, jail_connection, mock_ssh_connection, test_helper):
        """Test jail root detection when command fails."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup failed jail root detection
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j testjail path': (1, b"", b"Jail not found")
        })
        
        with pytest.raises(AnsibleError, match="Could not determine jail root path"):
            jail_connection._get_jail_root()
    
    def test_get_jail_root_empty_response(self, jail_connection, mock_ssh_connection, test_helper):
        """Test jail root detection with empty response."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup empty response
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j testjail path': (0, b"", b"")
        })
        
        with pytest.raises(AnsibleError, match="Empty jail root path"):
            jail_connection._get_jail_root()
    
    def test_get_jail_root_multiline_response(self, jail_connection, mock_ssh_connection, test_helper):
        """Test jail root detection with multiline response."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup multiline response (should take first line)
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j testjail path': (0, b"/jail/testjail\nextra line\n", b"")
        })
        
        result = jail_connection._get_jail_root()
        
        assert result == "/jail/testjail"


class TestOutputDecoding:
    """Test output decoding functionality."""
    
    def test_decode_output_bytes(self, jail_connection):
        """Test decoding bytes output."""
        byte_output = b"test output"
        result = jail_connection._decode_output(byte_output)
        assert result == "test output"
        assert isinstance(result, str)
    
    def test_decode_output_string(self, jail_connection):
        """Test decoding string output (passthrough)."""
        string_output = "test output"
        result = jail_connection._decode_output(string_output)
        assert result == "test output"
        assert isinstance(result, str)
    
    def test_decode_output_unicode_bytes(self, jail_connection):
        """Test decoding unicode bytes."""
        unicode_bytes = "test ütf-8 output".encode('utf-8')
        result = jail_connection._decode_output(unicode_bytes)
        assert result == "test ütf-8 output"
    
    def test_decode_output_invalid_bytes(self, jail_connection):
        """Test decoding invalid bytes with error handling."""
        invalid_bytes = b'\xff\xfe\xfd'  # Invalid UTF-8
        result = jail_connection._decode_output(invalid_bytes)
        # Should not raise exception, should replace invalid characters
        assert isinstance(result, str)
        assert len(result) > 0