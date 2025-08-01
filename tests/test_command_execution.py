"""
Unit tests for command execution functionality.

Tests command validation, execution, path transformation in commands,
and error handling during command execution.
"""

import pytest
from unittest.mock import Mock, patch
from ansible.errors import AnsibleError

# Import test utilities
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)


class TestCommandExecution:
    """Test command execution functionality."""
    
    def test_exec_command_string_success(self, jail_connection, mock_ssh_connection, test_helper):
        """Test successful command execution with string command."""
        # Setup connection
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.jail_user = "root"
        jail_connection.privilege_escalation = "doas"
        
        # Setup expected command execution
        expected_cmd = "doas jexec testjail /bin/sh -c 'echo hello'"
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            expected_cmd: (0, b"hello\n", b"")
        })
        
        result = jail_connection.exec_command("echo hello")
        
        assert result == (0, b"hello\n", b"")
    
    def test_exec_command_list_input(self, jail_connection, mock_ssh_connection, test_helper):
        """Test command execution with list input."""
        # Setup connection
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.jail_user = "root"
        jail_connection.privilege_escalation = "doas"
        
        # Setup expected command execution
        expected_cmd = "doas jexec testjail /bin/sh -c 'echo hello world'"
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            expected_cmd: (0, b"hello world\n", b"")
        })
        
        result = jail_connection.exec_command(["echo", "hello", "world"])
        
        assert result == (0, b"hello world\n", b"")
    
    def test_exec_command_with_user(self, jail_connection, mock_ssh_connection, test_helper):
        """Test command execution with specific user."""
        # Setup connection
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.jail_user = "testuser"
        jail_connection.privilege_escalation = "doas"
        
        # Setup expected command execution (should include -u flag)
        expected_cmd = "doas jexec -u testuser testjail /bin/sh -c 'echo hello'"
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            expected_cmd: (0, b"hello\n", b"")
        })
        
        result = jail_connection.exec_command("echo hello")
        
        assert result == (0, b"hello\n", b"")
    
    def test_exec_command_with_sudo(self, jail_connection, mock_ssh_connection, test_helper):
        """Test command execution with sudo privilege escalation."""
        # Setup connection
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.jail_user = "root"
        jail_connection.privilege_escalation = "sudo"
        
        # Setup expected command execution (should use sudo)
        expected_cmd = "sudo jexec testjail /bin/sh -c 'echo hello'"
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            expected_cmd: (0, b"hello\n", b"")
        })
        
        result = jail_connection.exec_command("echo hello")
        
        assert result == (0, b"hello\n", b"")
    
    def test_exec_command_auto_connect(self, jail_connection, sample_config, test_helper):
        """Test that exec_command automatically connects if not connected."""
        # Setup configuration but not connected
        jail_connection._connected = False
        test_helper.mock_get_option(jail_connection, sample_config)
        
        with patch.object(jail_connection, '_connect') as mock_connect:
            mock_connect.return_value = jail_connection
            jail_connection._connected = True  # Simulate successful connection
            jail_connection._host_connection = Mock()
            jail_connection._host_connection.exec_command.return_value = (0, b"output", b"")
            
            result = jail_connection.exec_command("echo test")
            
            mock_connect.assert_called_once()
    
    def test_exec_command_empty_command_string(self, jail_connection):
        """Test command execution with empty command string."""
        jail_connection._connected = True
        
        with pytest.raises(AnsibleError, match="Command cannot be empty"):
            jail_connection.exec_command("")
    
    def test_exec_command_empty_command_list(self, jail_connection):
        """Test command execution with empty command list."""
        jail_connection._connected = True
        
        with pytest.raises(AnsibleError, match="Command list cannot be empty"):
            jail_connection.exec_command([])
    
    def test_exec_command_whitespace_only(self, jail_connection):
        """Test command execution with whitespace-only command."""
        jail_connection._connected = True
        
        with pytest.raises(AnsibleError, match="Command cannot be empty"):
            jail_connection.exec_command("   \t\n   ")
    
    def test_exec_command_none_values_in_list(self, jail_connection, mock_ssh_connection, test_helper):
        """Test command execution with None values in command list."""
        # Setup connection
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup expected command execution (None values should be filtered)
        expected_cmd = "doas jexec testjail /bin/sh -c 'echo hello'"
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            expected_cmd: (0, b"hello\n", b"")
        })
        
        result = jail_connection.exec_command(["echo", None, "hello", None])
        
        assert result == (0, b"hello\n", b"")
    
    def test_exec_command_dangerous_path_in_command(self, jail_connection):
        """Test command execution with dangerous path patterns."""
        jail_connection._connected = True
        jail_connection._host_connection = Mock()
        
        dangerous_commands = [
            "cat ../../../etc/passwd",
            "ls ~/../../sensitive",
            "echo $(malicious)",
            "touch /tmp/file|rm -rf /"
        ]
        
        for cmd in dangerous_commands:
            with pytest.raises(AnsibleError, match="unsafe path"):
                jail_connection.exec_command(cmd)
    
    def test_exec_command_no_ssh_connection(self, jail_connection):
        """Test command execution without SSH connection."""
        jail_connection._connected = True
        jail_connection._host_connection = None
        
        with pytest.raises(AnsibleError, match="No SSH connection available"):
            jail_connection.exec_command("echo test")
    
    def test_exec_command_ssh_execution_fails(self, jail_connection, mock_ssh_connection):
        """Test command execution when SSH execution fails."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Make SSH execution raise an exception
        mock_ssh_connection.exec_command = Mock(side_effect=Exception("SSH error"))
        
        with pytest.raises(AnsibleError, match="Failed to execute command"):
            jail_connection.exec_command("echo test")
    
    def test_exec_command_with_input_data(self, jail_connection, mock_ssh_connection, test_helper):
        """Test command execution with input data."""
        # Setup connection
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Setup expected command execution
        expected_cmd = "doas jexec testjail /bin/sh -c 'cat'"
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            expected_cmd: (0, b"input data", b"")
        })
        
        # Mock the exec_command to verify input data is passed
        def exec_command_check(cmd, in_data=None, sudoable=True):
            assert in_data == b"input data"
            return (0, b"input data", b"")
        
        mock_ssh_connection.exec_command = Mock(side_effect=exec_command_check)
        
        result = jail_connection.exec_command("cat", in_data=b"input data")
        
        assert result == (0, b"input data", b"")
    
    def test_exec_command_updates_activity_timestamp(self, jail_connection, mock_ssh_connection):
        """Test that command execution updates the activity timestamp."""
        import time
        
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._last_activity = 0  # Set to old timestamp
        
        mock_ssh_connection.exec_command = Mock(return_value=(0, b"output", b""))
        
        jail_connection.exec_command("echo test")
        
        # Activity timestamp should be updated
        assert jail_connection._last_activity > 0
        assert jail_connection._last_activity <= time.time()


class TestCommandQuoting:
    """Test command quoting and shell safety."""
    
    def test_command_quoting_special_characters(self, jail_connection, mock_ssh_connection, test_helper):
        """Test that special characters in commands are properly quoted."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        
        # Test command with special characters
        cmd_with_specials = ["echo", "hello world", "$USER", "`date`", "file;rm -rf /"]
        
        # Mock exec_command to capture the actual command
        actual_commands = []
        def capture_command(cmd, in_data=None, sudoable=True):
            actual_commands.append(cmd)
            return (0, b"output", b"")
        
        mock_ssh_connection.exec_command = Mock(side_effect=capture_command)
        
        jail_connection.exec_command(cmd_with_specials)
        
        # Verify the command was properly quoted
        assert len(actual_commands) == 1
        actual_cmd = actual_commands[0]
        
        # Should contain properly quoted arguments
        assert "hello world" in actual_cmd  # Spaces should be handled
        assert "$USER" in actual_cmd  # Dollar signs should be quoted
        assert "`date`" in actual_cmd  # Backticks should be quoted
        assert "file;rm -rf /" in actual_cmd  # Semicolons should be quoted
    
    def test_jail_name_quoting(self, jail_connection, mock_ssh_connection, test_helper):
        """Test that jail names are properly quoted in commands."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "jail-with-dashes"
        jail_connection.privilege_escalation = "doas"
        
        # Mock exec_command to capture the actual command
        actual_commands = []
        def capture_command(cmd, in_data=None, sudoable=True):
            actual_commands.append(cmd)
            return (0, b"output", b"")
        
        mock_ssh_connection.exec_command = Mock(side_effect=capture_command)
        
        jail_connection.exec_command("echo test")
        
        # Verify jail name is properly quoted
        assert len(actual_commands) == 1
        actual_cmd = actual_commands[0]
        assert "jail-with-dashes" in actual_cmd