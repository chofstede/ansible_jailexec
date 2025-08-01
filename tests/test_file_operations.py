"""
Unit tests for file transfer operations.

Tests file upload (put_file) and download (fetch_file) functionality,
including security validation, error handling, and cleanup.
"""

import pytest
from unittest.mock import Mock, patch, call
from ansible.errors import AnsibleError

# Import test utilities
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)


class TestPutFile:
    """Test file upload functionality."""
    
    def test_put_file_success(self, jail_connection, mock_ssh_connection, test_helper):
        """Test successful file upload."""
        # Setup connection
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup successful operations
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas mkdir -p /jail/testjail/tmp': (0, b"", b""),
            'chmod 600 /tmp/ansible-jailexec-*': (0, b"", b""),  # Pattern match
            'doas mv /tmp/ansible-jailexec-* /jail/testjail/tmp/testfile': (0, b"", b"")
        })
        
        # Mock put_file to succeed
        mock_ssh_connection.put_file = Mock()
        
        # Mock exec_command with pattern matching
        def exec_command_side_effect(cmd):
            if 'mkdir -p' in cmd:
                return (0, b"", b"")
            elif 'chmod 600' in cmd:
                return (0, b"", b"")
            elif 'mv /tmp/ansible-jailexec-' in cmd:
                return (0, b"", b"")
            return (1, b"", b"Unknown command")
        
        mock_ssh_connection.exec_command = Mock(side_effect=exec_command_side_effect)
        
        # Test file upload
        jail_connection.put_file("/local/file", "/tmp/testfile")
        
        # Verify operations
        mock_ssh_connection.put_file.assert_called_once()
        assert mock_ssh_connection.exec_command.call_count >= 2  # mkdir and mv at minimum
    
    def test_put_file_auto_connect(self, jail_connection, sample_config, test_helper):
        """Test that put_file automatically connects if not connected."""
        jail_connection._connected = False
        test_helper.mock_get_option(jail_connection, sample_config)
        
        with patch.object(jail_connection, '_connect') as mock_connect:
            mock_connect.return_value = jail_connection
            jail_connection._connected = True
            jail_connection._host_connection = Mock()
            jail_connection._jail_root_cache = "/jail/testjail"
            
            # Setup mocks for successful operation
            jail_connection._host_connection.exec_command.return_value = (0, b"", b"")
            jail_connection._host_connection.put_file = Mock()
            
            jail_connection.put_file("/local/file", "/jail/file")
            
            mock_connect.assert_called_once()
    
    def test_put_file_path_transformation(self, jail_connection, mock_ssh_connection, test_helper):
        """Test that paths are properly transformed."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection.remote_tmp = "/tmp/.ansible/tmp"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Mock successful operations
        mock_ssh_connection.exec_command.return_value = (0, b"", b"")
        mock_ssh_connection.put_file = Mock()
        
        # Test home directory transformation
        jail_connection.put_file("/local/file", "~/userfile")
        
        # Verify that the path was transformed
        calls = mock_ssh_connection.exec_command.call_args_list
        final_move_call = None
        for call_args in calls:
            cmd = call_args[0][0]
            if 'mv /tmp/ansible-jailexec-' in cmd and '/tmp/.ansible/tmp/userfile' in cmd:
                final_move_call = cmd
                break
        
        assert final_move_call is not None, "Path transformation not applied correctly"
    
    def test_put_file_dangerous_path(self, jail_connection):
        """Test file upload with dangerous paths."""
        jail_connection._connected = True
        jail_connection._host_connection = Mock()
        
        dangerous_paths = [
            "../../../etc/passwd",
            "~/../../etc/shadow",
            "/tmp/file$(malicious)",
            "/path|with|pipes"
        ]
        
        for path in dangerous_paths:
            with pytest.raises(AnsibleError):
                jail_connection.put_file("/local/file", path)
    
    def test_put_file_mkdir_fails(self, jail_connection, mock_ssh_connection, test_helper):
        """Test file upload when directory creation fails."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup failed mkdir
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas mkdir -p /jail/testjail/tmp': (1, b"", b"Permission denied")
        })
        
        with pytest.raises(AnsibleError, match="Failed to create target directory"):
            jail_connection.put_file("/local/file", "/tmp/testfile")
    
    def test_put_file_ssh_put_fails(self, jail_connection, mock_ssh_connection, test_helper):
        """Test file upload when SSH put_file fails."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup successful mkdir but failed put_file
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas mkdir -p /jail/testjail/tmp': (0, b"", b"")
        })
        
        mock_ssh_connection.put_file = Mock(side_effect=Exception("Transfer failed"))
        
        with pytest.raises(AnsibleError, match="File transfer failed"):
            jail_connection.put_file("/local/file", "/tmp/testfile")
    
    def test_put_file_move_fails(self, jail_connection, mock_ssh_connection, test_helper):
        """Test file upload when final move fails."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup successful mkdir and put_file, but failed move
        def exec_command_side_effect(cmd):
            if 'mkdir -p' in cmd:
                return (0, b"", b"")
            elif 'chmod 600' in cmd:
                return (0, b"", b"")
            elif 'mv /tmp/ansible-jailexec-' in cmd:
                return (1, b"", b"No such file or directory")
            elif 'rm -f' in cmd:
                return (0, b"", b"")  # Cleanup succeeds
            return (1, b"", b"Unknown command")
        
        mock_ssh_connection.exec_command = Mock(side_effect=exec_command_side_effect)
        mock_ssh_connection.put_file = Mock()  # SSH put succeeds
        
        with pytest.raises(AnsibleError, match="Failed to move file to jail directory"):
            jail_connection.put_file("/local/file", "/tmp/testfile")
    
    def test_put_file_cleanup_on_failure(self, jail_connection, mock_ssh_connection, test_helper):
        """Test that temporary files are cleaned up on failure."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Track cleanup commands
        cleanup_commands = []
        
        def exec_command_side_effect(cmd):
            if 'rm -f' in cmd:
                cleanup_commands.append(cmd)
                return (0, b"", b"")
            elif 'mkdir -p' in cmd:
                return (0, b"", b"")
            elif 'chmod 600' in cmd:
                return (0, b"", b"")
            elif 'mv /tmp/ansible-jailexec-' in cmd:
                return (1, b"", b"Move failed")  # Simulate failure
            return (1, b"", b"Unknown command")
        
        mock_ssh_connection.exec_command = Mock(side_effect=exec_command_side_effect)
        mock_ssh_connection.put_file = Mock()
        
        with pytest.raises(AnsibleError):
            jail_connection.put_file("/local/file", "/tmp/testfile")
        
        # Verify cleanup was attempted
        assert len(cleanup_commands) > 0
        assert any('rm -f' in cmd for cmd in cleanup_commands)
    
    def test_put_file_secure_permissions(self, jail_connection, mock_ssh_connection, test_helper):
        """Test that temporary files get secure permissions."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        chmod_commands = []
        
        def exec_command_side_effect(cmd):
            if 'chmod 600' in cmd:
                chmod_commands.append(cmd)
                return (0, b"", b"")
            elif 'mkdir -p' in cmd:
                return (0, b"", b"")
            elif 'mv /tmp/ansible-jailexec-' in cmd:
                return (0, b"", b"")
            return (1, b"", b"Unknown command")
        
        mock_ssh_connection.exec_command = Mock(side_effect=exec_command_side_effect)
        mock_ssh_connection.put_file = Mock()
        
        jail_connection.put_file("/local/file", "/tmp/testfile")
        
        # Verify chmod 600 was called
        assert len(chmod_commands) > 0
        assert any('600' in cmd for cmd in chmod_commands)


class TestFetchFile:
    """Test file download functionality."""
    
    def test_fetch_file_success(self, jail_connection, mock_ssh_connection, test_helper):
        """Test successful file download."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup successful file existence check
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'test -f /jail/testjail/tmp/testfile': (0, b"", b"")
        })
        
        mock_ssh_connection.fetch_file = Mock()
        
        jail_connection.fetch_file("/tmp/testfile", "/local/file")
        
        mock_ssh_connection.fetch_file.assert_called_once_with("/jail/testjail/tmp/testfile", "/local/file")
    
    def test_fetch_file_auto_connect(self, jail_connection, sample_config, test_helper):
        """Test that fetch_file automatically connects if not connected."""
        jail_connection._connected = False
        test_helper.mock_get_option(jail_connection, sample_config)
        
        with patch.object(jail_connection, '_connect') as mock_connect:
            mock_connect.return_value = jail_connection
            jail_connection._connected = True
            jail_connection._host_connection = Mock()
            jail_connection._jail_root_cache = "/jail/testjail"
            
            # Setup mocks for successful operation
            jail_connection._host_connection.exec_command.return_value = (0, b"", b"")
            jail_connection._host_connection.fetch_file = Mock()
            
            jail_connection.fetch_file("/jail/file", "/local/file")
            
            mock_connect.assert_called_once()
    
    def test_fetch_file_path_transformation(self, jail_connection, mock_ssh_connection, test_helper):
        """Test that paths are properly transformed."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.remote_tmp = "/tmp/.ansible/tmp"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup successful operations
        mock_ssh_connection.exec_command.return_value = (0, b"", b"")
        mock_ssh_connection.fetch_file = Mock()
        
        # Test home directory transformation
        jail_connection.fetch_file("~/userfile", "/local/file")
        
        # Verify fetch_file was called with transformed path
        mock_ssh_connection.fetch_file.assert_called_once()
        call_args = mock_ssh_connection.fetch_file.call_args[0]
        assert call_args[0] == "/jail/testjail/tmp/.ansible/tmp/userfile"
    
    def test_fetch_file_dangerous_path(self, jail_connection):
        """Test file download with dangerous paths."""
        jail_connection._connected = True
        jail_connection._host_connection = Mock()
        
        dangerous_paths = [
            "../../../etc/passwd",
            "~/../../etc/shadow",
            "/tmp/file$(malicious)",
            "/path|with|pipes"
        ]
        
        for path in dangerous_paths:
            with pytest.raises(AnsibleError):
                jail_connection.fetch_file(path, "/local/file")
    
    def test_fetch_file_not_exists(self, jail_connection, mock_ssh_connection, test_helper):
        """Test file download when source file doesn't exist."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup failed file existence check
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'test -f /jail/testjail/tmp/nonexistent': (1, b"", b"")
        })
        
        with pytest.raises(AnsibleError, match="does not exist in jail"):
            jail_connection.fetch_file("/tmp/nonexistent", "/local/file")
    
    def test_fetch_file_ssh_fetch_fails(self, jail_connection, mock_ssh_connection, test_helper):
        """Test file download when SSH fetch_file fails."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection._jail_root_cache = "/jail/testjail"
        
        # Setup successful existence check but failed fetch
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'test -f /jail/testjail/tmp/testfile': (0, b"", b"")
        })
        
        mock_ssh_connection.fetch_file = Mock(side_effect=Exception("Transfer failed"))
        
        with pytest.raises(AnsibleError, match="Failed to fetch file from jail"):
            jail_connection.fetch_file("/tmp/testfile", "/local/file")
    
    def test_fetch_file_jail_root_detection_fails(self, jail_connection, mock_ssh_connection):
        """Test file download when jail root detection fails."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection.privilege_escalation = "doas"
        jail_connection._jail_root_cache = None  # Force jail root detection
        
        # Setup failed jail root detection
        mock_ssh_connection.exec_command = Mock(return_value=(1, b"", b"Jail not found"))
        
        with pytest.raises(AnsibleError, match="Could not determine jail root path"):
            jail_connection.fetch_file("/tmp/testfile", "/local/file")


class TestFileOperationIntegration:
    """Test integration between file operations and other components."""
    
    def test_file_operations_use_jail_root_cache(self, jail_connection, mock_ssh_connection, test_helper):
        """Test that file operations use cached jail root."""
        jail_connection._connected = True
        jail_connection._host_connection = mock_ssh_connection
        jail_connection.jail_name = "testjail"
        jail_connection._jail_root_cache = "/cached/jail/root"
        
        # Setup successful operations
        mock_ssh_connection.exec_command.return_value = (0, b"", b"")
        mock_ssh_connection.put_file = Mock()
        mock_ssh_connection.fetch_file = Mock()
        
        # Test put_file uses cache
        jail_connection.put_file("/local/file", "/jail/file")
        
        # Test fetch_file uses cache
        jail_connection.fetch_file("/jail/file", "/local/file")
        
        # Verify jail root detection was not called (would show up in exec_command calls)
        exec_calls = mock_ssh_connection.exec_command.call_args_list
        jail_root_calls = [call for call in exec_calls if 'jls -j testjail path' in str(call)]
        assert len(jail_root_calls) == 0, "Jail root detection should not be called when cached"
    
    def test_file_operations_error_propagation(self, jail_connection):
        """Test that file operation errors are properly propagated."""
        jail_connection._connected = True
        jail_connection._host_connection = None  # No SSH connection
        
        # Both operations should fail with appropriate errors
        with pytest.raises(AnsibleError):
            jail_connection.put_file("/local/file", "/jail/file")
        
        with pytest.raises(AnsibleError):
            jail_connection.fetch_file("/jail/file", "/local/file")