"""
Unit tests for the Connection class core functionality.

Tests connection initialization, configuration loading, SSH connection
management, and basic connection lifecycle.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from ansible.errors import AnsibleConnectionFailure, AnsibleError

# Import test utilities
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)


class TestConnectionInitialization:
    """Test Connection class initialization."""
    
    def test_connection_init_valid_jail_name(self, mock_play_context, mock_display):
        """Test successful connection initialization with valid jail name."""
        from jailexec import Connection
        
        mock_play_context.remote_addr = "testjail"
        
        with patch('jailexec.SSHConnection') as mock_ssh_base:
            conn = Connection(mock_play_context, None)
            
            assert conn.jail_name == "testjail"
            assert conn.jail_user == "root"  # Default
            assert conn.privilege_escalation == "doas"  # Default
            assert conn.remote_tmp == "/tmp/.ansible/tmp"  # Default
    
    def test_connection_init_invalid_jail_name(self, mock_play_context, mock_display):
        """Test connection initialization with invalid jail name."""
        from jailexec import Connection
        
        mock_play_context.remote_addr = "invalid;jail"
        
        with patch('jailexec.SSHConnection') as mock_ssh_base:
            with pytest.raises(AnsibleConnectionFailure, match="Invalid jail name format"):
                Connection(mock_play_context, None)
    
    def test_connection_init_custom_user(self, mock_play_context, mock_display):
        """Test connection initialization with custom user."""
        from jailexec import Connection
        
        mock_play_context.remote_addr = "testjail"
        mock_play_context.remote_user = "testuser"
        
        with patch('jailexec.SSHConnection') as mock_ssh_base:
            conn = Connection(mock_play_context, None)
            assert conn.jail_user == "testuser"
    
    def test_connection_attributes_initialized(self, mock_play_context, mock_display):
        """Test that all connection attributes are properly initialized."""
        from jailexec import Connection
        
        with patch('jailexec.SSHConnection') as mock_ssh_base:
            conn = Connection(mock_play_context, None)
            
            # Check all attributes are initialized
            assert hasattr(conn, 'jail_name')
            assert hasattr(conn, 'jail_host')
            assert hasattr(conn, 'jail_user')
            assert hasattr(conn, 'privilege_escalation')
            assert hasattr(conn, 'remote_tmp')
            assert hasattr(conn, 'connection_timeout')
            assert hasattr(conn, '_jail_root_cache')
            assert hasattr(conn, '_host_connection')
            assert hasattr(conn, '_last_activity')
            
            # Check initial values
            assert conn._jail_root_cache is None
            assert conn._host_connection is None
            assert isinstance(conn._last_activity, float)


class TestConfigurationLoading:
    """Test configuration loading and validation."""
    
    def test_get_jail_configuration_success(self, jail_connection, sample_config, test_helper):
        """Test successful configuration loading."""
        test_helper.mock_get_option(jail_connection, sample_config)
        
        jail_connection._get_jail_configuration()
        
        assert jail_connection.jail_host == sample_config['jail_host']
        assert jail_connection.jail_user == sample_config['jail_user']
        assert jail_connection.privilege_escalation == sample_config['privilege_escalation']
        assert jail_connection.remote_tmp == sample_config['remote_tmp']
    
    def test_get_jail_configuration_missing_host(self, jail_connection, test_helper):
        """Test configuration loading with missing jail_host."""
        test_helper.mock_get_option(jail_connection, {})
        
        with pytest.raises(AnsibleConnectionFailure, match="No jail host specified"):
            jail_connection._get_jail_configuration()
    
    def test_get_jail_configuration_empty_host(self, jail_connection, test_helper):
        """Test configuration loading with empty jail_host."""
        test_helper.mock_get_option(jail_connection, {'jail_host': '   '})
        
        with pytest.raises(AnsibleConnectionFailure, match="No jail host specified"):
            jail_connection._get_jail_configuration()
    
    def test_get_jail_configuration_invalid_privilege_escalation(self, jail_connection, test_helper):
        """Test configuration loading with invalid privilege escalation method."""
        config = {
            'jail_host': 'host.example.com',
            'privilege_escalation': 'invalid_method'
        }
        test_helper.mock_get_option(jail_connection, config)
        
        with pytest.raises(AnsibleConnectionFailure, match="Invalid privilege escalation method"):
            jail_connection._get_jail_configuration()
    
    def test_get_jail_configuration_invalid_remote_tmp(self, jail_connection, test_helper):
        """Test configuration loading with invalid remote_tmp path."""
        config = {
            'jail_host': 'host.example.com',
            'remote_tmp': 'relative/path'  # Not absolute
        }
        test_helper.mock_get_option(jail_connection, config)
        
        with pytest.raises(AnsibleConnectionFailure, match="must be an absolute path"):
            jail_connection._get_jail_configuration()
    
    def test_get_jail_configuration_dangerous_remote_tmp(self, jail_connection, test_helper):
        """Test configuration loading with dangerous remote_tmp path."""
        config = {
            'jail_host': 'host.example.com',
            'remote_tmp': '/tmp/../etc'  # Path traversal
        }
        test_helper.mock_get_option(jail_connection, config)
        
        with pytest.raises(AnsibleConnectionFailure):
            jail_connection._get_jail_configuration()
    
    def test_get_jail_configuration_jail_name_override(self, jail_connection, test_helper):
        """Test jail name override in configuration."""
        config = {
            'jail_host': 'host.example.com',
            'jail_name': 'overridden-jail'
        }
        test_helper.mock_get_option(jail_connection, config)
        
        original_name = jail_connection.jail_name
        jail_connection._get_jail_configuration()
        
        assert jail_connection.jail_name == 'overridden-jail'
        assert jail_connection.jail_name != original_name
    
    def test_get_jail_configuration_invalid_jail_name_override(self, jail_connection, test_helper):
        """Test invalid jail name override in configuration."""
        config = {
            'jail_host': 'host.example.com',
            'jail_name': 'invalid;jail'
        }
        test_helper.mock_get_option(jail_connection, config)
        
        with pytest.raises(AnsibleConnectionFailure, match="Invalid jail name format"):
            jail_connection._get_jail_configuration()
    
    def test_get_jail_configuration_timeout_validation(self, jail_connection, test_helper):
        """Test timeout configuration validation."""
        config = {
            'jail_host': 'host.example.com',
            'timeout': 60
        }
        test_helper.mock_get_option(jail_connection, config)
        
        jail_connection._get_jail_configuration()
        assert jail_connection.connection_timeout == 60
        
        # Test invalid timeout
        config['timeout'] = 'invalid'
        test_helper.mock_get_option(jail_connection, config)
        
        # Should not raise exception, just use default
        jail_connection._get_jail_configuration()


class TestSSHConnectionManagement:
    """Test SSH connection creation and management."""
    
    def test_create_ssh_connection_success(self, jail_connection, mock_display):
        """Test successful SSH connection creation."""
        jail_connection.jail_host = "host.example.com"
        
        with patch('jailexec.SSHConnection') as mock_ssh_class:
            mock_ssh_instance = Mock()
            mock_ssh_class.return_value = mock_ssh_instance
            
            result = jail_connection._create_ssh_connection()
            
            assert result == mock_ssh_instance
            mock_ssh_instance._connect.assert_called_once()
    
    def test_create_ssh_connection_with_retry(self, jail_connection, mock_display):
        """Test SSH connection creation with retry logic."""
        jail_connection.jail_host = "host.example.com"
        
        with patch('jailexec.SSHConnection') as mock_ssh_class:
            mock_ssh_instance = Mock()
            mock_ssh_instance._connect.side_effect = [
                AnsibleConnectionFailure("First attempt fails"),
                None  # Second attempt succeeds
            ]
            mock_ssh_class.return_value = mock_ssh_instance
            
            result = jail_connection._create_ssh_connection()
            
            assert result == mock_ssh_instance
            assert mock_ssh_instance._connect.call_count == 2
    
    def test_create_ssh_connection_all_retries_fail(self, jail_connection, mock_display):
        """Test SSH connection creation when all retries fail."""
        jail_connection.jail_host = "host.example.com"
        
        with patch('jailexec.SSHConnection') as mock_ssh_class:
            mock_ssh_instance = Mock()
            mock_ssh_instance._connect.side_effect = AnsibleConnectionFailure("Connection failed")
            mock_ssh_class.return_value = mock_ssh_instance
            
            with pytest.raises(AnsibleConnectionFailure, match="Connection failed"):
                jail_connection._create_ssh_connection()


class TestConnectionLifecycle:
    """Test connection lifecycle methods."""
    
    def test_connect_full_lifecycle(self, jail_connection, sample_config, test_helper, mock_ssh_connection):
        """Test full connection lifecycle."""
        # Setup configuration
        test_helper.mock_get_option(jail_connection, sample_config)
        
        # Setup SSH connection mock
        jail_connection._host_connection = mock_ssh_connection
        
        # Setup successful jail verification
        test_helper.setup_ssh_exec_results(mock_ssh_connection, {
            'doas jls -j testjail': (0, b"testjail running", b"")
        })
        
        # Test connection
        result = jail_connection._connect()
        
        assert result == jail_connection
        assert jail_connection._connected is True
        assert jail_connection.jail_host == sample_config['jail_host']
    
    def test_connect_already_connected(self, jail_connection):
        """Test connection when already connected."""
        jail_connection._connected = True
        
        result = jail_connection._connect()
        
        assert result == jail_connection
        # Should not attempt to reconnect
    
    def test_close_connection(self, jail_connection, mock_ssh_connection):
        """Test connection cleanup."""
        jail_connection._host_connection = mock_ssh_connection
        jail_connection._jail_root_cache = "/jail/root"
        jail_connection._connected = True
        
        jail_connection.close()
        
        assert mock_ssh_connection.connected is False
        assert jail_connection._jail_root_cache is None
        assert jail_connection._host_connection is None