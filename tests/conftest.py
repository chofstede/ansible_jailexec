"""
Pytest configuration and fixtures for jailexec plugin tests.

This module provides common fixtures and utilities for testing the
FreeBSD jail connection plugin.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any, Optional

# Mock Ansible modules for testing
class MockPlayContext:
    """Mock Ansible play context for testing."""
    
    def __init__(self, remote_addr: str = "testjail", remote_user: str = "root", 
                 port: int = 22):
        self.remote_addr = remote_addr
        self.remote_user = remote_user
        self.port = port
        self.shell = 'sh'
        self.executable = '/bin/sh'
        
    def copy(self):
        """Create a copy of the play context."""
        new_context = MockPlayContext(self.remote_addr, self.remote_user, self.port)
        new_context.shell = self.shell
        new_context.executable = self.executable
        return new_context


class MockSSHConnection:
    """Mock SSH connection for testing."""
    
    def __init__(self):
        self.connected = False
        self.exec_results = {}
        self.put_file_results = {}
        self.fetch_file_results = {}
        
    def _connect(self):
        """Mock connection method."""
        self.connected = True
        
    def exec_command(self, cmd: str, in_data=None, sudoable=True):
        """Mock command execution."""
        if cmd in self.exec_results:
            return self.exec_results[cmd]
        # Default success response
        return (0, b"success", b"")
        
    def put_file(self, in_path: str, out_path: str):
        """Mock file upload."""
        if out_path in self.put_file_results:
            result = self.put_file_results[out_path]
            if isinstance(result, Exception):
                raise result
        # Default success
        return
        
    def fetch_file(self, in_path: str, out_path: str):
        """Mock file download."""
        if in_path in self.fetch_file_results:
            result = self.fetch_file_results[in_path]
            if isinstance(result, Exception):
                raise result
        # Default success
        return
        
    def close(self):
        """Mock connection close."""
        self.connected = False


@pytest.fixture
def mock_play_context():
    """Provide a mock Ansible play context."""
    return MockPlayContext()


@pytest.fixture
def mock_ssh_connection():
    """Provide a mock SSH connection."""
    return MockSSHConnection()


@pytest.fixture
def mock_display():
    """Provide a mock Ansible display object."""
    with patch('jailexec.display') as mock:
        mock.vvv = Mock()
        mock.warning = Mock()
        yield mock


@pytest.fixture
def jail_connection(mock_play_context, mock_display):
    """Create a jail connection instance for testing."""
    # Import here to avoid circular imports during collection
    import sys
    import os
    
    # Add the parent directory to sys.path so we can import jailexec
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
        
    from jailexec import Connection
    
    # Mock the SSH connection base class
    with patch('jailexec.SSHConnection') as mock_ssh_base:
        mock_ssh_base.return_value = Mock()
        conn = Connection(mock_play_context, None)
        conn._host_connection = MockSSHConnection()
        yield conn


@pytest.fixture
def sample_config():
    """Provide sample configuration data for tests."""
    return {
        'jail_host': 'freebsd-host.example.com',
        'jail_name': 'testjail',
        'jail_user': 'root',
        'privilege_escalation': 'doas',
        'remote_tmp': '/tmp/.ansible/tmp',
        'timeout': 30
    }


class TestHelper:
    """Helper class for common test operations."""
    
    @staticmethod
    def mock_get_option(conn, options: Dict[str, Any]):
        """Mock the get_option method with provided options."""
        def get_option_side_effect(option, hostvars=None):
            return options.get(option)
        conn.get_option = Mock(side_effect=get_option_side_effect)
        
    @staticmethod
    def setup_ssh_exec_results(ssh_conn: MockSSHConnection, results: Dict[str, tuple]):
        """Setup expected results for SSH command execution."""
        ssh_conn.exec_results.update(results)
        
    @staticmethod
    def setup_ssh_file_results(ssh_conn: MockSSHConnection, 
                              put_results: Optional[Dict] = None,
                              fetch_results: Optional[Dict] = None):
        """Setup expected results for SSH file operations."""
        if put_results:
            ssh_conn.put_file_results.update(put_results)
        if fetch_results:
            ssh_conn.fetch_file_results.update(fetch_results)


@pytest.fixture
def test_helper():
    """Provide the test helper class."""
    return TestHelper


# Common test data
@pytest.fixture
def valid_jail_names():
    """List of valid jail names for testing."""
    return [
        'testjail',
        'web-server', 
        'db_backup',
        'jail123',
        'test.jail',
        'a' * 255  # Maximum length
    ]


@pytest.fixture
def invalid_jail_names():
    """List of invalid jail names for testing."""
    return [
        '',  # Empty
        ' ',  # Whitespace only
        '-startswithdasdh',  # Starts with dash
        '_startswithunderscore',  # Starts with underscore
        'has spaces',  # Contains spaces
        'has;semicolon',  # Contains dangerous characters
        'has$dollar',  # Contains dangerous characters
        'a' * 256,  # Too long
        '../escape',  # Path traversal
        'jail|pipe'  # Pipe character
    ]


@pytest.fixture
def dangerous_paths():
    """List of dangerous paths for security testing."""
    return [
        '../etc/passwd',
        '../../..',
        '/path/with/../traversal',
        'path;withsemicolon',
        'path|withpipe',
        'path$(command)',
        'path`command`',
        'path&command',
        '   ',  # Whitespace only
    ]


@pytest.fixture
def safe_paths():
    """List of safe paths for testing."""
    return [
        '/tmp/testfile',
        '/home/user/document.txt',
        '~/userfile',
        '/usr/local/bin/app',
        'relative/path/file.txt'
    ]