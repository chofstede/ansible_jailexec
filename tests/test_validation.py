"""
Unit tests for input validation and security functions.

Tests the validation functions that ensure security and compliance
with FreeBSD jail naming conventions and path security.
"""

import pytest
from ansible.errors import AnsibleConnectionFailure, AnsibleError

# Import the module under test
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from jailexec import validate_jail_name, validate_path_security


class TestJailNameValidation:
    """Test jail name validation functionality."""
    
    def test_valid_jail_names(self, valid_jail_names):
        """Test that valid jail names pass validation."""
        for jail_name in valid_jail_names:
            # Should not raise any exception
            validate_jail_name(jail_name)
    
    def test_invalid_jail_names(self, invalid_jail_names):
        """Test that invalid jail names raise appropriate exceptions."""
        for jail_name in invalid_jail_names:
            with pytest.raises(AnsibleConnectionFailure):
                validate_jail_name(jail_name)
    
    def test_empty_jail_name(self):
        """Test that empty jail names are rejected."""
        with pytest.raises(AnsibleConnectionFailure, match="cannot be empty"):
            validate_jail_name("")
        
        with pytest.raises(AnsibleConnectionFailure, match="cannot be empty"):
            validate_jail_name(None)
    
    def test_whitespace_jail_name(self):
        """Test that whitespace-only jail names are rejected."""
        with pytest.raises(AnsibleConnectionFailure, match="cannot be empty"):
            validate_jail_name("   ")
        
        with pytest.raises(AnsibleConnectionFailure, match="cannot be empty"):
            validate_jail_name("\t\n")
    
    def test_too_long_jail_name(self):
        """Test that overly long jail names are rejected."""
        long_name = "a" * 256  # One character too long
        with pytest.raises(AnsibleConnectionFailure, match="too long"):
            validate_jail_name(long_name)
    
    def test_jail_name_with_dangerous_characters(self):
        """Test that jail names with shell injection characters are rejected."""
        dangerous_names = [
            "jail;rm -rf /",
            "jail|cat /etc/passwd", 
            "jail$(malicious)",
            "jail`command`",
            "jail&background",
            "jail(function)"
        ]
        
        for name in dangerous_names:
            with pytest.raises(AnsibleConnectionFailure, match="Invalid jail name format"):
                validate_jail_name(name)
    
    def test_jail_name_format_validation(self):
        """Test specific format requirements."""
        # Must start with alphanumeric
        with pytest.raises(AnsibleConnectionFailure, match="Invalid jail name format"):
            validate_jail_name("-starts-with-dash")
        
        with pytest.raises(AnsibleConnectionFailure, match="Invalid jail name format"):
            validate_jail_name("_starts_with_underscore")
        
        with pytest.raises(AnsibleConnectionFailure, match="Invalid jail name format"):
            validate_jail_name(".starts.with.dot")
    
    def test_jail_name_allowed_characters(self):
        """Test that allowed characters work correctly."""
        allowed_names = [
            "jail123",
            "jail-name",
            "jail_name",
            "jail.name",
            "jail123.test-name_final"
        ]
        
        for name in allowed_names:
            # Should not raise any exception
            validate_jail_name(name)


class TestPathSecurityValidation:
    """Test path security validation functionality."""
    
    def test_safe_paths(self, safe_paths):
        """Test that safe paths pass validation."""
        for path in safe_paths:
            # Should not raise any exception
            validate_path_security(path)
    
    def test_dangerous_paths(self, dangerous_paths):
        """Test that dangerous paths are rejected."""
        for path in dangerous_paths:
            with pytest.raises(AnsibleError, match="dangerous pattern"):
                validate_path_security(path)
    
    def test_path_traversal_detection(self):
        """Test detection of path traversal attempts."""
        traversal_paths = [
            "../etc/passwd",
            "../../..",
            "/valid/path/../../../etc/shadow",
            "~/normal/../../dangerous",
            ".."
        ]
        
        for path in traversal_paths:
            with pytest.raises(AnsibleError, match="dangerous pattern"):
                validate_path_security(path)
    
    def test_shell_injection_detection(self):
        """Test detection of shell injection patterns in paths."""
        injection_paths = [
            "/path;rm -rf /",
            "/path|cat /etc/passwd",
            "/path$(malicious)",
            "/path`command`",
            "/path&background",
            "/path(function)"
        ]
        
        for path in injection_paths:
            with pytest.raises(AnsibleError, match="dangerous pattern"):
                validate_path_security(path)
    
    def test_empty_path_validation(self):
        """Test that empty paths are handled correctly."""
        # Empty string should not raise an exception (handled gracefully)
        validate_path_security("")
        validate_path_security(None)
    
    def test_whitespace_only_paths(self):
        """Test that whitespace-only paths are rejected."""
        whitespace_paths = [
            "   ",
            "\t",
            "\n",
            "\r\n",
            " \t \n "
        ]
        
        for path in whitespace_paths:
            with pytest.raises(AnsibleError, match="dangerous pattern"):
                validate_path_security(path)
    
    def test_normal_paths_with_spaces(self):
        """Test that normal paths with legitimate spaces are allowed."""
        normal_paths_with_spaces = [
            # These should be handled by the application layer, not rejected here
            # The dangerous pattern detection focuses on obvious security risks
        ]
        
        # Note: Paths with spaces in legitimate contexts should be handled
        # by proper quoting in the application layer, not rejected by security validation
        pass


class TestValidationIntegration:
    """Test integration between different validation functions."""
    
    def test_combined_validation_scenarios(self):
        """Test scenarios that involve multiple validation functions."""
        # This would be expanded based on how the functions are used together
        # in the actual connection plugin
        pass
    
    def test_error_message_quality(self):
        """Test that error messages are helpful and informative."""
        try:
            validate_jail_name("invalid;name")
            assert False, "Should have raised an exception"
        except AnsibleConnectionFailure as e:
            assert "Invalid jail name format" in str(e)
            assert "alphanumeric" in str(e)
        
        try:
            validate_path_security("../dangerous")
            assert False, "Should have raised an exception"  
        except AnsibleError as e:
            assert "dangerous pattern" in str(e)