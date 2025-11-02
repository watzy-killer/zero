"""
Unit tests for SQL Injection scanner module.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from scans.sql_injection import run, test_sql_injection_url, test_sql_injection_form


class TestSQLInjectionScanner:
    """Test cases for SQL Injection scanner."""
    
    @pytest.fixture
    def mock_context(self):
        """Create a mock scan context."""
        context = Mock()
        context.vulnerabilities = []
        context.record_vulnerability = lambda vuln: context.vulnerabilities.append(vuln)
        context.is_same_domain = lambda url: True
        return context
    
    @pytest.fixture
    def mock_options(self):
        """Create mock scan options."""
        return {'timeout': 30}
    
    def test_run_with_valid_target(self, mock_context, mock_options):
        """Test run function with valid target."""
        with patch('scans.sql_injection.test_sql_injection_url') as mock_test:
            mock_test.return_value = []
            results = run('http://example.com', mock_options, mock_context)
            
            assert isinstance(results, list)
            mock_test.assert_called_once_with('http://example.com', mock_options, mock_context)
    
    def test_sql_injection_url_detection(self, mock_context, mock_options):
        """Test SQL injection detection in URL parameters."""
        with patch('scans.sql_injection.HTTPClient') as MockHTTPClient:
            mock_client = Mock()
            mock_response = Mock()
            mock_response.text = "Error in your SQL syntax"
            mock_response.status_code = 200
            mock_client.get.return_value = mock_response
            MockHTTPClient.return_value = mock_client
            
            # Test URL with parameters
            test_url = 'http://example.com/page?id=1'
            findings = test_sql_injection_url(test_url, mock_options, mock_context)
            
            assert len(findings) > 0
            assert findings[0]['type'] == 'SQL Injection (URL)'
            assert findings[0]['severity'] == 'Critical'
    
    def test_sql_injection_url_no_parameters(self, mock_context, mock_options):
        """Test SQL injection on URL without parameters."""
        test_url = 'http://example.com/page'
        findings = test_sql_injection_url(test_url, mock_options, mock_context)
        
        assert len(findings) == 0
    
    def test_sql_injection_form_detection(self, mock_context, mock_options):
        """Test SQL injection detection in forms."""
        with patch('scans.sql_injection.HTTPClient') as MockHTTPClient:
            mock_client = Mock()
            mock_response = Mock()
            mock_response.text = "MySQL server version"
            mock_response.status_code = 200
            mock_client.post.return_value = mock_response
            MockHTTPClient.return_value = mock_client
            
            # Mock form data
            mock_form = {
                'action': 'http://example.com/login',
                'method': 'post',
                'inputs': [
                    {'type': 'text', 'name': 'username', 'value': ''},
                    {'type': 'password', 'name': 'password', 'value': ''},
                    {'type': 'hidden', 'name': 'token', 'value': 'abc123'}
                ]
            }
            
            findings = test_sql_injection_form(mock_form, 'http://example.com', mock_options, mock_context)
            
            assert len(findings) > 0
            assert findings[0]['type'] == 'SQL Injection'
            assert findings[0]['severity'] == 'Critical'
    
    def test_sql_injection_form_different_domain(self, mock_context, mock_options):
        """Test SQL injection on form with different domain."""
        mock_context.is_same_domain.return_value = False
        
        mock_form = {
            'action': 'http://external.com/login',
            'method': 'post',
            'inputs': [{'type': 'text', 'name': 'test', 'value': ''}]
        }
        
        findings = test_sql_injection_form(mock_form, 'http://example.com', mock_options, mock_context)
        
        assert len(findings) == 0
    
    def test_sql_injection_no_vulnerability(self, mock_context, mock_options):
        """Test when no SQL injection vulnerability is found."""
        with patch('scans.sql_injection.HTTPClient') as MockHTTPClient:
            mock_client = Mock()
            mock_response = Mock()
            mock_response.text = "Normal page content"
            mock_response.status_code = 200
            mock_client.get.return_value = mock_response
            MockHTTPClient.return_value = mock_client
            
            test_url = 'http://example.com/page?id=1'
            findings = test_sql_injection_url(test_url, mock_options, mock_context)
            
            assert len(findings) == 0
    
    def test_sql_injection_network_error(self, mock_context, mock_options):
        """Test handling of network errors."""
        with patch('scans.sql_injection.HTTPClient') as MockHTTPClient:
            mock_client = Mock()
            mock_client.get.side_effect = Exception("Network error")
            MockHTTPClient.return_value = mock_client
            
            test_url = 'http://example.com/page?id=1'
            findings = test_sql_injection_url(test_url, mock_options, mock_context)
            
            assert len(findings) == 0
    
    def test_sql_injection_multiple_payloads(self, mock_context, mock_options):
        """Test that multiple payloads are tried."""
        with patch('scans.sql_injection.HTTPClient') as MockHTTPClient:
            mock_client = Mock()
            mock_response = Mock()
            
            # First payload doesn't trigger error, second one does
            def side_effect(*args, **kwargs):
                if "' OR '1'='1" in str(args[0]):
                    mock_response.text = "SQL syntax error"
                else:
                    mock_response.text = "Normal content"
                return mock_response
            
            mock_client.get.side_effect = side_effect
            MockHTTPClient.return_value = mock_client
            
            test_url = 'http://example.com/page?id=1'
            findings = test_sql_injection_url(test_url, mock_options, mock_context)
            
            # Should find vulnerability on second payload
            assert len(findings) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])