"""Tests for the Recon Domains module."""

from unittest.mock import patch
from redops.core.context import Context
from redops.modules.recon.domains import (
    get_dns_records,
    profile_domain,
    enumerate_dns,
    discover_subdomains
)


def test_get_dns_records_success():
    """Test successful DNS record retrieval."""
    with patch('socket.gethostbyname_ex') as mock_dns:
        mock_dns.return_value = ('example.com', [], ['93.184.216.34'])
        
        records = get_dns_records('example.com', 'A')
        
        assert len(records) > 0
        assert '93.184.216.34' in records


def test_get_dns_records_failure():
    """Test DNS record retrieval with failure."""
    with patch('socket.gethostbyname_ex') as mock_dns:
        mock_dns.side_effect = Exception("DNS lookup failed")
        
        records = get_dns_records('nonexistent.invalid', 'A')
        
        assert records == []


def test_get_dns_records_other_types():
    """Test requesting other DNS record types (stubbed)."""
    records = get_dns_records('example.com', 'MX')
    assert isinstance(records, list)


def test_profile_domain_success():
    """Test successful domain profiling."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['93.184.216.34', '93.184.216.35']
        
        ctx = Context(target="example.com")
        result = profile_domain(ctx)
        
        assert result is not None
        assert "domain_profile" in result.data
        profile = result.data["domain_profile"]
        assert profile["domain"] == "example.com"
        assert "dns_records" in profile
        assert "A" in profile["dns_records"]


def test_profile_domain_with_params():
    """Test domain profiling with explicit domain in params."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['192.0.2.1']
        
        ctx = Context(target="default.com")
        result = profile_domain(ctx, params={"domain": "custom.com"})
        
        profile = result.data["domain_profile"]
        assert profile["domain"] == "custom.com"


def test_profile_domain_no_target():
    """Test domain profiling without target."""
    ctx = Context()
    result = profile_domain(ctx)
    
    assert result is not None
    warnings = result.get_logs(level="WARNING")
    assert len(warnings) > 0


def test_profile_domain_dns_error():
    """Test domain profiling with DNS errors."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.side_effect = Exception("DNS error")
        
        ctx = Context(target="example.com")
        result = profile_domain(ctx)
        
        assert result is not None
        errors = result.get_logs(level="ERROR")
        assert len(errors) > 0


def test_profile_domain_creates_findings():
    """Test that domain profiling creates findings."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['93.184.216.34']
        
        ctx = Context(target="test.com")
        result = profile_domain(ctx)
        
        # Check for finding in context data
        finding_keys = [key for key in result.data.keys() if key.startswith('finding_')]
        assert len(finding_keys) > 0


def test_enumerate_dns_success():
    """Test successful DNS enumeration."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['93.184.216.34', '93.184.216.35']
        
        ctx = Context(target="example.com")
        result = enumerate_dns(ctx)
        
        assert result is not None
        assert "dns_enumeration" in result.data
        dns_data = result.data["dns_enumeration"]
        assert dns_data["domain"] == "example.com"
        assert "A" in dns_data
        assert len(dns_data["A"]) == 2


def test_enumerate_dns_with_params():
    """Test DNS enumeration with custom domain."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['192.0.2.1']
        
        ctx = Context(target="default.com")
        result = enumerate_dns(ctx, params={"domain": "custom.com"})
        
        dns_data = result.data["dns_enumeration"]
        assert dns_data["domain"] == "custom.com"


def test_enumerate_dns_no_target():
    """Test DNS enumeration without target."""
    ctx = Context()
    result = enumerate_dns(ctx)
    
    assert result is not None
    warnings = result.get_logs(level="WARNING")
    assert any("no domain" in log["message"].lower() for log in warnings)


def test_enumerate_dns_all_record_types():
    """Test that all record types are included."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['93.184.216.34']
        
        ctx = Context(target="example.com")
        result = enumerate_dns(ctx)
        
        dns_data = result.data["dns_enumeration"]
        assert "A" in dns_data
        assert "AAAA" in dns_data
        assert "MX" in dns_data
        assert "TXT" in dns_data


def test_discover_subdomains_placeholder():
    """Test subdomain discovery (placeholder implementation)."""
    ctx = Context(target="example.com")
    result = discover_subdomains(ctx)
    
    assert result is not None
    assert "subdomains" in result.data
    # Placeholder returns empty list
    assert isinstance(result.data["subdomains"], list)


def test_discover_subdomains_no_target():
    """Test subdomain discovery without target."""
    ctx = Context()
    result = discover_subdomains(ctx)
    
    assert result is not None
    warnings = result.get_logs(level="WARNING")
    assert len(warnings) > 0


def test_discover_subdomains_with_params():
    """Test subdomain discovery with custom domain."""
    ctx = Context(target="default.com")
    result = discover_subdomains(ctx, params={"domain": "custom.com"})
    
    assert result is not None
    info_logs = result.get_logs(level="INFO")
    assert any("custom.com" in log["message"] for log in info_logs)


def test_profile_domain_logging():
    """Test that domain profiling creates appropriate logs."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['93.184.216.34']
        
        ctx = Context(target="example.com")
        result = profile_domain(ctx)
        
        info_logs = result.get_logs(level="INFO")
        assert len(info_logs) > 0
        assert any("profiling" in log["message"].lower() for log in info_logs)
        assert any("completed" in log["message"].lower() for log in info_logs)


def test_enumerate_dns_logging():
    """Test that DNS enumeration creates appropriate logs."""
    with patch('redops.modules.recon.domains.get_dns_records') as mock_dns:
        mock_dns.return_value = ['93.184.216.34']
        
        ctx = Context(target="example.com")
        result = enumerate_dns(ctx)
        
        info_logs = result.get_logs(level="INFO")
        assert any("enumerating" in log["message"].lower() for log in info_logs)
        assert any("completed" in log["message"].lower() for log in info_logs)
