import pytest

from threat_intelligence import ThreatIntelligence


@pytest.fixture
def analyzer():
    return ThreatIntelligence()


# IP ADDRESS TESTS

def test_valid_public_ip(analyzer):
    result = analyzer.analyze_ip("8.8.8.8")

    assert result["valid"] is True
    assert result["ip_version"] == 4
    assert result["risk"] == "NEEDS_REPUTATION_CHECK"


def test_private_ip(analyzer):
    result = analyzer.analyze_ip("192.168.1.1")

    assert result["valid"] is True
    assert result["is_private"] is True


def test_invalid_ip(analyzer):
    result = analyzer.analyze_ip("999.999.999.999")

    assert result["valid"] is False
    assert result["risk"] == "INVALID"


# DOMAIN TESTS

def test_valid_domain(analyzer):
    result = analyzer.analyze_domain("example.com")

    assert result["valid"] is True
    assert result["risk"] == "NO_LOCAL_INDICATORS"


def test_invalid_domain(analyzer):
    result = analyzer.analyze_domain("invalid_domain")

    assert result["valid"] is False
    assert result["risk"] == "INVALID"


# URL TESTS

def test_https_url(analyzer):
    result = analyzer.analyze_url(
        "https://example.com/login"
    )

    assert result["valid"] is True
    assert result["risk"] == "NO_LOCAL_INDICATORS"


def test_http_url(analyzer):
    result = analyzer.analyze_url(
        "http://example.com/login"
    )

    assert result["valid"] is True
    assert "Unencrypted HTTP connection" in result["indicators"]


def test_invalid_url(analyzer):
    result = analyzer.analyze_url("invalid-url")

    assert result["valid"] is False
    assert result["risk"] == "INVALID"