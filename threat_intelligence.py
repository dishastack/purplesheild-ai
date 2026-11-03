import ipaddress
import re
from urllib.parse import urlparse


class ThreatIntelligence:

    def __init__(self):
        self.suspicious_ports = {
            21, 22, 23, 445, 3389, 4444, 5555
        }

    # --------------------------------
    # IP ADDRESS INVESTIGATION
    # --------------------------------

    def analyze_ip(self, ip_address):

        try:
            ip = ipaddress.ip_address(ip_address)

            result = {
                "ip_address": str(ip),
                "valid": True,
                "ip_version": ip.version,
                "is_private": ip.is_private,
                "is_global": ip.is_global,
                "is_loopback": ip.is_loopback,
                "risk": "UNKNOWN"
            }

            if ip.is_loopback:
                result["risk"] = "INFORMATIONAL"

            elif ip.is_private:
                result["risk"] = "INFORMATIONAL"

            elif ip.is_global:
                result["risk"] = "NEEDS_REPUTATION_CHECK"

            return result

        except ValueError:

            return {
                "ip_address": ip_address,
                "valid": False,
                "risk": "INVALID"
            }

    # --------------------------------
    # DOMAIN INVESTIGATION
    # --------------------------------

    def analyze_domain(self, domain):

        domain = domain.strip().lower()

        result = {
            "domain": domain,
            "valid": False,
            "indicators": [],
            "risk": "UNKNOWN"
        }

        if not domain or len(domain) > 253:
            result["risk"] = "INVALID"
            return result

        domain_pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}$"
        )

        if not re.match(domain_pattern, domain):
            result["risk"] = "INVALID"
            return result

        result["valid"] = True

        if domain.startswith("xn--") or ".xn--" in domain:
            result["indicators"].append("Punycode domain")

        if len(domain) > 50:
            result["indicators"].append("Unusually long domain")

        if len(result["indicators"]) > 0:
            result["risk"] = "REVIEW_REQUIRED"
        else:
            result["risk"] = "NO_LOCAL_INDICATORS"

        return result

    # --------------------------------
    # URL INVESTIGATION
    # --------------------------------

    def analyze_url(self, url):

        result = {
            "url": url,
            "valid": False,
            "indicators": [],
            "risk": "UNKNOWN"
        }

        try:
            parsed = urlparse(url.strip())

            if parsed.scheme not in ("http", "https"):
                result["risk"] = "INVALID"
                return result

            if not parsed.hostname:
                result["risk"] = "INVALID"
                return result

            result["valid"] = True

            if parsed.scheme == "http":
                result["indicators"].append(
                    "Unencrypted HTTP connection"
                )

            if "@" in parsed.netloc:
                result["indicators"].append(
                    "URL contains user information"
                )

            if len(url) > 200:
                result["indicators"].append(
                    "Unusually long URL"
                )

            if result["indicators"]:
                result["risk"] = "REVIEW_REQUIRED"
            else:
                result["risk"] = "NO_LOCAL_INDICATORS"

            return result

        except Exception:

            result["risk"] = "INVALID"
            return result


# --------------------------------
# TESTING
# --------------------------------

if __name__ == "__main__":

    intelligence = ThreatIntelligence()

    print("\nPURPLESHIELD AI - THREAT INTELLIGENCE")

    print("\nIP INVESTIGATION")
    print(intelligence.analyze_ip("8.8.8.8"))

    print("\nDOMAIN INVESTIGATION")
    print(intelligence.analyze_domain("example.com"))

    print("\nURL INVESTIGATION")
    print(
        intelligence.analyze_url(
            "https://example.com/login"
        )
    )