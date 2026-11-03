import re
from urllib.parse import urlparse
from email import message_from_string
from email.policy import default


class EmailAnalyzer:

    def __init__(self):

        self.suspicious_keywords = [
            "urgent",
            "verify your account",
            "account suspended",
            "password expired",
            "click here",
            "limited time",
            "update payment",
            "confirm your identity",
            "unusual activity",
            "immediate action"
        ]

        self.dangerous_extensions = [
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".js",
            ".vbs",
            ".msi",
            ".ps1"
        ]

    def extract_urls(self, text):

        url_pattern = r'https?://[^\s<>"\']+'

        return re.findall(url_pattern, text, re.IGNORECASE)

    def check_suspicious_keywords(self, text):

        detected = []

        text = text.lower()

        for keyword in self.suspicious_keywords:

            if keyword in text:
                detected.append(keyword)

        return detected

    def analyze_urls(self, urls):

        results = []

        for url in urls:

            parsed = urlparse(url)

            hostname = parsed.hostname or ""

            suspicious = False
            reasons = []

            if parsed.scheme != "https":

                suspicious = True
                reasons.append("URL does not use HTTPS")

            if "@" in parsed.netloc:

                suspicious = True
                reasons.append("URL contains an @ symbol")

            if hostname.startswith("xn--") or ".xn--" in hostname:

                suspicious = True
                reasons.append("Internationalized domain detected")

            if len(url) > 100:

                suspicious = True
                reasons.append("Unusually long URL")

            results.append({
                "url": url,
                "hostname": hostname,
                "suspicious": suspicious,
                "reasons": reasons
            })

        return results

    def analyze_attachments(self, filenames):

        detected = []

        for filename in filenames:

            extension = "." + filename.split(".")[-1].lower()

            if extension in self.dangerous_extensions:

                detected.append({
                    "filename": filename,
                    "reason": "Potentially dangerous file extension"
                })

        return detected

    def calculate_risk(self, keywords, urls, attachments):

        score = 0

        score += min(len(keywords) * 5, 30)

        score += min(
            sum(20 for url in urls if url["suspicious"]),
            40
        )

        score += min(len(attachments) * 15, 30)

        if score >= 60:
            severity = "HIGH"

        elif score >= 30:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        return {
            "risk_score": min(score, 100),
            "severity": severity
        }

    def analyze_email(self, email_text, attachments=None):

        if attachments is None:
            attachments = []

        keywords = self.check_suspicious_keywords(email_text)

        urls = self.extract_urls(email_text)

        url_analysis = self.analyze_urls(urls)

        attachment_analysis = self.analyze_attachments(
            attachments
        )

        risk = self.calculate_risk(
            keywords,
            url_analysis,
            attachment_analysis
        )

        return {
            "detected_keywords": keywords,
            "urls": url_analysis,
            "attachments": attachment_analysis,
            "risk_score": risk["risk_score"],
            "severity": risk["severity"]
        }


if __name__ == "__main__":

    analyzer = EmailAnalyzer()

    sample_email = """
    URGENT! Your account has been suspended.
    Verify your account immediately.

    Click here:
    http://example.com/login
    """

    sample_attachments = [
        "invoice.pdf",
        "suspicious.exe"
    ]

    result = analyzer.analyze_email(
        sample_email,
        sample_attachments
    )

    print("\nPURPLESHIELD AI - EMAIL ANALYSIS")
    print("=" * 45)

    for key, value in result.items():

        print(f"\n{key}: {value}")