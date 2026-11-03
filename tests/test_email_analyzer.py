from email_analyzer import EmailAnalyzer


def test_safe_email():
    analyzer = EmailAnalyzer()

    result = analyzer.analyze(
        subject="Meeting tomorrow",
        body="Hello, let's meet tomorrow to discuss the project.",
        sender="team@example.com"
    )

    assert result is not None


def test_suspicious_email():
    analyzer = EmailAnalyzer()

    result = analyzer.analyze(
        subject="Urgent! Verify your account",
        body="Click here immediately to claim your prize.",
        sender="unknown@example.com"
    )

    assert result is not None