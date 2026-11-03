from email_analyzer import EmailAnalyzer


def test_email_analyzer_initialization():
    analyzer = EmailAnalyzer()
    assert analyzer is not None


def test_email_analysis_returns_result():
    analyzer = EmailAnalyzer()

    result = analyzer.analyze_email(
        email_text="""
        Subject: Meeting tomorrow

        Hello, let's meet tomorrow to discuss the project.
        From: team@example.com
        """
    )

    assert result is not None


def test_suspicious_email_analysis():
    analyzer = EmailAnalyzer()

    result = analyzer.analyze_email(
        email_text="""
        Subject: Urgent! Verify your account

        Click here immediately to claim your prize.
        Your account will be suspended unless you verify now.
        From: unknown@example.com
        """
    )

    assert result is not None