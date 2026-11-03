import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EmailInput:

    sender: str
    subject: str
    body: str

    attachments: list = field(default_factory=list)


@dataclass
class ValidationResult:

    valid: bool
    errors: list = field(default_factory=list)


class EmailValidator:

    MAX_EMAIL_SIZE = 1024 * 1024  # 1 MB

    ALLOWED_EXTENSIONS = {
        ".pdf",
        ".txt",
        ".doc",
        ".docx",
        ".png",
        ".jpg",
        ".jpeg",
        ".eml"
    }

    @staticmethod
    def validate_sender(sender):

        pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

        return bool(re.match(pattern, sender))

    @staticmethod
    def validate_subject(subject):

        return bool(subject and subject.strip())

    @staticmethod
    def validate_body(body):

        return bool(body and body.strip())

    def validate_attachments(self, attachments):

        errors = []

        for filename in attachments:

            if not isinstance(filename, str) or not filename.strip():
                errors.append("Invalid attachment filename")
                continue

            extension = "." + filename.rsplit(".", 1)[-1].lower()

            if "." not in filename or extension not in self.ALLOWED_EXTENSIONS:
                errors.append(
                    f"Unsupported attachment format: {filename}"
                )

        return errors

    def validate_email(self, email_data):

        errors = []

        if not isinstance(email_data, EmailInput):
            return ValidationResult(
                valid=False,
                errors=["Input must be an EmailInput object"]
            )

        if not self.validate_sender(email_data.sender):
            errors.append("Invalid sender email address")

        if not self.validate_subject(email_data.subject):
            errors.append("Email subject cannot be empty")

        if not self.validate_body(email_data.body):
            errors.append("Email body cannot be empty")

        if len(email_data.body.encode("utf-8")) > self.MAX_EMAIL_SIZE:
            errors.append("Email body exceeds 1 MB")

        errors.extend(
            self.validate_attachments(email_data.attachments)
        )

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors
        )


if __name__ == "__main__":

    validator = EmailValidator()

    email = EmailInput(
        sender="security@example.com",
        subject="Account verification",
        body="Please verify your account.",
        attachments=["report.pdf"]
    )

    result = validator.validate_email(email)

    print("\nPURPLESHIELD AI - INPUT VALIDATION")
    print("=" * 40)

    print("Valid:", result.valid)
    print("Errors:", result.errors)