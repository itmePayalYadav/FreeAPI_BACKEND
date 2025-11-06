EMAIL_TEMPLATES = {
    "welcome": """\
Hi {username},

Welcome to API Verse! Your account has been successfully created.

Best regards,
API Verse Team
""",
    "email_verification": """\
Hi {username},

Please use the verification code below to verify your email:

Verification Code: {verification_code}

This code will expire in 10 minutes.
""",
    "reset_password": """\
Hi {username},

Click the link below to reset your password:

{reset_link}

If you did not request this, ignore this email.
""",
    "generic": """\
Hi {username},

{message}
"""
}
