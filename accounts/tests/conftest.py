import pytest
import pyotp
from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from model_bakery import baker

User = get_user_model()

# ===============================
# API Client Fixture
# ===============================
@pytest.fixture
def api_client():
    """Provides DRF API client"""
    return APIClient()

# ===============================
# Default User Data
# ===============================
@pytest.fixture
def user_data():
    """Default data dict for registration/login API calls"""
    return {
        "email": "test@example.com",
        "username": "testuser",
        "password": "testpass123"
    }

# ===============================
# User Fixtures
# ===============================
@pytest.fixture
def user(user_data):
    """Regular test user (unverified)"""
    return baker.make(User, **user_data)

@pytest.fixture
def verified_user(user_data):
    """Verified user"""
    user = baker.make(User, **user_data, is_verified=True)
    user.set_password(user_data["password"])
    user.save()
    return user

@pytest.fixture
def user_with_2fa():
    """User with 2FA already enabled"""
    user = baker.make(
        User,
        username="user2fa",
        email="user2fa@example.com",
        is_verified=True,
        is_2fa_enabled=True,
        totp_secret=pyotp.random_base32()
    )
    user.set_password("testpass123")
    user.save()
    return user

@pytest.fixture
def user_with_secret():
    """User with existing TOTP secret (but not enabled)"""
    user = baker.make(
        User,
        username="usersecret",
        email="usersecret@example.com",
        is_verified=True,
        totp_secret=pyotp.random_base32(),
        is_2fa_enabled=False
    )
    user.set_password("testpass123")
    user.save()
    return user

@pytest.fixture
def superuser(user_data):
    """Superadmin user"""
    return baker.make(
        User,
        **user_data,
        is_staff=True,
        is_superuser=True,
        is_verified=True,
        role="SUPERADMIN"
    )

# ===============================
# Authenticated Client Fixtures
# ===============================
@pytest.fixture
def authenticated_client(api_client, verified_user):
    """Authenticated API client with a verified user"""
    api_client.force_authenticate(user=verified_user)
    return api_client

@pytest.fixture
def authenticated_client_with_2fa(api_client, user_with_2fa):
    """Authenticated client with 2FA-enabled user"""
    api_client.force_authenticate(user=user_with_2fa)
    return api_client

@pytest.fixture
def authenticated_client_with_secret(api_client, user_with_secret):
    """Authenticated client with a user who has an existing TOTP secret"""
    api_client.force_authenticate(user=user_with_secret)
    return api_client

# ===============================
# Mock Fixtures
# ===============================
@pytest.fixture
def mock_send_email():
    """Mocks send_email function globally for tests"""
    with patch("accounts.views.send_email") as mock:
        yield mock

@pytest.fixture
def mock_upload_to_cloudinary():
    """Mocks Cloudinary upload function"""
    with patch("accounts.views.upload_to_cloudinary") as mock:
        mock.return_value = "https://cloudinary.com/avatar.jpg"
        yield mock

@pytest.fixture
def mock_generate_qr_code():
    """Mocks QR code generation for TOTP"""
    with patch("accounts.views.generate_totp_qr_code") as mock:
        mock.return_value = "base64_qr_code"
        yield mock

@pytest.fixture
def mock_user_verify_totp(user_with_secret):
    with patch.object(user_with_secret, "verify_totp", return_value=True) as mock:
        yield mock

@pytest.fixture
def mock_image_file():
    """Provides a simple uploaded image file"""
    return SimpleUploadedFile(
        "avatar.jpg",
        b"file_content",
        content_type="image/jpeg"
    )

@pytest.fixture
def change_password():
    """User to test password change"""
    user = baker.make(
        User,
        username="passworduser",
        email="passworduser@example.com",
        is_verified=True
    )
    user.set_password("mysecret123")
    user.save()
    return user
