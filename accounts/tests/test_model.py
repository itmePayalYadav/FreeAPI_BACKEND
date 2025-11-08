import pytest
import pyotp
from datetime import timedelta
from django.utils import timezone
from freezegun import freeze_time
from urllib.parse import quote_plus
from model_bakery import baker
from accounts.models import User

pytestmark = pytest.mark.django_db

# =============================================================
# USER MODEL TESTS
# =============================================================

@pytest.mark.django_db
class TestUserModel:
    # =============================================================
    # CREATE
    # =============================================================
    def test_create_user(self, user_data):
        """Should create a regular user correctly"""
        user = User.objects.create_user(**user_data)
        assert user.email == user_data["email"]
        assert user.username == user_data["username"]
        assert user.check_password(user_data["password"])
        assert user.is_active
        assert not user.is_staff
        assert not user.is_superuser
        assert not user.is_verified

    def test_create_superuser(self, user_data):
        """Should create a superuser correctly"""
        superuser = User.objects.create_superuser(**user_data)
        assert superuser.email == user_data["email"]
        assert superuser.is_staff
        assert superuser.is_superuser

    # =============================================================
    # AVATAR URL
    # =============================================================
    def test_avatar_url_with_custom_avatar(self, user):
        """Should return custom avatar URL if set"""
        user.avatar = "https://example.com/avatar.jpg"
        user.save()
        print(user)
        assert user.avatar_url == "https://example.com/avatar.jpg"

    def test_avatar_url_without_avatar(self, user):
        """Should fallback to generated UI avatar if no custom avatar"""
        user.avatar = None
        user.save()
        expected_url = f"https://ui-avatars.com/api/?name={quote_plus(user.username)}&size=200"
        assert user.avatar_url == expected_url

    # =============================================================
    # ONLINE PRESENCE
    # =============================================================
    def test_mark_online(self, user):
        """Should set user online and update last_seen"""
        with freeze_time("2023-01-01 12:00:00"):
            user.mark_online()
            user.refresh_from_db()
            assert user.is_online is True
            assert user.last_seen == timezone.make_aware(timezone.datetime(2023, 1, 1, 12, 0, 0))

    def test_mark_offline(self, user):
        """Should set user offline and update last_seen"""
        with freeze_time("2023-01-01 12:00:00"):
            user.mark_offline()
            user.refresh_from_db()
            assert user.is_online is False
            assert user.last_seen == timezone.make_aware(timezone.datetime(2023, 1, 1, 12, 0, 0))

    # =============================================================
    # LAST SEEN FORMAT
    # =============================================================
    def test_formatted_last_seen_recent(self, user):
        """Should show 'online just now' for recent activity"""
        user.last_seen = timezone.now() - timedelta(seconds=30)
        assert user.formatted_last_seen() == "online just now"

    def test_formatted_last_seen_minutes_ago(self, user):
        """Should show minutes ago"""
        user.last_seen = timezone.now() - timedelta(minutes=10)
        assert "minutes ago" in user.formatted_last_seen()

    def test_formatted_last_seen_today(self, user):
        """Should show 'today at'"""
        user.last_seen = timezone.now() - timedelta(hours=3)
        assert "today at" in user.formatted_last_seen()

    def test_formatted_last_seen_yesterday(self, user):
        """Should show 'yesterday at'"""
        user.last_seen = timezone.now() - timedelta(days=1, hours=2)
        result = user.formatted_last_seen()
        assert "yesterday at" in result

    def test_formatted_last_seen_older(self, user):
        """Should show formatted date for older last_seen"""
        user.last_seen = timezone.now() - timedelta(days=5)
        result = user.formatted_last_seen()
        assert "on" in result and "at" in result

    # =============================================================
    # TOTP (2FA)
    # =============================================================
    def test_generate_totp_secret(self, user):
        """Should generate a valid TOTP secret"""
        secret = user.generate_totp_secret()
        user.refresh_from_db()
        assert user.totp_secret == secret
        assert len(secret) == 32

    def test_get_totp_uri(self, user):
        """Should return valid otpauth URI"""
        user.totp_secret = "TESTSECRET123"
        uri = user.get_totp_uri()
        assert "otpauth://totp/" in uri
        assert user.totp_secret in uri
        assert user.email in uri
        assert "issuer=config" in uri

    def test_verify_totp_valid_token(self, user):
        """Should verify a valid TOTP token"""
        user.generate_totp_secret()
        totp = pyotp.TOTP(user.totp_secret)
        token = totp.now()
        assert user.verify_totp(token) is True

    def test_verify_totp_invalid_token(self, user):
        """Should reject invalid TOTP token"""
        user.generate_totp_secret()
        assert user.verify_totp("000000") is False

    def test_verify_totp_no_secret(self, user):
        """Should return False when no TOTP secret set"""
        user.totp_secret = None
        assert user.verify_totp("123456") is False

    # =============================================================
    # SOFT DELETE
    # =============================================================
    def test_soft_delete_marks_as_deleted(self):
        """Soft delete should not remove user from DB"""
        user = User.objects.create_user(
            email="soft@test.com", username="softuser", password="pass123"
        )
        user.delete()
        user.refresh_from_db()
        assert User.objects.filter(id=user.id).exists()

    # =============================================================
    # STRING REPRESENTATION
    # =============================================================
    def test_string_representation(self, user):
        """__str__ should return email"""
        assert str(user) == user.email
