import pytest
from rest_framework.exceptions import ValidationError
from accounts.models import User
from accounts.serializers import (
    RegisterSerializer, 
    VerifyEmailSerializer,
    LoginSerializer,
    ForgotPasswordSerializer,
    ChangePasswordSerializer,
    UserSerializer,
    ResendEmailVerificationSerializer,
    UpdateAvatarSerializer,
    ChangeRoleSerializer,
    OAuthCallbackSerializer,
    RefreshTokenInputSerializer,
    Enable2FASerializer,
    Disable2FASerializer,
    Setup2FASerializer
)
from model_bakery import baker

# =============================================================
# REGISTER SERIALIZER TESTS
# =============================================================
@pytest.mark.django_db
class TestRegisterSerializer:
    def test_creates_user(self):
        """Should create a user with hashed password"""
        data = {"email": "test@example.com", "username": "testuser", "password": "secret123"}
        serializer = RegisterSerializer(data=data)
        assert serializer.is_valid(), serializer.errors
        user = serializer.save()
        assert isinstance(user, User)
        assert user.check_password(data["password"])
        assert user.email == data["email"]
        assert user.username == data["username"]

# =============================================================
# VERIFY EMAIL SERIALIZER
# =============================================================
class TestVerifyEmailSerializer:
    def test_validation(self):
        """Should validate token field correctly"""
        serializer = VerifyEmailSerializer(data={"token": "abc123"})
        assert serializer.is_valid()
        assert serializer.validated_data["token"] == "abc123"
        
# =============================================================
# LOGIN SERIALIZER
# =============================================================
class TestLoginSerializer:
    def test_validation(self):
        """Should validate email and password"""
        serializer = LoginSerializer(data={"email": "test@example.com", "password": "secret"})
        assert serializer.is_valid()
        assert serializer.validated_data["email"] == "test@example.com"
        
# =============================================================
# FORGOT PASSWORD SERIALIZER
# =============================================================
class TestForgotPasswordSerializer:
    def test_validation(self):
        """Should validate email"""
        serializer = ForgotPasswordSerializer(data={"email": "test@example.com"})
        assert serializer.is_valid()
        assert serializer.validated_data["email"] == "test@example.com"
        
# =============================================================
# CHANGE PASSWORD SERIALIZER
# =============================================================
class TestChangePasswordSerializer:
    def test_validation(self):
        """Should validate old and new password"""
        data = {"old_password": "oldpass", "new_password": "newpass123"}
        serializer = ChangePasswordSerializer(data=data)
        assert serializer.is_valid()
        assert serializer.validated_data["old_password"] == "oldpass"

# =============================================================
# USER SERIALIZER
# =============================================================
@pytest.mark.django_db
class TestUserSerializer:
    def test_avatar_url_generated(self):
        """Should return UI avatar URL when no custom avatar"""
        user = baker.make(User, username="John Doe", avatar=None)
        serializer = UserSerializer(user)
        data = serializer.data
        assert data["avatar_url"].startswith("https://ui-avatars.com/api/")
        assert "John+Doe" in data["avatar_url"]

    def test_avatar_url_custom(self):
        """Should return custom avatar URL if set"""
        user = baker.make(User, avatar="https://example.com/avatar.png")
        serializer = UserSerializer(user)
        data = serializer.data
        assert data["avatar_url"] == "https://example.com/avatar.png"
        
# =============================================================
# RESEND EMAIL VERIFICATION SERIALIZER
# =============================================================
@pytest.mark.django_db
class TestResendEmailVerificationSerializer:
    def test_valid_email(self):
        """Should attach user to validated data"""
        user = baker.make(User, email="a@example.com", is_verified=False)
        serializer = ResendEmailVerificationSerializer(data={"email": user.email})
        assert serializer.is_valid()
        assert serializer.validated_data["user"] == user
        
    def test_already_verified_email_raises_error(self):
        """Should raise error if email is already verified"""
        user = baker.make(User, email="b@example.com", is_verified=True)
        serializer = ResendEmailVerificationSerializer(data={"email": user.email})
        with pytest.raises(ValidationError):
            serializer.is_valid(raise_exception=True)
            
# =============================================================
# UPDATE AVATAR SERIALIZER
# =============================================================
@pytest.mark.django_db
class TestUpdateAvatarSerializer:
    def test_avatar_required(self):
        """Should raise error if avatar is None"""
        user = baker.make(User)
        serializer = UpdateAvatarSerializer(user, data={"avatar": None})
        with pytest.raises(ValidationError):
            serializer.is_valid(raise_exception=True)

# =============================================================
# CHANGE ROLE SERIALIZER
# =============================================================
@pytest.mark.django_db
class TestChangeRoleSerializer:
    def test_validation(self):
        """Should validate user_id and role"""
        data = {"user_id": "550e8400-e29b-41d4-a716-446655440000", "role": "ADMIN"}
        serializer = ChangeRoleSerializer(data=data)
        assert serializer.is_valid()
        assert serializer.validated_data["role"] == "ADMIN"
        
# =============================================================
# OAUTH CALLBACK SERIALIZER
# =============================================================
class TestOAuthCallbackSerializer:
    def test_validation(self):
        """Should validate code field"""
        serializer = OAuthCallbackSerializer(data={"code": "abc123"})
        assert serializer.is_valid()
        assert serializer.validated_data["code"] == "abc123"
        
# =============================================================
# REFRESH TOKEN SERIALIZER
# =============================================================
class TestRefreshTokenInputSerializer:

    def test_validation(self):
        """Should validate refresh token field"""
        serializer = RefreshTokenInputSerializer(data={"refresh": "token123"})
        assert serializer.is_valid()
        assert serializer.validated_data["refresh"] == "token123"
        
# =============================================================
# ENABLE/DISABLE 2FA SERIALIZERS
# =============================================================
@pytest.mark.django_db
class Test2FASerializers:
    def test_enable_validation(self):
        """Should validate TOTP token for enabling 2FA"""
        serializer = Enable2FASerializer(data={"token": "123456"})
        assert serializer.is_valid()
        assert serializer.validated_data["token"] == "123456"
        

    def test_disable_validation(self):
        """Should validate TOTP token for disabling 2FA"""
        serializer = Disable2FASerializer(data={"token": "654321"})
        assert serializer.is_valid()
        assert serializer.validated_data["token"] == "654321"
