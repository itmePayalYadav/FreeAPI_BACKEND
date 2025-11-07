import pytest
from django.core.exceptions import ValidationError
from accounts.models import User, UserManager
from model_bakery import baker
from core.constants import ROLE_SUPERADMIN

pytestmark = pytest.mark.django_db

# =============================================================
# USER MANAGER TESTS
# =============================================================
class TestUserManager:
    # =============================================================
    # _CREATE_USER
    # =============================================================
    def test_create_user_missing_email_raises_error(self):
        with pytest.raises(ValueError, match="Email must be provided"):
            User.objects._create_user(email=None, username="test", password="pass")
            
    def test_create_user_missing_username_raises_error(self):
        with pytest.raises(ValueError, match="Username must be provided"):
            User.objects._create_user(email="a@test.com", username=None, password="pass")
    
    # =============================================================
    # CREATE USER
    # =============================================================
    def test_create_user_defaults(self):
        user = User.objects.create_user(email="user@test.com", username="user1", password="secret")
        assert user.email == "user@test.com"
        assert user.username == "user1"
        assert user.check_password("secret")
        assert user.is_staff is False
        assert user.is_superuser is False
    
    # =============================================================
    # CREATE SUPERUSER
    # =============================================================
    def test_create_superuser_flags_and_role(self):
        superuser = User.objects.create_superuser(email="admin@test.com", username="admin", password="secret")
        assert superuser.is_staff is True
        assert superuser.is_superuser is True
        assert superuser.is_verified is True
        assert superuser.role == ROLE_SUPERADMIN
        assert superuser.check_password("secret")
        
    # =============================================================
    # ACTIVE USER MANAGER TESTS
    # =============================================================
    class TestActiveUserManager:
        def test_active_manager_only_returns_active_users(self):
            active_user = baker.make(User, is_active=True)
            inactive_user = baker.make(User, is_active=False)
            queryset = User.active_objects.all()
            assert active_user in queryset
            assert inactive_user not in queryset
