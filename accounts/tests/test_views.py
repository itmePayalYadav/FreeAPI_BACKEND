import pytest
import secrets
import hashlib
from datetime import timedelta
from unittest.mock import patch, MagicMock
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.models import User

pytestmark = pytest.mark.django_db

class TestRegisterView:
    def test_register_success(self, api_client, user_data, mock_send_email):
        url = reverse('accounts:register')
        response = api_client.post(url, user_data)
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['success'] is True
        assert "User registered successfully" in response.data['message']
        
        user = User.objects.get(email=user_data['email'])
        assert user.email == user_data['email']
        assert user.check_password(user_data['password'])
        assert user.is_verified is False
        
        mock_send_email.assert_called_once()
        
    def test_register_duplicate_email(self, api_client, user, user_data):
        url = reverse('accounts:register')
        response = api_client.post(url, user_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        
    def test_register_invalid_data(self, api_client):
        url = reverse('accounts:register')
        invalid_data = {"email": "invalid", "password": "123"}
        response = api_client.post(url, invalid_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

class TestVerifyEmailView:
    def test_verify_email_success(self, api_client, user):
        url = reverse('accounts:verify-email')
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()

        user.email_verification_token = hashed
        user.email_verification_expiry = timezone.now() + timedelta(minutes=10)
        user.save()
        
        response = api_client.post(url, {"token": un_hashed})
        assert response.status_code == status.HTTP_200_OK

        user.refresh_from_db()
        assert user.is_verified is True
        assert user.email_verification_token is None

    def test_verify_email_invalid_token(self, api_client):
        url = reverse('accounts:verify-email')
        response = api_client.post(url, {"token": "invalid"})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_verify_email_expired_token(self, api_client, user):
        url = reverse('accounts:verify-email')
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()

        user.email_verification_token = hashed
        user.email_verification_expiry = timezone.now() - timedelta(minutes=10)
        user.save()
    
        response = api_client.post(url, {"token": un_hashed})
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

class TestLoginView:
    def test_login_success(self, api_client, verified_user, user_data):
        url = reverse('accounts:login')
        login_data = {"email": user_data["email"], "password": user_data["password"]}

        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = verified_user
            response = api_client.post(url, login_data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert response.data['message'] == "Login successful"

        assert 'access_token' in response.data['data']
        assert 'refresh_token' in response.data['data']

        user = response.data['data']['user']
        assert user['email'] == user_data['email']
        assert user['is_verified'] is True

    def test_login_invalid_credentials(self, api_client):
        url = reverse('accounts:login')
        login_data = {"email": "wrong@example.com", "password": "wrong"}
        
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = None
            response = api_client.post(url, login_data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.data['success'] is False
    
    def test_login_unverified_email(self, api_client, user, user_data):
        url = reverse('accounts:login')
        login_data = {"email": user_data["email"], "password": user_data["password"]}
        
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = user
            response = api_client.post(url, login_data)
            
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.data['success'] is False

    def test_login_with_2fa_success(self, api_client, user_with_2fa, user_data):
        url = reverse('accounts:login')
        user_with_2fa.is_2fa_enabled = True
        user_with_2fa.save()

        login_data = {"email": user_data["email"], "password": user_data["password"], "token": "123456"}

        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = user_with_2fa
            with patch.object(user_with_2fa, "verify-totp", return_value=True):
                response = api_client.post(url, login_data)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        
    def test_login_with_2fa_success(self, api_client, user_with_2fa, user_data):
        url = reverse('accounts:login')
        user_with_2fa.is_2fa_enabled = True
        user_with_2fa.save()

        login_data = {
            "email": user_data["email"],
            "password": user_data["password"],
            "token": "123456"
        }

        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = user_with_2fa
            with patch.object(user_with_2fa, "verify_totp", return_value=True):
                response = api_client.post(url, login_data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

class TestLogoutView:
    def test_logout_success(self, authenticated_client, verified_user):
        url = reverse('accounts:logout')
        verified_user.refresh_token = "test_refresh_token"
        verified_user.save()
        
        response = authenticated_client.post(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

        verified_user.refresh_from_db()
        assert verified_user.refresh_token is None
        
    def test_logout_unauthenticated(self, api_client):
        url = reverse('accounts:logout')
        response = api_client.post(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

class TestRefreshTokenView:
    def test_refresh_token_success(self, api_client, verified_user):
        refresh = RefreshToken.for_user(verified_user)
        verified_user.refresh_token = str(refresh)
        verified_user.save(update_fields=["refresh_token"])

        url = reverse('accounts:refresh-token')
        response = api_client.post(url, {"refresh": str(refresh)})

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert 'access_token' in response.data['data']

    def test_refresh_token_invalid(self, api_client):
        url = reverse('accounts:refresh-token')
        response = api_client.post(url, {"refresh": "invalid"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.data['success'] is False

class TestResendEmailVerificationView:
    def test_resend_email_success(self, api_client, user, mock_send_email):
        url = reverse('accounts:resend-email')
        response = api_client.post(url, {"email": user.email})
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        mock_send_email.assert_called_once()
        
        user.refresh_from_db()
        assert user.email_verification_token is not None
        
    def test_resend_email_already_verified(self, api_client, verified_user):
        url = reverse('accounts:resend-email')
        response = api_client.post(url, {"email": verified_user.email})
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    def test_resend_email_nonexistent(self, api_client):
        url = reverse('accounts:resend-email')
        response = api_client.post(url, {"email": "nonexistent@example.com"})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

class TestForgotPasswordView:
    def test_forgot_password_success(self, api_client, verified_user, mock_send_email):
        """Test successful forgot password request"""
        url = reverse('accounts:forgot-password')
        response = api_client.post(url, { "email": verified_user.email })
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

        mock_send_email.assert_called_once()
        
        verified_user.refresh_from_db()
        assert verified_user.forgot_password_token is not None
    
    def test_forgot_password_nonexistent_email(self, api_client, mock_send_email):
        """Test forgot password with nonexistent email"""
        
        url = reverse('accounts:forgot-password')
        response = api_client.post(url, {"email": "nonexistent@example.com"})

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        mock_send_email.assert_not_called()

class TestResetPasswordView:
    def test_reset_password_success(self, api_client, verified_user):
        """Test successful password reset"""
        url = reverse('accounts:reset-password')
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
    
        verified_user.forgot_password_token = hashed
        verified_user.forgot_password_expiry = timezone.now() + timedelta(minutes=10)
        verified_user.save()

        reset_data = {
            "token": un_hashed,
            "new_password": "newpassword123"
        }
        
        response = api_client.post(url, reset_data)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        
        verified_user.refresh_from_db()
        assert verified_user.forgot_password_token is None
        assert verified_user.check_password("newpassword123")

    def test_reset_password_invalid_token(self, api_client):
        """Test password reset with invalid token"""
        url = reverse('accounts:reset-password')
        reset_data = {
            "token": "invalid",
            "new_password": "newpassword123"
        }
        response = api_client.post(url, reset_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['success'] is False

    def test_reset_password_expired_token(self, api_client, verified_user):
        """Test password reset with expired token"""
        url = reverse('accounts:reset-password')
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()

        verified_user.forgot_password_token = hashed
        verified_user.forgot_password_expiry = timezone.now() - timedelta(minutes=10)
        verified_user.save()

        reset_data = {
            "token": un_hashed,
            "new_password": "newpassword123"
        }
        response = api_client.post(url, reset_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['success'] is False

class TestChangePasswordView:
    def test_change_password_success(self, authenticated_client, verified_user, user_data):
        """Test successful password change"""
        authenticated_client.force_authenticate(user=verified_user)

        url = reverse('accounts:change-password')
        change_data = {
            "old_password": user_data["password"],
            "new_password": "newpassword123"
        }
        response = authenticated_client.post(url, change_data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

        verified_user.refresh_from_db()
        assert verified_user.check_password("newpassword123")

    def test_change_password_wrong_old_password(self, authenticated_client):
        """Test password change with wrong old password"""
        url = reverse('accounts:change-password')
        change_data = {
            "old_password": "wrongpassword",
            "new_password": "newpassword123"
        }
        response = authenticated_client.post(url, change_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['success'] is False
    
    def test_change_password_unauthenticated(self, api_client):
        """Test password change without authentication"""
        url = reverse('accounts:change-password')
        change_data = {
            "old_password": "oldpass",
            "new_password": "newpass"
        }
        response = api_client.post(url, change_data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

class TestCurrentUserView:
    def test_get_current_user_success(self, authenticated_client, verified_user):
        """Test successful retrieval of current user"""
        url = reverse('accounts:current-user')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert response.data['data']['email'] == verified_user.email
        assert response.data['data']['username'] == verified_user.username

    def test_get_current_user_unauthenticated(self, api_client):
        """Test getting current user without authentication"""
        url = reverse('accounts:current-user')
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

class TestUpdateAvatarView:
    def test_update_avatar_success(self, authenticated_client, mock_upload_to_cloudinary, mock_image_file):
        """Test successful avatar update"""
        url = reverse('accounts:update-avatar')  
        response = authenticated_client.patch(
            url,
            {"avatar": mock_image_file},
            format='multipart'
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        mock_upload_to_cloudinary.assert_called_once()

    def test_update_avatar_no_file(self, authenticated_client):
        """Test avatar update without file"""
        url = reverse('accounts:update-avatar')
        response = authenticated_client.patch(url, {})
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['success'] is False

    def test_update_avatar_upload_error(self, authenticated_client, mock_upload_to_cloudinary, mock_image_file):
        """Test avatar update with upload error"""
        mock_upload_to_cloudinary.side_effect = Exception("Upload failed")
        url = reverse('accounts:update-avatar')
        
        response = authenticated_client.patch(
            url,
            {"avatar": mock_image_file},
            format='multipart'
        )

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.data['success'] is False

class TestOAuthViews:
    def test_google_login_url(self, api_client):
        """Test Google login URL generation"""
        url = reverse("accounts:google-login")
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert 'auth_url' in response.data['data']
        assert 'accounts.google.com' in response.data['data']['auth_url']

    def test_github_login_url(self, api_client):
        """Test GitHub login URL generation"""
        url = reverse("accounts:github-login") 
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert 'auth_url' in response.data['data']
        assert 'github.com' in response.data['data']['auth_url']

    @patch('accounts.views.requests')
    def test_google_callback_success(self, mock_requests, api_client):
        """Test successful Google OAuth callback"""
        url = reverse("accounts:google-callback")  
        
        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {"access_token": "google_token"}
        mock_user_response = MagicMock()
        mock_user_response.json.return_value = {
            "email": "oauth@example.com",
            "name": "OAuth User"
        }
        
        mock_requests.post.return_value = mock_token_response
        mock_requests.get.return_value = mock_user_response
        
        response = api_client.get(f"{url}?code=test-code")
        
        assert response.status_code == 302
        assert 'access' in response.url
        assert 'refresh' in response.url

    @patch('accounts.views.requests')
    def test_github_callback_success(self, mock_requests, api_client):
        """Test successful GitHub OAuth callback"""
        url = reverse("accounts:github-callback") 
        
        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {"access_token": "github_token"}
        mock_user_response = MagicMock()
        mock_user_response.json.return_value = {
            "email": "github@example.com",
            "login": "githubuser",
            "id": 12345
        }
        
        mock_requests.post.return_value = mock_token_response
        mock_requests.get.return_value = mock_user_response
        
        response = api_client.get(f"{url}?code=test-code")
        
        assert response.status_code == 302
        assert 'access' in response.url
        assert 'refresh' in response.url

class TestChangeRoleView:
    def test_change_role_success(self, api_client, superuser, change_password):
        """Superadmin can successfully change a user's role"""
        api_client.force_authenticate(user=superuser)
        print(f"User id is available or not ", change_password.id)
        change_data = {
            "user_id": str(change_password.id),
            "role": "ADMIN"
        }
        url = reverse("accounts:change-role")
        response = api_client.patch(url, change_data)

        assert response.status_code == status.HTTP_200_OK
    
    def test_change_role_self(self, api_client, superuser):
        """Superadmin cannot change their own role"""
        api_client.force_authenticate(user=superuser)

        change_data = {
            "user_id": str(superuser.id),
            "role": "USER"
        }
        url = reverse("accounts:change-role")
        response = api_client.patch(url, change_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['success'] is False

    def test_change_role_nonexistent_user(self, api_client, superuser):
        """Changing role for nonexistent user returns 404"""
        api_client.force_authenticate(user=superuser)

        change_data = {
            "user_id": "12345678-1234-1234-1234-123456789012",
            "role": "ADMIN"
        }
        url = reverse("accounts:change-role")
        response = api_client.patch(url, change_data)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data['success'] is False
        
    def test_change_role_other_superadmin(self, api_client, superuser, change_password):
        """Cannot change role of another superadmin"""
        other_superadmin = User.objects.create(
            email="other@example.com",
            username="otheradmin",
            is_staff=True,
            is_superuser=True,
            is_verified=True,
            role="SUPERADMIN",
            password="testpass123"
        )
        api_client.force_authenticate(user=superuser)
        change_data = {
            "user_id": str(other_superadmin.id),
            "role": "USER"
        }
        url = reverse("accounts:change-role")
        response = api_client.patch(url, change_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['success'] is False

    def test_change_role_unauthorized(self, authenticated_client, change_password):
        """Non-superadmin users cannot change roles"""
        change_data = {
            "user_id": str(change_password.id),
            "role": "ADMIN"
        }
        url = reverse("accounts:change-role")
        response = authenticated_client.patch(url, change_data)

        assert response.status_code == status.HTTP_403_FORBIDDEN

class Test2FAViews:
    def test_setup_2fa_success(self, authenticated_client, verified_user, mock_generate_qr_code):
        """Test successful 2FA setup initialization"""
        url = reverse("accounts:2fa-setup")
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK

    def test_setup_2fa_already_enabled(self, authenticated_client, user_with_2fa):
        """Test setup when 2FA is already enabled"""
        url = reverse("accounts:2fa-setup")
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
    
    def test_setup_2fa_reuses_existing_secret(self, authenticated_client, user_with_secret):
        """Test setup reuses existing TOTP secret"""
        original_secret = user_with_secret.totp_secret
        url = reverse("accounts:2fa-setup")
        
        response = authenticated_client.get(url)
        user_with_secret.refresh_from_db()
        
        assert response.status_code == status.HTTP_200_OK
        assert user_with_secret.totp_secret == original_secret
        
    def test_setup_2fa_unauthenticated(self, client):
        """Test unauthenticated access to setup"""
        url = reverse("accounts:2fa-setup")
        response = client.get(url)
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    # -------------------------
    # Enable2FAView tests
    # -------------------------
    def test_enable_2fa_success(self, authenticated_client_with_secret, user_with_secret):
        """Test successful 2FA enablement"""
        with patch.object(user_with_secret, "verify_totp", return_value=True) as mock_verify:
            url = reverse("accounts:2fa-enable")
            data = {"token": "123456"}

            response = authenticated_client_with_secret.post(url, data)
            user_with_secret.refresh_from_db()

            assert response.status_code == 200
            assert response.data['success'] is True
            assert user_with_secret.is_2fa_enabled is True
            mock_verify.assert_called_once_with("123456")
    
    def test_enable_2fa_invalid_token(self, authenticated_client_with_secret, user_with_secret):
        """Test enablement with invalid token"""
        with patch.object(user_with_secret, "verify_totp", return_value=False) as mock_verify:
            url = reverse("accounts:2fa-enable")
            data = {"token": "wrong"}
            
            response = authenticated_client_with_secret.post(url, data)
            user_with_secret.refresh_from_db()
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert response.data['success'] is False
            assert user_with_secret.is_2fa_enabled is False
            mock_verify.assert_called_once_with("wrong")

    def test_enable_2fa_already_enabled(self, authenticated_client_with_2fa, user_with_2fa):
        """Test enablement when 2FA is already enabled"""
        url = reverse("accounts:2fa-enable")
        data = {"token": "123456"}
        
        response = authenticated_client_with_2fa.post(url, data)
        user_with_2fa.refresh_from_db()
        
        assert response.status_code == status.HTTP_200_OK
        assert "already enabled" in response.data['message']
        assert user_with_2fa.is_2fa_enabled is True
        
    def test_enable_2fa_no_secret(self, authenticated_client, verified_user):
        """Test enablement without existing TOTP secret"""
        url = reverse("accounts:2fa-enable")
        data = {"token": "123456"}
        
        response = authenticated_client.post(url, data)
        verified_user.refresh_from_db()
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    # -------------------------
    # Disable2FAView tests
    # -------------------------
    def test_disable_2fa_success(self, authenticated_client_with_2fa, user_with_2fa):
        """Test successful 2FA disablement"""
        with patch.object(user_with_2fa, "verify_totp", return_value=True) as mock_verify:
            url = reverse("accounts:2fa-disable")
            data = {"token": "123456"}
            
            response = authenticated_client_with_2fa.post(url, data)
            user_with_2fa.refresh_from_db()
            
            assert response.status_code == status.HTTP_200_OK
            assert user_with_2fa.is_2fa_enabled is False
            assert user_with_2fa.totp_secret is None
            mock_verify.assert_called_once_with("123456")
            
    def test_disable_2fa_invalid_token(self, authenticated_client_with_2fa, user_with_2fa):
        """Test disablement with invalid token"""
        with patch.object(user_with_2fa, "verify_totp", return_value=False) as mock_verify:
            url = reverse("accounts:2fa-disable")
            data = {"token": "wrong"}
            
            response = authenticated_client_with_2fa.post(url, data)
            user_with_2fa.refresh_from_db()
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert user_with_2fa.is_2fa_enabled is True
            mock_verify.assert_called_once_with("wrong")

    def test_disable_2fa_invalid_data(self, authenticated_client_with_2fa, user_with_2fa):
        """Test disablement with missing token"""
        url = reverse("accounts:2fa-disable")
        data = {} 
        
        response = authenticated_client_with_2fa.post(url, data)
        user_with_2fa.refresh_from_db()
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert user_with_2fa.is_2fa_enabled is True
        
    def test_disable_2fa_not_enabled(self, authenticated_client, verified_user):
        """Test disablement when 2FA is not enabled"""
        url = reverse("accounts:2fa-disable")
        data = {"token": "123456"}
        
        response = authenticated_client.post(url, data)
        verified_user.refresh_from_db()
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

