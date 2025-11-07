import pytest
import secrets
import hashlib
from datetime import timedelta
from unittest.mock import patch
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from accounts.models import User

pytestmark = pytest.mark.django_db

class TestIntegratedAuthFlows:
    """Integrated tests simulating full user journeys across multiple endpoints."""

    def test_complete_registration_to_login_flow(self, api_client, user_data, mock_send_email):
        # -----------------------------
        # Registration
        # -----------------------------
        register_url = reverse('accounts:register')
        response = api_client.post(register_url, user_data)
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['success'] is True

        user = User.objects.get(email=user_data['email'])
        assert user.is_verified is False
        mock_send_email.assert_called_once()

        # -----------------------------
        # Email Verification
        # -----------------------------
        verify_url = reverse('accounts:verify-email')
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
        user.email_verification_token = hashed
        user.email_verification_expiry = timezone.now() + timedelta(minutes=10)
        user.save()

        response = api_client.post(verify_url, {"token": un_hashed})
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.is_verified is True

        # -----------------------------
        # Login
        # -----------------------------
        login_url = reverse('accounts:login')
        login_data = {"email": user_data["email"], "password": user_data["password"]}
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = user
            response = api_client.post(login_url, login_data)
            assert response.status_code == status.HTTP_200_OK

            access_token = response.data['data']['access_token']
            refresh_token = response.data['data']['refresh_token']

        # -----------------------------
        # Access current user
        # -----------------------------
        current_user_url = reverse('accounts:current-user')
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = api_client.get(current_user_url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['data']['email'] == user_data['email']

        # -----------------------------
        # Refresh token
        # -----------------------------
        refresh_url = reverse('accounts:refresh-token')
        response = api_client.post(refresh_url, {"refresh": refresh_token})
        assert response.status_code == status.HTTP_200_OK
        new_access_token = response.data['data']['access_token']

        # -----------------------------
        # Use new access token
        # -----------------------------
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        response = api_client.get(current_user_url)
        assert response.status_code == status.HTTP_200_OK

        # -----------------------------
        # Logout
        # -----------------------------
        logout_url = reverse('accounts:logout')
        response = api_client.post(logout_url)
        assert response.status_code == status.HTTP_200_OK


    def test_password_reset_flow(self, api_client, verified_user, mock_send_email):
        """Complete password reset flow"""

        # -----------------------------
        # Step 1: Request reset password link
        # -----------------------------
        forgot_url = reverse('accounts:forgot-password')
        response = api_client.post(forgot_url, {"email": verified_user.email})
        assert response.status_code == status.HTTP_200_OK
        mock_send_email.assert_called_once()

        # -----------------------------
        # Step 2: Simulate token generation and reset password
        # -----------------------------
        reset_url = reverse('accounts:reset-password')
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()

        verified_user.forgot_password_token = hashed
        verified_user.forgot_password_expiry = timezone.now() + timedelta(minutes=10)
        verified_user.save(update_fields=["forgot_password_token", "forgot_password_expiry"])

        new_password = "new_secure_password_123"
        reset_data = {"token": un_hashed, "new_password": new_password}
        response = api_client.post(reset_url, reset_data)
        assert response.status_code == status.HTTP_200_OK
        verified_user.refresh_from_db()
        assert verified_user.check_password(new_password) is True

        # -----------------------------
        # Step 3: Login with new password
        # -----------------------------
        login_url = reverse('accounts:login')
        login_data = {"email": verified_user.email, "password": new_password}
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = verified_user
            response = api_client.post(login_url, login_data)

        assert response.status_code == status.HTTP_200_OK
        assert 'access_token' in response.data['data']
        assert 'refresh_token' in response.data['data']


    def test_2fa_complete_flow(self, api_client, user_with_secret, mock_generate_qr_code):
        """Complete 2FA setup, login, and disable flow"""

        # -----------------------------
        # Step 1: Setup 2FA (generate TOTP & QR code)
        # -----------------------------
        api_client.force_authenticate(user=user_with_secret)
        setup_url = reverse('accounts:2fa-setup')
        response = api_client.get(setup_url)
        assert response.status_code == status.HTTP_200_OK
        assert 'qr_code' in response.data['data']
        assert 'totp_uri' in response.data['data']
        mock_generate_qr_code.assert_called_once()

        # -----------------------------
        # Step 2: Enable 2FA
        # -----------------------------
        enable_url = reverse('accounts:2fa-enable')
        with patch.object(user_with_secret, 'verify_totp', return_value=True):
            response = api_client.post(enable_url, {"token": "123456"})
        assert response.status_code == status.HTTP_200_OK
        user_with_secret.refresh_from_db()
        assert user_with_secret.is_2fa_enabled is True

        # -----------------------------
        # Step 3: Login with 2FA
        # -----------------------------
        api_client.force_authenticate(user=None)
        login_url = reverse('accounts:login')
        login_data = {
            "email": user_with_secret.email,
            "password": "testpass123",
            "token": "123456"  # 2FA token
        }
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = user_with_secret
            with patch.object(user_with_secret, 'verify_totp', return_value=True):
                response = api_client.post(login_url, login_data)
        assert response.status_code == status.HTTP_200_OK
        assert 'access_token' in response.data['data']
        assert 'refresh_token' in response.data['data']

        # -----------------------------
        # Step 4: Disable 2FA
        # -----------------------------
        api_client.force_authenticate(user=user_with_secret)
        disable_url = reverse('accounts:2fa-disable')
        with patch.object(user_with_secret, 'verify_totp', return_value=True):
            response = api_client.post(disable_url, {"token": "123456"})
        assert response.status_code == status.HTTP_200_OK
        user_with_secret.refresh_from_db()
        assert user_with_secret.is_2fa_enabled is False
        assert user_with_secret.totp_secret is None


    def test_user_profile_complete_flow(
        self, api_client, verified_user, mock_upload_to_cloudinary, mock_image_file
    ):
        """Complete user profile flow: current user, avatar update, and password change"""

        # -----------------------------
        # Authenticate user
        # -----------------------------
        api_client.force_authenticate(user=verified_user)

        # -----------------------------
        # Step 1: Get current user
        # -----------------------------
        current_user_url = reverse('accounts:current-user')
        response = api_client.get(current_user_url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['data']['email'] == verified_user.email

        # -----------------------------
        # Step 2: Update avatar
        # -----------------------------
        avatar_url = reverse('accounts:update-avatar')
        response = api_client.patch(
            avatar_url, {"avatar": mock_image_file}, format='multipart'
        )
        assert response.status_code == status.HTTP_200_OK
        assert 'avatar' in response.data['data']
        mock_upload_to_cloudinary.assert_called_once()

        # -----------------------------
        # Step 3: Change password
        # -----------------------------
        change_password_url = reverse('accounts:change-password')
        response = api_client.post(
            change_password_url,
            {
                "old_password": "testpass123",
                "new_password": "new_secure_password_456"
            }
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

        # -----------------------------
        # Step 4: Verify login with new password
        # -----------------------------
        api_client.force_authenticate(user=None)
        login_url = reverse('accounts:login')
        login_data = {
            "email": verified_user.email,
            "password": "new_secure_password_456"
        }
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = verified_user
            response = api_client.post(login_url, login_data)
        assert response.status_code == status.HTTP_200_OK
        assert 'access_token' in response.data['data']
        assert 'refresh_token' in response.data['data']


class TestErrorScenarios:
    """Integrated error and edge case tests"""

    def test_token_compromise_scenario(self, api_client, verified_user):
        """Verify that refresh tokens cannot be used after logout"""
        login_url = reverse('accounts:login')
        login_data = {"email": verified_user.email, "password": "testpass123"}

        # Login
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = verified_user
            response = api_client.post(login_url, login_data)
        assert response.status_code == status.HTTP_200_OK
        access_token = response.data['data']['access_token']
        refresh_token = response.data['data']['refresh_token']

        # Access current user with access token
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        current_user_url = reverse('accounts:current-user')
        response = api_client.get(current_user_url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['data']['email'] == verified_user.email

        # Logout user (invalidate refresh token)
        logout_url = reverse('accounts:logout')
        response = api_client.post(logout_url)
        assert response.status_code == status.HTTP_200_OK

        # Attempt to refresh token after logout
        refresh_url = reverse('accounts:refresh-token')
        response = api_client.post(refresh_url, {"refresh": refresh_token})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.data['success'] is False

    def test_concurrent_sessions_scenario(self, api_client, verified_user):
        """Verify multiple simultaneous sessions with separate tokens"""
        login_url = reverse('accounts:login')
        login_data = {"email": verified_user.email, "password": "testpass123"}

        # First login
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = verified_user
            response1 = api_client.post(login_url, login_data)
        token1 = response1.data['data']['access_token']
        assert response1.status_code == status.HTTP_200_OK

        # Second login
        with patch('accounts.views.authenticate') as mock_authenticate:
            mock_authenticate.return_value = verified_user
            response2 = api_client.post(login_url, login_data)
        token2 = response2.data['data']['access_token']
        assert response2.status_code == status.HTTP_200_OK

        # Both tokens should be valid independently
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token1}')
        response = api_client.get(reverse('accounts:current-user'))
        assert response.status_code == status.HTTP_200_OK

        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token2}')
        response = api_client.get(reverse('accounts:current-user'))
        assert response.status_code == status.HTTP_200_OK
