import time
import secrets
import hashlib
import requests
from urllib.parse import urlencode
from django.shortcuts import redirect
from django.contrib.auth import login, authenticate
from django.utils import timezone
from django.conf import settings
from rest_framework import generics, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.parsers import MultiPartParser, FormParser
from accounts.models import User
from accounts.serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    UserSerializer,
    ForgotPasswordSerializer, 
    ResetPasswordSerializer, 
    ChangePasswordSerializer,
    VerifyEmailSerializer,
    ResendEmailVerificationSerializer,
    OAuthCallbackSerializer,
    EmptySerializer,
    UpdateAvatarSerializer,
    RefreshTokenInputSerializer,
    ChangeRoleSerializer,
    Enable2FASerializer,
    Disable2FASerializer
)
from accounts.utils import get_client_ip, generate_totp_qr_code
from core.utils import send_email, api_response
from core.constants import LOGIN_GOOGLE, LOGIN_GITHUB
from core.cloudinary import upload_to_cloudinary
from core.permissions import IsSuperAdmin

# ----------------------
# Helper function for generating JWT tokens
# ----------------------
def generate_jwt_tokens(user):
    """
    Generate JWT access and refresh tokens for a given user.
    Returns: (access_token, refresh_token)
    """
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token), str(refresh)

# ----------------------
# Register with Email Verification
# ----------------------
class RegisterView(generics.CreateAPIView):
    """
    Registers a new user and sends an email verification link.
    """
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate unique email verification token
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
        expiry = timezone.now() + timezone.timedelta(minutes=10)
        user.email_verification_token = hashed
        user.email_verification_expiry = expiry
        user.save(update_fields=["email_verification_token", "email_verification_expiry"])

        # Prepare verification link
        verify_link = f"{settings.FRONTEND_URL}/verify-email/{un_hashed}"
        send_email(
            to_email=user.email,
            subject="Verify your email",
            template_name="email_verification",
            context={"username": user.username, "verification_code": un_hashed, "verify_link": verify_link}
        )

        return api_response(
            success=True,
            message="User registered successfully. Please verify your email.",
            data={"user": UserSerializer(user).data},
            status_code=status.HTTP_201_CREATED
        )

# ----------------------
# Verify Email
# ----------------------
class VerifyEmailView(generics.GenericAPIView):
    """
    Verify a user's email using a token sent via email.
    """
    serializer_class = VerifyEmailSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        # Check if token is valid and not expired
        user = User.objects.filter(
            email_verification_token=hashed_token,
            email_verification_expiry__gt=timezone.now()
        ).first()

        if not user:
            return api_response(False, "Invalid or expired token", status_code=status.HTTP_400_BAD_REQUEST)

        # Mark user as verified
        user.is_verified = True
        user.email_verification_token = None
        user.email_verification_expiry = None
        user.save(update_fields=["is_verified", "email_verification_token", "email_verification_expiry"])

        return api_response(True, "Email verified successfully")

# ----------------------
# Login
# ----------------------
class LoginView(generics.GenericAPIView):
    """
    Authenticates a user with email and password.
    Handles 2FA if enabled.
    Returns access and refresh tokens on successful login.
    """
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        token = serializer.validated_data.get("token")

        # Authenticate user
        user = authenticate(email=email, password=password)
        if not user:
            return api_response(False, "Invalid credentials", status_code=status.HTTP_401_UNAUTHORIZED)

        # Check if email is verified
        if not user.is_verified:
            return api_response(False, "Email not verified", status_code=status.HTTP_403_FORBIDDEN)

        # 2FA verification if enabled
        if user.is_2fa_enabled:
            if not token or not user.verify_totp(token):
                return api_response(False, "Invalid or missing 2FA token", status_code=status.HTTP_400_BAD_REQUEST)

        # Login user and store session info
        login(request, user)
        request.session['ip'] = get_client_ip(request)
        request.session['user_agent'] = request.META.get("HTTP_USER_AGENT", "")

        # Generate JWT tokens
        access_token, refresh_token = generate_jwt_tokens(user)
        user.refresh_token = refresh_token
        user.save(update_fields=["refresh_token"])
        
        return api_response(
            True,
            "Login successful",
            data={
                "user": UserSerializer(user).data,
                "access_token": access_token,
                "refresh_token": refresh_token
            },
            status_code=status.HTTP_200_OK
        )

# ----------------------
# Logout
# ----------------------
class LogoutView(generics.GenericAPIView):
    """
    Logs out the authenticated user.
    Invalidates refresh token and clears session.
    """
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request.user.refresh_token = None
        request.user.save(update_fields=["refresh_token"])
        request.session.flush()
        return api_response(True, "Logged out successfully")

# ----------------------
# Refresh Token
# ----------------------
class RefreshTokenView(generics.GenericAPIView):
    """
    Refreshes the access token using a valid refresh token.
    """
    serializer_class = RefreshTokenInputSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data.get("refresh")

        user = User.objects.filter(refresh_token=refresh_token, is_active=True).first()
        if not user:
            return api_response(False, "Invalid or expired refresh token", status_code=status.HTTP_401_UNAUTHORIZED)

        try:
            token = RefreshToken(refresh_token)
            access_token = str(token.access_token)
            return api_response(True, "Token refreshed successfully", data={"access_token": access_token})
        except TokenError as e:
            return api_response(False, f"Invalid or expired refresh token: {str(e)}", status_code=status.HTTP_401_UNAUTHORIZED)

# ----------------------
# Forgot Password
# ----------------------
class ForgotPasswordView(generics.GenericAPIView):
    """
    Generates a password reset token and sends it to the user's email.
    """
    serializer_class = ForgotPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(email=serializer.validated_data["email"]).first()

        if user:
            # Generate reset token
            un_hashed = secrets.token_hex(20)
            hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
            expiry = timezone.now() + timezone.timedelta(minutes=10)
            user.forgot_password_token = hashed
            user.forgot_password_expiry = expiry
            user.save(update_fields=["forgot_password_token", "forgot_password_expiry"])

            # Send reset email
            reset_link = f"{settings.FRONTEND_URL}/reset-password/{un_hashed}"
            send_email(
                to_email=user.email,
                subject="Reset Password",
                template_name="reset_password",
                context={"username": user.username, "reset_link": reset_link}
            )

        return api_response(True, "Reset link sent successfully.")

# ----------------------
# Reset Password
# ----------------------
class ResetPasswordView(generics.GenericAPIView):
    """
    Resets the user's password using a valid token.
    """
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        # Validate token
        user = User.objects.filter(forgot_password_token=hashed_token, forgot_password_expiry__gt=timezone.now()).first()
        if not user:
            return api_response(False, "Invalid or expired token", status_code=status.HTTP_400_BAD_REQUEST)

        # Set new password
        user.set_password(serializer.validated_data["new_password"])
        user.forgot_password_token = None
        user.forgot_password_expiry = None
        user.save(update_fields=["password", "forgot_password_token", "forgot_password_expiry"])

        return api_response(True, "Password reset successful")

# ----------------------
# Change Password
# ----------------------
class ChangePasswordView(generics.GenericAPIView):
    """
    Allows an authenticated user to change their password.
    """
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check old password
        if not request.user.check_password(serializer.validated_data["old_password"]):
            return api_response(False, "Old password incorrect", status_code=status.HTTP_400_BAD_REQUEST)

        # Set new password
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save(update_fields=["password"])
        return api_response(True, "Password changed successfully")

# ----------------------
# Resend Email Verification
# ----------------------
class ResendEmailView(generics.GenericAPIView):
    """
    Resends email verification token to the user.
    """
    serializer_class = ResendEmailVerificationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        # Generate new token
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
        expiry = timezone.now() + timezone.timedelta(minutes=10)
        user.email_verification_token = hashed
        user.email_verification_expiry = expiry
        user.save(update_fields=["email_verification_token", "email_verification_expiry"])

        verify_link = f"{settings.FRONTEND_URL}/verify-email/{un_hashed}"
        send_email(
            to_email=user.email,
            subject="Verify your email",
            template_name="email_verification",
            context={"username": user.username, "verification_code": un_hashed, "verify_link": verify_link},
        )

        return api_response(True, "Verification email resent successfully.")

# ----------------------
# Current User
# ----------------------
class CurrentUserView(generics.RetrieveAPIView):
    """
    Retrieves the currently authenticated user's details.
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_object())
        return api_response(True, "Current user retrieved successfully", data=serializer.data)

# ----------------------
# Update Avatar
# ----------------------
class UpdateAvatarView(generics.UpdateAPIView):
    """
    Updates the authenticated user's avatar.
    Uploads the file to Cloudinary.
    """
    serializer_class = UpdateAvatarSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser] 
    http_method_names = ['patch']

    def get_object(self):
        return self.request.user

    def patch(self, request, *args, **kwargs):
        file = request.FILES.get("avatar")
        if not file:
            return api_response(False, "No file provided", status_code=status.HTTP_400_BAD_REQUEST)

        try:
            avatar_url = upload_to_cloudinary(file, folder="avatars")
        except Exception as e:
            return api_response(False, str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user = request.user
        user.avatar = avatar_url 
        user.save(update_fields=["avatar"])

        return api_response(True, "Avatar updated successfully", data={"avatar": avatar_url})

# ----------------------
# OAuth Callbacks (Google)
# ----------------------
class GoogleLoginView(generics.GenericAPIView):
    """
    Generates Google OAuth login URL for client.
    """
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"response_type=code&client_id={settings.GOOGLE_CLIENT_ID}"
            f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
            f"&scope=openid%20email%20profile&access_type=offline&prompt=consent"
        )
        return api_response(True, "Google login URL generated successfully", data={"auth_url": auth_url})

class GoogleLoginCallbackView(generics.GenericAPIView):
    """
    Handles Google OAuth callback.
    Authenticates or creates a user based on Google email.
    """
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        # Exchange code for access token
        token_res = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            }
        ).json()

        google_access_token = token_res.get("access_token")
        if not google_access_token:
            return api_response(False, "Failed to get access token from Google", status_code=status.HTTP_400_BAD_REQUEST)

        # Get user info
        user_info = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {google_access_token}"}
        ).json()

        email = user_info.get("email")
        username = user_info.get("name")
        if not email:
            return api_response(False, "Email not available from Google", status_code=status.HTTP_400_BAD_REQUEST)

        # Create or update user
        user, created = User.objects.get_or_create(
            email=email,
            defaults={"username": username, "is_verified": True, "login_type": LOGIN_GOOGLE}
        )
        if not created:
            user.username = username
            user.is_verified = True
            user.save(update_fields=["username", "is_verified"])

        # Generate tokens
        access_token, refresh_token = generate_jwt_tokens(user)
        user.refresh_token = refresh_token
        user.save(update_fields=["refresh_token"])

        # Redirect to frontend with tokens
        params = urlencode({"access": access_token, "refresh": refresh_token})
        return redirect(f"{settings.FRONTEND_URL}/api/v1/accounts/google/callback?{params}")

# ----------------------
# OAuth Callbacks (GitHub)
# ----------------------
class GitHubLoginView(APIView):
    """
    Generates GitHub OAuth login URL for client.
    """
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        auth_url = f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&redirect_uri={settings.GITHUB_REDIRECT_URI}&scope=user:email"
        return api_response(True, "GitHub login URL generated successfully", data={"auth_url": auth_url})

class GitHubLoginCallbackView(generics.GenericAPIView):
    """
    Handles GitHub OAuth callback.
    Authenticates or creates a user based on GitHub email.
    """
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        # Exchange code for access token
        token_res = requests.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code
            },
            headers={"Accept": "application/json"}
        ).json()

        access_token = token_res.get("access_token")
        if not access_token:
            return api_response(False, "Failed to get access token from GitHub", status_code=status.HTTP_400_BAD_REQUEST)

        # Get user info
        user_info = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"}
        ).json()

        email = user_info.get("email") or f"{user_info.get('id')}@github.com"
        username = user_info.get("login")

        # Create or update user
        user, created = User.objects.get_or_create(
            email=email,
            defaults={"username": username, "is_verified": True, "login_type": LOGIN_GITHUB}
        )
        if not created:
            user.username = username
            user.is_verified = True
            user.save(update_fields=["username", "is_verified"])

        # Generate tokens
        access_token, refresh_token = generate_jwt_tokens(user)
        user.refresh_token = refresh_token
        user.save(update_fields=["refresh_token"])

        # Redirect to frontend with tokens
        params = urlencode({"access": access_token, "refresh": refresh_token, "username": username})
        return redirect(f"{settings.FRONTEND_URL}/github/callback?{params}")

# ----------------------
# Role Management
# ----------------------
class ChangeRoleView(generics.GenericAPIView):
    """
    Allows SuperAdmin to change the role of another user.
    Cannot change own role or other SuperAdmin's role.
    """
    serializer_class = ChangeRoleSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        role = serializer.validated_data["role"]
        
        if str(request.user.id) == str(user_id):
            return api_response(
                False,
                "SuperAdmin cannot change their own role.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(id=user_id, is_active=True)
        except User.DoesNotExist:
            return api_response(False, "User not found", status_code=status.HTTP_404_NOT_FOUND)
        
        if user.role == "SUPERADMIN":
            return api_response(
                False,
                "You cannot change the role of another SuperAdmin.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        user.role = role
        user.save(update_fields=["role"])

        return api_response(True, f"Role updated successfully to {role}", data={"user_id": user.id, "role": user.role})

# ----------------------
# 2FA Management
# ----------------------
class Setup2FAView(APIView):
    """
    Generates a TOTP secret and QR code for 2FA setup.
    """
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        if user.is_2fa_enabled:
            return api_response(False, "2FA is already enabled.")

        if not user.totp_secret:
            user.generate_totp_secret()

        totp_uri = user.get_totp_uri()
        qr_code_base64 = generate_totp_qr_code(totp_uri)

        return api_response(
            True,
            "TOTP secret generated successfully.",
            data={"totp_uri": totp_uri, "qr_code": qr_code_base64}
        )

class Enable2FAView(generics.GenericAPIView):
    """
    Enables 2FA for the user after validating the TOTP token.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = Enable2FASerializer

    def post(self, request):
        user = request.user

        if user.is_2fa_enabled:
            return api_response(False, "2FA is already enabled.")
        
        serializer = Enable2FASerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        
        if user.verify_totp(token):
            user.is_2fa_enabled = True
            user.save(update_fields=["is_2fa_enabled"])
            return api_response(True, "2FA enabled successfully.")
        
        return api_response(False, "Invalid TOTP token.", status_code=status.HTTP_400_BAD_REQUEST)

class Disable2FAView(generics.GenericAPIView):
    """
    Disables 2FA for the user after validating the TOTP token.
    """
    serializer_class = Disable2FASerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]

        if user.verify_totp(token):
            user.is_2fa_enabled = False
            user.totp_secret = None
            user.save(update_fields=["is_2fa_enabled", "totp_secret"])
            return api_response(True, "2FA disabled successfully.")

        return api_response(False, "Invalid TOTP token.", status_code=status.HTTP_400_BAD_REQUEST)
