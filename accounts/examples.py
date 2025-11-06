# views.py
from django.shortcuts import redirect
from urllib.parse import urlencode
from django.contrib.auth import login, authenticate
from django.utils import timezone
from django.conf import settings
from rest_framework import generics, status, permissions
from rest_framework.views import APIView
import jwt, hashlib, secrets, requests

from .models import User
from .serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    UserSerializer,
    ForgotPasswordSerializer, 
    ResetPasswordSerializer, 
    ChangePasswordSerializer,
    VerifyEmailSerializer,
    ResendEmailVerificationSerializer,
    UpdateAvatarSerializer,
    ChangeRoleSerializer,
    OAuthCallbackSerializer,
    Enable2FASerializer,    
    Disable2FASerializer,    
    LoginOTPSerializer,
    EmptySerializer,
    RefreshTokenInputSerializer,
    SessionKeySerializer
)
from core.utils import send_email, api_response
from core.permissions import IsSuperAdmin, IsAdminOrSuperAdmin, IsOwnerOrAdmin
from core.constants import LOGIN_GOOGLE, LOGIN_GITHUB
from accounts.utils import get_user_sessions, revoke_session, revoke_all_sessions, get_client_ip, generate_totp_qr_code

# ----------------------
# Register with email verification
# ----------------------
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate email verification token
        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
        expiry = timezone.now() + timezone.timedelta(minutes=10)  # Configurable in settings

        user.email_verification_token = hashed
        user.email_verification_expiry = expiry
        user.save(update_fields=["email_verification_token", "email_verification_expiry"])

        # Send verification email
        verify_link = f"{settings.FRONTEND_URL}/verify-email/{un_hashed}"
        send_email(
            to_email=user.email,
            subject="Verify your email",
            template_name="email_verification",
            context={"username": user.username, "verification_code": un_hashed}
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
    serializer_class = VerifyEmailSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        # Fetch user with valid token and expiry
        user = User.objects.filter(
            email_verification_token=hashed_token,
            email_verification_expiry__gt=timezone.now()
        ).first()

        if not user:
            return api_response(success=False, message="Invalid or expired token", status_code=status.HTTP_400_BAD_REQUEST)

        # Mark user as verified
        user.is_verified = True
        user.email_verification_token = None
        user.email_verification_expiry = None
        user.save(update_fields=["is_verified", "email_verification_token", "email_verification_expiry"])

        return api_response(success=True, message="Email verified successfully")


# ----------------------
# Login
# ----------------------
class LoginView(generics.GenericAPIView):
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

        if not user.is_verified:
            return api_response(False, "Email not verified", status_code=status.HTTP_403_FORBIDDEN)

        # If 2FA enabled, check TOTP token
        if user.is_2fa_enabled:
            if not token:
                return api_response(False, "2FA token required", status_code=status.HTTP_400_BAD_REQUEST)
            if not user.verify_totp(token):
                return api_response(False, "Invalid 2FA token", status_code=status.HTTP_400_BAD_REQUEST)

        # Set session info
        login(request, user)
        ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        request.session['ip'] = ip
        request.session['user_agent'] = user_agent

        # Generate tokens
        access_token = user.generate_access_token()
        refresh_token = user.generate_refresh_token()
        user.refresh_token = refresh_token
        user.save(update_fields=["refresh_token"])

        return api_response(
            True,
            "Login successful",
            data={
                "user":UserSerializer(user).data,
                "access_token": access_token,
                "refresh_token": refresh_token
            },
            status_code=status.HTTP_200_OK
        )

# ----------------------
# Logout
# ----------------------
class LogoutView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request.user.refresh_token = None
        request.user.save(update_fields=["refresh_token"])
        request.session.flush()  
        return api_response(success=True, message="Logged out successfully")


# ----------------------
# Refresh token
# ----------------------
class RefreshTokenView(generics.GenericAPIView):
    serializer_class = RefreshTokenInputSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh = request.data.get("refresh")
        if not refresh:
            return api_response(success=False, message="Refresh token required", status_code=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(refresh, settings.SECRET_KEY, algorithms=["HS256"])
            exp_timestamp = payload.get("exp")
            if not exp_timestamp or time.time() > exp_timestamp:
                return api_response(False, "Refresh token has expired.", status_code=status.HTTP_401_UNAUTHORIZED)
            user_id = payload.get("id")
            user = User.objects.filter(id=user_id, is_active=True).first()
            if not user:
                return api_response(False, "User not found or inactive.", status_code=status.HTTP_404_NOT_FOUND)
            access_token = user.generate_access_token()
            return api_response(True, "Token refreshed successfully.", data={"access_token": access_token}, status_code=status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError:
            return api_response(False, "Refresh token has expired.", status_code=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return api_response(False, "Invalid refresh token.", status_code=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return api_response(False, f"Error: {str(e)}", status_code=status.HTTP_400_BAD_REQUEST)

# ----------------------
# Forgot Password
# ----------------------
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(email=serializer.validated_data["email"]).first()

        if user:
            un_hashed = secrets.token_hex(20)
            hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
            expiry = timezone.now() + timezone.timedelta(minutes=10)

            user.forgot_password_token = hashed
            user.forgot_password_expiry = expiry
            user.save(update_fields=["forgot_password_token", "forgot_password_expiry"])

            reset_link = f"{settings.FRONTEND_URL}/reset-password/{un_hashed}"
            send_email(
                to_email=user.email, 
                subject="Reset Password", 
                template_name="reset_password",
                context={"username": user.username, "reset_link": reset_link}
            )

        return api_response(success=True, message="Reset link sent successfully.")


# ----------------------
# Reset Password
# ----------------------
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
        user = User.objects.filter(forgot_password_token=hashed_token, forgot_password_expiry__gt=timezone.now()).first()

        if not user:
            return api_response(success=False, message="Invalid or expired token", status_code=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data["new_password"])
        user.forgot_password_token = None
        user.forgot_password_expiry = None
        user.save(update_fields=["password", "forgot_password_token", "forgot_password_expiry"])

        return api_response(success=True, message="Password reset successful")


# ----------------------
# Change Password
# ----------------------
class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not request.user.check_password(serializer.validated_data["old_password"]):
            return api_response(success=False, message="Old password incorrect", status_code=status.HTTP_400_BAD_REQUEST)

        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save(update_fields=["password"])
        return api_response(success=True, message="Password changed successfully")


# ----------------------
# Resend Email Verification
# ----------------------
class ResendEmailVerificationView(generics.GenericAPIView):
    serializer_class = ResendEmailVerificationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

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

        return api_response(success=True, message="Verification email resent successfully.", status_code=status.HTTP_200_OK)


# ----------------------
# Current User
# ----------------------
class CurrentUserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_object())
        return api_response(success=True, message="Current user retrieved successfully", data=serializer.data)


# ----------------------
# Update Avatar
# ----------------------
class UpdateAvatarView(generics.UpdateAPIView):
    serializer_class = UpdateAvatarSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(instance=request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_serializer = UserSerializer(request.user, context={"request": request})
        return api_response(success=True, message="Avatar updated successfully", data={"avatar": user_serializer.data["avatar_url"]})


# ----------------------
# Google OAuth Login
# ----------------------
class GoogleLoginView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        google_client_id = settings.GOOGLE_CLIENT_ID
        redirect_uri = urlencode({"redirect_uri": settings.GOOGLE_REDIRECT_URI})
        scope = urlencode({"scope": "openid email profile"})

        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"response_type=code&client_id={google_client_id}"
            f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
            f"&scope=openid%20email%20profile"
            f"&access_type=offline&prompt=consent"
        )

        return api_response(success=True, message="Google login URL generated successfully", data={"auth_url": auth_url})


# ----------------------
# Google OAuth Callback
# ----------------------
class GoogleLoginCallbackView(generics.GenericAPIView):
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }

        token_res = requests.post(token_url, data=data).json()
        google_access_token = token_res.get("access_token")

        if not google_access_token:
            return api_response(success=False, message="Failed to get access token from Google", status_code=status.HTTP_400_BAD_REQUEST)

        # Get user info
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        headers = {"Authorization": f"Bearer {google_access_token}"}
        user_info = requests.get(user_info_url, headers=headers).json()

        email = user_info.get("email")
        name = user_info.get("name")
        if not email:
            return api_response(success=False, message="Email not available from Google", status_code=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(email=email, defaults={"username": name, "is_verified": True, "login_type": LOGIN_GOOGLE})
        if not created:
            user.username = name
            user.is_verified = True
            user.save(update_fields=["username", "is_verified"])

        access = user.generate_access_token()
        refresh = user.generate_refresh_token()
        user.refresh_token = refresh
        user.save(update_fields=["refresh_token"])

        params = urlencode({"access": access, "refresh": refresh})
        frontend_url = f"{settings.FRONTEND_URL}/google/callback?{params}"
        print(frontend_url)
        return redirect(frontend_url)

# ----------------------
# GitHub OAuth Login
# ----------------------
class GitHubLoginView(APIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        client_id = settings.GITHUB_CLIENT_ID
        redirect_uri = settings.GITHUB_REDIRECT_URI
        auth_url = f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=user:email"
        return api_response(success=True, message="Github login URL generated successfully", data={"auth_url": auth_url})


# ----------------------
# GitHub OAuth Callback
# ----------------------
class GitHubLoginCallbackView(generics.GenericAPIView):
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        # Exchange code for token
        token_url = "https://github.com/login/oauth/access_token"
        data = {"client_id": settings.GITHUB_CLIENT_ID, "client_secret": settings.GITHUB_CLIENT_SECRET, "code": code}
        headers = {"Accept": "application/json"}
        token_res = requests.post(token_url, data=data, headers=headers).json()
        access_token = token_res.get("access_token")

        if not access_token:
            return api_response(success=False, message="Failed to get access token from GitHub", status_code=status.HTTP_400_BAD_REQUEST)

        # Get user info
        user_info_url = "https://api.github.com/user"
        headers = {"Authorization": f"token {access_token}"}
        user_info = requests.get(user_info_url, headers=headers).json()

        email = user_info.get("email") or f"{user_info.get('id')}@github.com"
        username = user_info.get("login")

        user, created = User.objects.get_or_create(email=email, defaults={"username": username, "is_verified": True, "login_type": LOGIN_GITHUB})
        if not created:
            user.username = username
            user.is_verified = True
            user.save(update_fields=["username", "is_verified"])

        # Generate tokens and redirect
        access = user.generate_access_token()
        refresh = user.generate_refresh_token()
        user.refresh_token = refresh
        user.save(update_fields=["refresh_token"])

        params = urlencode({"access": access, "refresh": refresh, "username": username})
        frontend_url = f"{settings.FRONTEND_URL}/github/callback?{params}"
        return redirect(frontend_url)


# ----------------------
# Role Management
# ----------------------
class ChangeRoleView(generics.GenericAPIView):
    serializer_class = ChangeRoleSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        new_role = serializer.validated_data["role"]
        
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

        user.role = new_role
        user.save(update_fields=["role"])

        return api_response(True, f"Role updated successfully to {new_role}", data={"user_id": user.id, "role": user.role})

# ----------------------
# List all active sessions
# ----------------------
class ListUserSessionsView(APIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        sessions = get_user_sessions(request.user)
        return api_response(
            True,
            "Active sessions retrieved successfully",
            data={"sessions": sessions, "current_session": request.session.session_key},
        )

# ----------------------
# Revoke a single session
# ----------------------
class RevokeSessionView(APIView):
    serializer_class = SessionKeySerializer
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, session_key):
        if session_key == request.session.session_key:
            return api_response(False, "Cannot revoke current session", status_code=status.HTTP_400_BAD_REQUEST)

        revoke_session(session_key)
        return api_response(True, "Session revoked successfully")

# ----------------------
# Revoke all sessions
# ----------------------
class RevokeAllSessionsView(APIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        revoke_all_sessions(request.user)
        return api_response(True, "All sessions revoked successfully")


# ----------------------
# Account Management
# ----------------------
class DeactivateAccountView(APIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        user = request.user
        if not user.is_active:
            return api_response(False, "Account already deactivated", status_code=status.HTTP_400_BAD_REQUEST)
        user.soft_delete()
        return api_response(True, "Account deactivated successfully")

class RestoreAccountView(APIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        user = request.user
        if user.is_active:
            return api_response(False, "Account is already active", status_code=400)
        user.restore()
        return api_response(True, "Account restored successfully")
    
class DeleteAccountView(APIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]

    def delete(self, request, *args, **kwargs):
        user_id = request.data.get("user_id")
        if not user_id:
            return api_response(False, "user_id is required", status_code=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id, is_active=True)
        except User.DoesNotExist:
            return api_response(False, "User not found", status_code=status.HTTP_404_NOT_FOUND)

        if user.is_superuser:
            superuser_count = User.objects.filter(is_superuser=True, is_active=True).count()
            if superuser_count <= 1:
                return api_response(False, "Cannot delete the last superuser.", status_code=status.HTTP_400_BAD_REQUEST)

        user.delete(hard=True)
        return api_response(True, f"User {user.username} permanently deleted")

# ----------------------------
# Generate TOTP secret & QR code
# ----------------------------
class Setup2FAView(APIView):
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


# ----------------------------
# Enable 2FA by verifying TOTP token
# ----------------------------
class Enable2FAView(generics.GenericAPIView):
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

# ----------------------------
# Disable 2FA
# ----------------------------
class Disable2FAView(generics.GenericAPIView):
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

class UserListView(generics.ListAPIView):
    queryset = User.objects.filter(is_active=True)
    serializer_class = UserSerializer
    permission_classes = [IsOwnerOrAdmin]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return api_response(
            success=True,
            message="Users retrieved successfully",
            data={"users": serializer.data}
        )
        
class UserDetailView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]

    def get_object(self):
        user_id = self.kwargs.get("pk")
        return get_object_or_404(User, id=user_id, is_active=True)

    def retrieve(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        return api_response(
            success=True,
            message="User retrieved successfully",
            data={"user": serializer.data}
        )
        