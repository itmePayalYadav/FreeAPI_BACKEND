import time
import uuid
import pyotp  
import secrets
import hashlib
import jwt
from core.models import BaseModel
from django.db import models
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from .managers import UserManager, ActiveUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from core.constants import ROLE_CHOICES, LOGIN_TYPE_CHOICES, ROLE_USER, LOGIN_EMAIL_PASSWORD

# ----------------------
# Avatar Upload Path
# ----------------------
def avatar_upload_path(instance, filename):
    return f"avatars/user_{instance.id}/{filename}"

class User(BaseModel, AbstractBaseUser, PermissionsMixin):
    # ----------------------
    # Basic User Info
    # ----------------------
    email = models.EmailField(unique=True, db_index=True)
    username = models.CharField(max_length=150, unique=True, db_index=True)
    avatar = models.URLField(blank=True, null=True)

    # ----------------------
    # Role & Login Type
    # ----------------------
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default=ROLE_USER)
    login_type = models.CharField(max_length=50, choices=LOGIN_TYPE_CHOICES, default=LOGIN_EMAIL_PASSWORD)

    # ----------------------
    # Account Status Flags
    # ----------------------
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # ----------------------
    # Authentication Tokens
    # ----------------------
    refresh_token = models.TextField(blank=True, null=True)
    forgot_password_token = models.CharField(max_length=255, blank=True, null=True)
    forgot_password_expiry = models.DateTimeField(blank=True, null=True)
    email_verification_token = models.CharField(max_length=255, blank=True, null=True)
    email_verification_expiry = models.DateTimeField(blank=True, null=True)

    # ----------------------
    # Two-Factor Authentication (TOTP)
    # ----------------------
    is_2fa_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    
    # ----------------------
    # Realtime Presence 
    # ----------------------
    is_online = models.BooleanField(default=False)
    last_seen = models.DateTimeField(blank=True, null=True)
    status_message = models.CharField(max_length=255, blank=True, null=True, default="Hey there! I am using config Hub.")

    # ----------------------
    # User Model Config
    # ----------------------
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = UserManager()
    active_objects = ActiveUserManager()

    # ----------------------
    # Avatar URL
    # ----------------------
    @property
    def avatar_url(self):
        if self.avatar:
            if hasattr(self.avatar, "url"):
                return self.avatar.url
            elif isinstance(self.avatar, str) and self.avatar.startswith("http"):
                return self.avatar
        return f"https://ui-avatars.com/api/?name={self.username}&size=200"
    
    # ----------------------
    # Online Presence Helpers
    # ----------------------
    def mark_online(self):
        self.is_online = True
        self.last_seen = timezone.now()
        self.save(update_fields=["is_online", "last_seen"])

    def mark_offline(self):
        self.is_online = False
        self.last_seen = timezone.now()
        self.save(update_fields=["is_online", "last_seen"])

    def formatted_last_seen(self):
        """Return human-readable last seen (WhatsApp-style)."""
        if not self.last_seen:
            return "last seen recently"

        now = timezone.now()
        delta = now - self.last_seen

        if delta < timedelta(minutes=1):
            return "online just now"
        elif delta < timedelta(hours=1):
            return f"last seen {int(delta.seconds / 60)} minutes ago"
        elif delta < timedelta(hours=24):
            return f"last seen today at {self.last_seen.strftime('%I:%M %p')}"
        elif delta < timedelta(days=2):
            return f"last seen yesterday at {self.last_seen.strftime('%I:%M %p')}"
        else:
            return f"last seen on {self.last_seen.strftime('%b %d, %Y at %I:%M %p')}"

    # ----------------------
    # String Representation
    # ----------------------
    def __str__(self):
        return self.email

    # ----------------------
    # Soft Delete
    # ----------------------
    def delete(self, using=None, keep_parents=False, hard=False):
        if hard:
            super(User, self).delete(using=using, keep_parents=keep_parents)
        else:
            self.soft_delete()

    # ----------------------
    # TOTP (Two-Factor Authentication)
    # ----------------------
    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        self.save(update_fields=['totp_secret'])
        return self.totp_secret

    def get_totp_uri(self):
        return f"otpauth://totp/{self.email}?secret={self.totp_secret}&issuer=config"

    def verify_totp(self, token):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)
    