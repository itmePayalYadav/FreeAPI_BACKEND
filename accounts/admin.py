from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User
from django.utils.translation import gettext_lazy as _

class UserAdmin(BaseUserAdmin):
    model = User

    # Fields to display in the list view
    list_display = ("email", "username", "role", "is_verified", "is_staff", "is_active")
    list_filter = ("role", "is_verified", "is_staff", "login_type", "is_active")
    search_fields = ("email", "username")
    ordering = ("email",)
    readonly_fields = ("refresh_token", "forgot_password_token", "email_verification_token")

    # Fields shown when editing a user
    fieldsets = (
        (None, {"fields": ("email", "username", "password", "avatar")}),
        (_("Permissions"), {"fields": ("role", "is_verified", "is_staff", "is_superuser", "is_active")}),
        (_("Important tokens"), {"fields": ("refresh_token", "forgot_password_token", "email_verification_token")}),
        (_("Login Type"), {"fields": ("login_type",)}),
        (_("Two-Factor Authentication"), {"fields": ("is_2fa_enabled", "totp_secret")}),
    )

    # Fields shown when creating a new user
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "username", "password1", "password2", "role", "is_staff", "is_verified"),
        }),
    )

admin.site.register(User, UserAdmin)
