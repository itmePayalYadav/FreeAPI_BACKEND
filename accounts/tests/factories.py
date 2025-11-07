# =============================================================
# USER FACTORY
# =============================================================

import factory
from accounts.models import User

class UserFactory(factory.django.DjangoModelFactory):
    """
    Factory for generating User instances for testing.
    """
    # ----------------------------
    # Meta Configuration
    # ----------------------------
    class Meta:
        model = User
        django_get_or_create = ("email",)
        skip_postgeneration_save = True
        
    # ----------------------------
    # Default Fields
    # ----------------------------
    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    password = factory.PostGenerationMethodCall("set_password", "testpass123")
    is_verified = False
    is_staff = False
    is_superuser = False
