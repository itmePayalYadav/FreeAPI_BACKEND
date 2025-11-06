from django.db.models.signals import post_save
from django.dispatch import receiver
from accounts.models import User
from social.models import Profile
from chat.models import Chat, Participant

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(owner=instance)
        