from django.db.models.signals import post_save,pre_save
from django.dispatch import receiver
from .models import User
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
import uuid
from rest_framework import serializers

@receiver(pre_save,sender=User)
def generate_referral_code(sender, instance, **kwargs):
    if not instance.referral_code:
        instance.referral_code=uuid.uuid4()
    
@receiver(post_save, sender=User)
def send_verification_email(sender, instance, created, **kwargs):
    if created:  
        token = instance.tokens()
        verification_url = reverse('verify-email', kwargs={'token': token['access']})
        full_verification_link = f'http://localhost:8000{verification_url}'

        try:
            send_mail(
                subject='Verify your email',
                message=f'Click the link to verify your account: {full_verification_link}',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[instance.email], 
                fail_silently=False,
            )
        except Exception as e:
            raise Exception(f"Error sending verification email: {str(e)}")
        