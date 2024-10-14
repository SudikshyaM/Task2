from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken
import uuid
from django.contrib.auth.models import BaseUserManager

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set.')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  
        user.save(using=self._db) 
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')


class User(AbstractUser):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]
    phone_number = models.IntegerField(null=True)
    avatar=models.ImageField(upload_to='uploads/',null=True)
    email = models.EmailField(unique=True, blank=False, null=False)
    is_verified = models.BooleanField(default=False)
    referral_code = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)  
    referred_by = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='referrals')  
    no_of_referrals = models.IntegerField(default=0)  
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def __str__(self):
        return self.username
    
    def save(self, *args, **kwargs):
        if self._state.adding:
            self.referral_code = uuid.uuid4()
        super(User, self).save(*args, **kwargs)

    def generate_referral_link(self):
        base_url = "http://localhost:8000/api/register"  
        referral_link = f"{base_url}/?referral_code={self.referral_code}"
        return referral_link
    

