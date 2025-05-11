from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
import datetime

# Admin Manager remains the same as before
class AdminManager(BaseUserManager):
    def create_user(self, email, full_name, password=None, **extra_fields):
        if not email:
            raise ValueError("Email required")
        email = self.normalize_email(email)
        user = self.model(email=email, full_name=full_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, password=None, **extra_fields):
        return self.create_user(email, full_name, password, **extra_fields)

class Admin(AbstractBaseUser):
    AdminID      = models.AutoField(primary_key=True)
    full_name    = models.CharField(max_length=255, blank=True, default='')   # allow empty
    email        = models.EmailField(unique=True)
    # step2 fields (blank until filled)
    company_name = models.CharField(max_length=255, blank=True)
    address      = models.TextField(blank=True)
    gst_details  = models.CharField(max_length=100, blank=True)

    is_verified  = models.BooleanField(default=False)  # OTP flow if desired

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    objects = AdminManager()

    def __str__(self):
        return f"{self.full_name} <{self.email}>"

class Member(models.Model):
    DESIGNER = 'Designer'
    MANAGER = 'Manager'
    PRODUCTION = 'Production'
    ROLE_CHOICES = [
        (DESIGNER, 'Designer'),
        (MANAGER, 'Manager'),
        (PRODUCTION, 'Production'),
    ]
    
    member_id    = models.AutoField(primary_key=True)
    admin        = models.ForeignKey(Admin, on_delete=models.CASCADE, related_name='members')
    full_name    = models.CharField(max_length=255, blank=True, default='')
    email        = models.EmailField(unique=True)
    password     = models.CharField(max_length=128)
    role         = models.CharField(max_length=50, choices=ROLE_CHOICES, default=DESIGNER)
    created_at   = models.DateTimeField(auto_now_add=True)

    def set_password(self, raw):
        from django.contrib.auth.hashers import make_password
        self.password = make_password(raw)

    def check_password(self, raw):
        from django.contrib.auth.hashers import check_password
        return check_password(raw, self.password)

    def __str__(self):
        return f"{self.full_name} ({self.role})"


class EmailOTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + datetime.timedelta(minutes=5)

    def __str__(self):
        return f"{self.email} - {self.otp}"