from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import datetime


# Custom manager for Admin model
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

# Admin model
class Admin(AbstractBaseUser):
    AdminID      = models.AutoField(primary_key=True)
    full_name    = models.CharField(max_length=255, blank=True, default='')
    email        = models.EmailField(unique=True)

    # Optional business info
    company_name = models.CharField(max_length=255, blank=True)
    address      = models.TextField(blank=True)
    gst_details  = models.CharField(max_length=100, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    objects = AdminManager()

    def __str__(self):
        return f"{self.full_name} <{self.email}>"

# Member model
class Member(models.Model):
    DESIGNER = 'Designer'
    MANAGER = 'Manager'
    PRODUCTION = 'Production'

    ROLE_CHOICES = [
        (DESIGNER, 'Designer'),
        (MANAGER, 'Manager'),
        (PRODUCTION, 'Production'),
    ]

    member_id   = models.AutoField(primary_key=True)
    admin       = models.ForeignKey(Admin, on_delete=models.CASCADE, related_name='members')
    full_name   = models.CharField(max_length=255, blank=True, default='')
    email       = models.EmailField(unique=True)
    password    = models.CharField(max_length=128)
    role        = models.CharField(max_length=50, choices=ROLE_CHOICES, default=DESIGNER)
    created_at  = models.DateTimeField(auto_now_add=True)
    admin       = models.ForeignKey(Admin, on_delete=models.CASCADE, related_name='members', null=True, blank=True)

    def set_password(self, raw):
        from django.contrib.auth.hashers import make_password
        self.password = make_password(raw)

    def check_password(self, raw):
        from django.contrib.auth.hashers import check_password
        return check_password(raw, self.password)

    def __str__(self):
        return f"{self.full_name} ({self.role})"


class Customer(models.Model):
    admin = models.ForeignKey(Admin, on_delete=models.CASCADE, related_name='customers')
    manager = models.ForeignKey(Member, on_delete=models.SET_NULL, related_name='managed_customers', null=True, blank=True,
                                limit_choices_to={'role': 'Manager'})

    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    address = models.TextField(blank=True)
    contact_number = models.CharField(max_length=20, blank=True)

    # Progress percentage from 0 to 100
    progress_percentage = models.PositiveSmallIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def status(self):
        """Determine project status automatically based on progress percentage."""
        if self.progress_percentage == 0:
            return "Not Started"
        elif 1 <= self.progress_percentage < 50:
            return "Designing"
        elif 50 <= self.progress_percentage < 100:
            return "Production"
        elif self.progress_percentage >= 100:
            return "Completed"
        return "Unknown"

    def __str__(self):
        return f"{self.name} - {self.status} ({self.progress_percentage}%)"