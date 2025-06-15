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
    

def drawing_upload_path(instance, filename):
    return f"drawings/customer_{instance.customer.id}/{filename}"


class ProjectDetail(models.Model):
    customer      = models.OneToOneField(Customer, on_delete=models.CASCADE, related_name="project_detail")
    designer      = models.ForeignKey(Member, on_delete=models.SET_NULL, null=True, blank=True,
                                      limit_choices_to={'role': 'Designer'})

    length_ft     = models.DecimalField(max_digits=7, decimal_places=2)
    width_ft      = models.DecimalField(max_digits=7, decimal_places=2)
    depth_in      = models.DecimalField(max_digits=7, decimal_places=2, default=0)

    drawing1      = models.ImageField(upload_to=drawing_upload_path, null=True, blank=True)
    drawing2      = models.ImageField(upload_to=drawing_upload_path, null=True, blank=True)
    drawing3      = models.ImageField(upload_to=drawing_upload_path, null=True, blank=True)
    drawing4      = models.ImageField(upload_to=drawing_upload_path, null=True, blank=True)

    created_at    = models.DateTimeField(default=timezone.now)
    updated_at    = models.DateTimeField(auto_now=True)

    @property
    def square_feet(self):
        return float(self.length_ft) * float(self.width_ft)

    def drawing_count(self):
        return len([img for img in [self.drawing1, self.drawing2, self.drawing3, self.drawing4] if img])

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.drawing_count() < 2:
            raise ValidationError("At least 2 drawings are required.")
        if self.drawing_count() > 4:
            raise ValidationError("No more than 4 drawings allowed.")

    def __str__(self):
        return f"{self.customer.name} — {self.square_feet} sq ft"
    


class ProjectDrawing(models.Model):
    project = models.ForeignKey(ProjectDetail, on_delete=models.CASCADE, related_name='drawings')
    drawing_file = models.FileField(upload_to='project_drawings/')
    uploaded_at = models.DateTimeField(auto_now_add=True)