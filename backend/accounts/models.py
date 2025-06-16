from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
import datetime
from pathlib import Path


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
   
    customer        = models.OneToOneField(
        Customer, on_delete=models.CASCADE, related_name="project"
    )

    length_ft       = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )
    width_ft        = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )
    depth_in        = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )

    material_name   = models.CharField(max_length=120, blank=True)
    body_color      = models.CharField(max_length=40,  blank=True)
    door_color      = models.CharField(max_length=40,  blank=True)
    body_material   = models.CharField(max_length=120, blank=True)
    door_material   = models.CharField(max_length=120, blank=True)

    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)

    # -------------- helpers ----------------
    @property
    def square_feet(self):
        if self.length_ft and self.width_ft:
            return float(self.length_ft) * float(self.width_ft)
        return None

    @property
    def drawings_count(self):
        return self.drawings.count()

    def __str__(self):
        return f"Project for {self.customer}"


def drawings_upload_path(instance: "Drawing", filename: str) -> str:
    # e.g. projects/42/drawing2.pdf
    return f"projects/{instance.project.customer_id}/drawing{instance.drawing_num}{Path(filename).suffix}"


class Drawing(models.Model):
    """
    One PDF (or PNG, etc.) per “drawing”.
    Limited to four per project ― enforced in clean().
    """
    project         = models.ForeignKey(
        ProjectDetail, on_delete=models.CASCADE, related_name="drawings"
    )
    drawing_num     = models.PositiveSmallIntegerField()
    file            = models.FileField(upload_to=drawings_upload_path)
    uploaded_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("project", "drawing_num")
        ordering        = ("drawing_num",)

    # enforce 1‑4 at model level too
    def clean(self):
        if not (1 <= self.drawing_num <= 4):
            raise ValidationError("drawing_num must be between 1 and 4 (inclusive).")

    def __str__(self):
        return f"Drawing {self.drawing_num} – {self.project.customer}"
    
    