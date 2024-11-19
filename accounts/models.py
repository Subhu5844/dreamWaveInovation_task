from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,PermissionsMixin
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    """Manager for custom user creation."""

    def create_user(self, email, mobile_number, password=None, **extra_fields):
        """Create and return a regular user with an email and password."""
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, mobile_number=mobile_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, mobile_number, password=None, **extra_fields):
        """Create and return a superuser with email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, mobile_number, password, **extra_fields)


class CustomUser(AbstractBaseUser,PermissionsMixin):
    """Custom User model with additional fields."""

    class Role(models.TextChoices):
        OWNER = 'Owner', _('Owner')
        DIRECTOR = 'Director', _('Director')
        FINANCE_MANAGER = 'Finance Manager', _('Finance Manager')
        GENERAL_MANAGER = 'General Manager', _('General Manager')
        NORMAL_USER = 'Normal User', _('Normal User')

    class Designation(models.TextChoices):
        MANAGER = 'Manager', _('Manager')
        SUPERVISOR = 'Supervisor', _('Supervisor')
        TEAM_LEAD = 'Team Lead', _('Team Lead')
        OTHER = 'Other', _('Other')

    # Personal Information
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)

    # Contact Information
    email = models.EmailField(unique=True)
    mobile_number = models.CharField(
        max_length=15,
        unique=True,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$')]
    )
    whatsapp_number = models.CharField(max_length=15, blank=True, null=True)

    # Company Information
    company_name = models.CharField(max_length=255)
    registration_no = models.CharField(max_length=100, unique=True)
    vat_no = models.CharField(max_length=100, unique=True)
    address = models.TextField()

    # Role and Designation
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.NORMAL_USER
    )
    designation = models.CharField(
        max_length=100,
        choices=Designation.choices,
        blank=True, null=True
    )

    # Admin and Authentication-related fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Required fields
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'mobile_number', 'company_name']

    # Relationships (if any)
    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        """Override save method to ensure password hashing."""
        super().save(*args, **kwargs)

    def has_perm(self, perm, obj=None):
        """Check if the user has permission for the given permission."""
        return self.is_superuser

    def has_module_perms(self, app_label):
        """Check if the user has permission to view the app."""
        return self.is_superuser


class PasswordResetToken(models.Model):
    """Model to store the reset token for forgotten passwords."""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset token for {self.user.email}"


class RolePermission(models.Model):
    """Model for managing role-based access control permissions."""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    role = models.CharField(
        max_length=20,
        choices=CustomUser.Role.choices
    )
    permissions = models.JSONField(default=dict)  # JSON to store the list of permissions

    def __str__(self):
        return f"Permissions for {self.user.email} with role {self.role}"
    