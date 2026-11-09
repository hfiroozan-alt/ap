import uuid

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models


class Role(models.TextChoices):
    LAWYER = "lawyer", "وکیل"
    SECRETARY = "secretary", "منشی"
    FINANCE = "finance", "کارمند مالی"
    CLIENT = "client", "موکل"


class AccessLevel(models.TextChoices):
    LAWYER_ONLY = "lawyer_only", "فقط وکیل"
    STAFF = "staff", "وکیل و کارکنان"
    CLIENT_VISIBLE = "client_visible", "قابل مشاهده برای موکل"


class CaseStatus(models.TextChoices):
    ACTIVE = "active", "فعال"
    CLOSED = "closed", "مختومه"
    SUSPENDED = "suspended", "متوقف"


class PartySide(models.TextChoices):
    PLAINTIFF = "plaintiff", "خواهان"
    DEFENDANT = "defendant", "خوانده"
    COMPLAINANT = "complainant", "شاکی"
    ACCUSED = "accused", "متشاکی‌عنه"
    OTHER = "other", "سایر"


class DocType(models.TextChoices):
    PETITION = "petition", "دادخواست"
    COMPLAINT = "complaint", "شکواییه"
    BRIEF = "brief", "لایحه"
    NOTICE = "notice", "ابلاغیه"
    VERDICT = "verdict", "دادنامه"
    CONTRACT = "contract", "قرارداد"
    POA = "power_of_attorney", "وکالت‌نامه"
    EXPERT = "expert_opinion", "نظریه کارشناسی"
    OTHER = "other", "سایر مدارک"


class UserManager(BaseUserManager):
    def create_user(self, mobile, **extra):
        user = self.model(mobile=mobile, **extra)
        user.set_unusable_password()  # login is by OTP, not password
        user.save(using=self._db)
        return user

    def create_superuser(self, mobile, **extra):
        extra.setdefault("role", Role.LAWYER)
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        return self.create_user(mobile, **extra)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(max_length=20, choices=Role.choices)
    mobile = models.CharField(max_length=15, unique=True)
    full_name = models.CharField(max_length=150)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # Django admin access only
    totp_secret = models.BinaryField(null=True, blank=True)  # encrypt before saving
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "mobile"
    REQUIRED_FIELDS = ["full_name"]
    objects = UserManager()


class Client(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client_code = models.CharField(max_length=20, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="client_profile",
    )
    full_name = models.CharField(max_length=150)
    father_name = models.CharField(max_length=100, blank=True)
    national_id = models.BinaryField(null=True, blank=True)  # field-level encryption
    birth_date = models.DateField(null=True, blank=True)
    mobile = models.CharField(max_length=15)
    landline = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    postal_code = models.CharField(max_length=10, blank=True)
    occupation = models.CharField(max_length=100, blank=True)
    email = models.EmailField(blank=True)
    marital_status = models.CharField(max_length=30, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)


class Case(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    internal_no = models.CharField(max_length=30, unique=True)
    client = models.ForeignKey(Client, on_delete=models.PROTECT, related_name="cases")
    title = models.CharField(max_length=200)
    subject = models.TextField(blank=True)
    judicial_no = models.CharField(max_length=40, blank=True)
    archive_no = models.CharField(max_length=40, blank=True)
    authority = models.CharField(max_length=150, blank=True)
    province = models.CharField(max_length=60, blank=True)
    city = models.CharField(max_length=60, blank=True)
    branch = models.CharField(max_length=120, blank=True)
    opened_on = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=CaseStatus.choices, default=CaseStatus.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)


class CaseParty(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="parties")
    side = models.CharField(max_length=20, choices=PartySide.choices)
    full_name = models.CharField(max_length=150)
    details = models.TextField(blank=True)


class Hearing(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="hearings")
    starts_at = models.DateTimeField(db_index=True)
    authority = models.CharField(max_length=150, blank=True)
    branch = models.CharField(max_length=120, blank=True)
    topic = models.CharField(max_length=200, blank=True)
    outcome = models.TextField(blank=True)
    minutes = models.TextField(blank=True)


class Deadline(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="deadlines")
    kind = models.CharField(max_length=100)
    notified_on = models.DateField(null=True, blank=True)
    due_on = models.DateField(db_index=True)
    done_at = models.DateTimeField(null=True, blank=True)


class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="documents")
    doc_type = models.CharField(max_length=30, choices=DocType.choices)
    title = models.CharField(max_length=200)
    doc_date = models.DateField(null=True, blank=True)
    description = models.TextField(blank=True)
    file = models.FileField(upload_to="documents/%Y/%m/")  # use private, encrypted storage
    mime_type = models.CharField(max_length=100, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    level = models.CharField(
        max_length=20, choices=AccessLevel.choices, default=AccessLevel.LAWYER_ONLY
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)


class Note(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="notes")
    body = models.TextField()
    level = models.CharField(
        max_length=20, choices=AccessLevel.choices, default=AccessLevel.LAWYER_ONLY
    )
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)


class CaseActivity(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="activities")
    happened_on = models.DateField()
    description = models.TextField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )


class AuditLog(models.Model):
    at = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    action = models.CharField(max_length=20)  # CREATE / UPDATE / DELETE / VIEW / LOGIN
    table_name = models.CharField(max_length=60, blank=True)
    row_id = models.CharField(max_length=60, blank=True)
    old_data = models.JSONField(null=True, blank=True)
    new_data = models.JSONField(null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)


class OfficeSettings(models.Model):
    """Single-row table (pk=1). Edited only by the lawyer through /settings."""

    # Early test stage: False = login without an SMS code. This only takes effect when the server
    # itself allows it (settings.OTP_BYPASS_ALLOWED = True); see otp_auth.otp_enforced().
    otp_required = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
