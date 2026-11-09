"""OTP login (mobile + one-time code) with a TOTP second step for lawyer and secretary.

Setup notes:
  * Add at the END of models.py:   from .otp_auth import OTPCode  # noqa
  * pip install djangorestframework djangorestframework-simplejwt pyotp
  * settings.py:
        SMS_SENDER = "yourproject.sms.send_sms"            # def send_sms(mobile, text) -> None
        FIELD_DECRYPT = "yourproject.crypto.decrypt_bytes"  # def decrypt_bytes(b: bytes) -> str
        REST_FRAMEWORK = {"DEFAULT_THROTTLE_RATES": {"otp": "10/hour"}}
  * Behind a reverse proxy, make sure REMOTE_ADDR is the real client IP.
  * Test stage only: settings.OTP_BYPASS_ALLOWED = True (from an environment variable on the TEST
    server; keep it False/absent in production). Then the lawyer can switch the SMS code off via
    PATCH /settings {"otp_required": false}. In production the code is always required.
"""
import re
import secrets
from datetime import timedelta

import pyotp
from django.conf import settings
from django.core import signing
from django.db import models, transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.module_loading import import_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import AuditLog, OfficeSettings, Role, User

OTP_TTL = timedelta(minutes=2)
MAX_ATTEMPTS = 5
MAX_CODES_PER_HOUR = 5
CHALLENGE_MAX_AGE = 300  # seconds
TWO_FACTOR_ROLES = (Role.LAWYER, Role.SECRETARY)

GENERIC_MSG = "اگر این شماره ثبت شده باشد، کد ورود پیامک می‌شود."
BAD_CODE_MSG = "کد واردشده نادرست یا منقضی است."

_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "0123456789" * 2)


class OTPCode(models.Model):
    mobile = models.CharField(max_length=15, db_index=True)
    code_hash = models.CharField(max_length=64)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


def normalize_mobile(raw):
    """Return 09xxxxxxxxx or None. Accepts Persian/Arabic digits and +98 / 0098 / 98 prefixes."""
    m = (raw or "").translate(_DIGITS).strip().replace(" ", "").replace("-", "")
    if m.startswith("+98"):
        m = "0" + m[3:]
    elif m.startswith("0098"):
        m = "0" + m[4:]
    elif m.startswith("98") and len(m) == 12:
        m = "0" + m[2:]
    elif len(m) == 10 and m.startswith("9"):
        m = "0" + m
    return m if re.fullmatch(r"09\d{9}", m) else None


def _hash(mobile, code):
    return salted_hmac("otp-code", f"{mobile}:{code}").hexdigest()


def issue_code(mobile):
    """Invalidate older codes, store a new hashed one, and return the plain code."""
    now = timezone.now()
    OTPCode.objects.filter(mobile=mobile, used_at__isnull=True).update(used_at=now)
    code = f"{secrets.randbelow(10**6):06d}"
    OTPCode.objects.create(mobile=mobile, code_hash=_hash(mobile, code), expires_at=now + OTP_TTL)
    return code


@transaction.atomic
def check_code(mobile, code):
    """One-time check. Returns True only for a correct, unexpired, unused code."""
    now = timezone.now()
    rec = (
        OTPCode.objects.select_for_update()
        .filter(mobile=mobile, used_at__isnull=True, expires_at__gt=now)
        .order_by("-created_at")
        .first()
    )
    if rec is None:
        return False
    rec.attempts += 1
    if rec.attempts > MAX_ATTEMPTS:
        rec.used_at = now
        rec.save(update_fields=["attempts", "used_at"])
        return False
    ok = constant_time_compare(rec.code_hash, _hash(mobile, (code or "").translate(_DIGITS).strip()))
    if ok:
        rec.used_at = now
    rec.save(update_fields=["attempts", "used_at"])
    return ok


def _tokens(user):
    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}


def _log_login(request, user, action="LOGIN"):
    AuditLog.objects.create(user=user, action=action, ip=request.META.get("REMOTE_ADDR"))


def otp_enforced():
    """The SMS code (and staff 2FA) is skipped only when BOTH hold:
      1. the server allows it: settings.OTP_BYPASS_ALLOWED = True (set by the developer on a test
         server only, never in production), and
      2. the lawyer switched `otp_required` off in the office settings.
    Otherwise login always needs the code."""
    if not getattr(settings, "OTP_BYPASS_ALLOWED", False):
        return True
    return OfficeSettings.load().otp_required


class OTPThrottle(AnonRateThrottle):
    scope = "otp"


class OTPRequestView(APIView):
    authentication_classes = []
    permission_classes = []
    throttle_classes = [OTPThrottle]

    def post(self, request):
        mobile = normalize_mobile(request.data.get("mobile"))
        if mobile is None:
            return Response({"detail": "شماره موبایل معتبر نیست."}, status=status.HTTP_400_BAD_REQUEST)
        if not otp_enforced():
            # Test mode: no SMS is sent and the app should skip the code screen.
            return Response({"detail": "ورود آزمایشی: نیازی به کد نیست.", "otp_required": False})
        user = User.objects.filter(mobile=mobile, is_active=True).first()
        recent = OTPCode.objects.filter(
            mobile=mobile, created_at__gt=timezone.now() - timedelta(hours=1)
        ).count()
        # The answer is identical whether or not the number exists, so numbers cannot be probed.
        if user is not None and recent < MAX_CODES_PER_HOUR:
            code = issue_code(mobile)
            import_string(settings.SMS_SENDER)(mobile, f"کد ورود شما: {code}")
        return Response({"detail": GENERIC_MSG, "otp_required": True})


class OTPVerifyView(APIView):
    authentication_classes = []
    permission_classes = []
    throttle_classes = [OTPThrottle]

    def post(self, request):
        mobile = normalize_mobile(request.data.get("mobile"))
        code = request.data.get("code")
        user = User.objects.filter(mobile=mobile, is_active=True).first() if mobile else None
        if user is None:
            return Response({"detail": BAD_CODE_MSG}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_enforced():
            # Test mode: mobile number alone logs in. Recorded in the audit log, flagged to the app.
            _log_login(request, user, action="LOGIN_NO_OTP")
            return Response({**_tokens(user), "otp_bypass": True})

        if not check_code(mobile, code):
            return Response({"detail": BAD_CODE_MSG}, status=status.HTTP_400_BAD_REQUEST)

        if user.role in TWO_FACTOR_ROLES:
            if not user.totp_secret:
                return Response(
                    {"detail": "ورود دومرحله‌ای برای این حساب فعال نشده است. با مدیر تماس بگیرید."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            challenge = signing.dumps({"u": str(user.id)}, salt="totp-challenge")
            return Response({"totp_required": True, "challenge": challenge})

        _log_login(request, user)
        return Response(_tokens(user))


class TOTPVerifyView(APIView):
    authentication_classes = []
    permission_classes = []
    throttle_classes = [OTPThrottle]

    def post(self, request):
        try:
            data = signing.loads(
                request.data.get("challenge", ""), salt="totp-challenge", max_age=CHALLENGE_MAX_AGE
            )
        except signing.BadSignature:
            return Response({"detail": BAD_CODE_MSG}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(id=data["u"], is_active=True).first()
        if user is None or not user.totp_secret:
            return Response({"detail": BAD_CODE_MSG}, status=status.HTTP_400_BAD_REQUEST)

        secret = import_string(settings.FIELD_DECRYPT)(bytes(user.totp_secret))
        code = str(request.data.get("code", "")).translate(_DIGITS).strip()
        if not pyotp.TOTP(secret).verify(code, valid_window=1):
            return Response({"detail": BAD_CODE_MSG}, status=status.HTTP_400_BAD_REQUEST)

        _log_login(request, user)
        return Response(_tokens(user))
