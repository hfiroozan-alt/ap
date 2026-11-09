import os
import re

from django.conf import settings
from django.urls import reverse
from django.utils.module_loading import import_string
from rest_framework import serializers

from .models import Case, CaseActivity, CaseParty, Client, Deadline, Document, Hearing, Note
from .otp_auth import normalize_mobile
from .permissions import can_set_level

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx"}


def _encrypt(text):
    return import_string(settings.FIELD_ENCRYPT)(text)  # str -> bytes


def _decrypt(data):
    return import_string(settings.FIELD_DECRYPT)(bytes(data))  # bytes -> str


class ClientSerializer(serializers.ModelSerializer):
    national_id = serializers.CharField(write_only=True, required=False, allow_blank=True)
    national_id_last4 = serializers.SerializerMethodField()

    class Meta:
        model = Client
        fields = [
            "id", "client_code", "full_name", "father_name", "national_id", "national_id_last4",
            "birth_date", "mobile", "landline", "address", "postal_code", "occupation",
            "email", "marital_status", "created_at",
        ]
        read_only_fields = ["id", "client_code", "created_at"]

    def get_national_id_last4(self, obj):
        return _decrypt(obj.national_id)[-4:] if obj.national_id else ""

    def validate_national_id(self, value):
        if not value:
            return value
        if not re.fullmatch(r"\d{10}", value):
            raise serializers.ValidationError("کد ملی باید ۱۰ رقم باشد.")
        return "".join(str(int(ch)) for ch in value)  # Persian digits -> ASCII

    def validate_mobile(self, value):
        mobile = normalize_mobile(value)
        if mobile is None:
            raise serializers.ValidationError("شماره موبایل معتبر نیست.")
        return mobile

    def _pack(self, validated):
        national_id = validated.pop("national_id", None)
        if national_id:
            validated["national_id"] = _encrypt(national_id)
        return validated

    def create(self, validated_data):
        return super().create(self._pack(validated_data))

    def update(self, instance, validated_data):
        return super().update(instance, self._pack(validated_data))


class CaseSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source="client.full_name", read_only=True)
    internal_no = serializers.CharField(required=False)

    class Meta:
        model = Case
        fields = [
            "id", "internal_no", "client", "client_name", "title", "subject", "judicial_no",
            "archive_no", "authority", "province", "city", "branch", "opened_on", "status", "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class PartySerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseParty
        fields = ["id", "side", "full_name", "details"]


class HearingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hearing
        fields = ["id", "starts_at", "authority", "branch", "topic", "outcome", "minutes"]


class DeadlineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Deadline
        fields = ["id", "kind", "notified_on", "due_on", "done_at"]


class ActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseActivity
        fields = ["id", "happened_on", "description", "created_by"]
        read_only_fields = ["created_by"]


class _LevelMixin:
    def validate_level(self, value):
        if not can_set_level(self.context["request"].user, value):
            raise serializers.ValidationError("شما اجازه تعیین این سطح دسترسی را ندارید.")
        return value


class NoteSerializer(_LevelMixin, serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ["id", "body", "level", "created_by", "created_at"]
        read_only_fields = ["created_by", "created_at"]


class DocumentSerializer(_LevelMixin, serializers.ModelSerializer):
    file = serializers.FileField(write_only=True, required=False)
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = Document
        fields = [
            "id", "doc_type", "title", "doc_date", "description", "file", "level",
            "mime_type", "size_bytes", "uploaded_at", "download_url",
        ]
        read_only_fields = ["id", "mime_type", "size_bytes", "uploaded_at"]

    def get_download_url(self, obj):
        return reverse("document-download", args=[obj.pk])

    def validate_file(self, value):
        if value.size > MAX_UPLOAD_BYTES:
            raise serializers.ValidationError("حجم فایل نباید بیشتر از ۲۵ مگابایت باشد.")
        if os.path.splitext(value.name)[1].lower() not in ALLOWED_EXTENSIONS:
            raise serializers.ValidationError("فقط فایل‌های PDF، تصویر و Word پذیرفته می‌شوند.")
        return value

    def validate(self, attrs):
        if self.instance is None and "file" not in attrs:
            raise serializers.ValidationError({"file": "فایل سند را بارگذاری کنید."})
        return attrs

    def update(self, instance, validated_data):
        validated_data.pop("file", None)  # replacing the file is not allowed; upload a new document
        return super().update(instance, validated_data)
