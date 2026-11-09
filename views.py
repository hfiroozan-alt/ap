import os
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_date
from rest_framework import viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    AuditLog,
    Case,
    CaseActivity,
    CaseParty,
    CaseStatus,
    Client,
    OfficeSettings,
    Role,
    User,
)
from .otp_auth import otp_enforced
from .permissions import (
    STAFF_ROLES,
    IsLawyer,
    StaffWriteClientReadOnly,
    visible_cases,
    visible_clients,
    visible_deadlines,
    visible_documents,
    visible_hearings,
    visible_notes,
)
from .serializers import (
    ActivitySerializer,
    CaseSerializer,
    ClientSerializer,
    DeadlineSerializer,
    DocumentSerializer,
    HearingSerializer,
    NoteSerializer,
    PartySerializer,
)


def _log(request, action, instance, data=None):
    AuditLog.objects.create(
        user=request.user,
        action=action,
        table_name=instance._meta.db_table,
        row_id=str(instance.pk),
        new_data=data,
        ip=request.META.get("REMOTE_ADDR"),
    )


class BaseViewSet(viewsets.ModelViewSet):
    """Staff read/write, clients read-only (and only what the queryset exposes). Delete: lawyer only.
    Every change is written to the audit log (field names only, never sensitive values)."""

    permission_classes = [StaffWriteClientReadOnly]

    def get_permissions(self):
        if self.action == "destroy":
            return [IsLawyer()]
        return super().get_permissions()

    def create_kwargs(self, serializer):
        return {}

    def perform_create(self, serializer):
        obj = serializer.save(**self.create_kwargs(serializer))
        _log(self.request, "CREATE", obj)

    def perform_update(self, serializer):
        obj = serializer.save()
        fields = [f for f in serializer.validated_data if f not in ("file", "national_id")]
        _log(self.request, "UPDATE", obj, {"fields": fields})

    def perform_destroy(self, instance):
        _log(self.request, "DELETE", instance)
        instance.delete()


class ClientViewSet(BaseViewSet):
    serializer_class = ClientSerializer
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["full_name", "mobile", "client_code"]

    def get_queryset(self):
        return visible_clients(self.request.user).order_by("-created_at")

    @transaction.atomic
    def perform_create(self, serializer):
        mobile = serializer.validated_data["mobile"]
        user = User.objects.filter(mobile=mobile).first()
        if user is None:
            user = User.objects.create_user(
                mobile=mobile, role=Role.CLIENT, full_name=serializer.validated_data["full_name"]
            )
        elif user.role != Role.CLIENT or Client.objects.filter(user=user).exists():
            raise ValidationError({"mobile": "این شماره قبلاً برای حساب دیگری ثبت شده است."})
        obj = serializer.save(
            user=user, client_code=self._new_code(), created_by=self.request.user
        )
        _log(self.request, "CREATE", obj)

    @staticmethod
    def _new_code():
        while True:
            code = "C" + secrets.token_hex(3).upper()
            if not Client.objects.filter(client_code=code).exists():
                return code


class CaseViewSet(BaseViewSet):
    serializer_class = CaseSerializer
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["title", "internal_no", "judicial_no", "client__full_name"]

    def get_queryset(self):
        qs = visible_cases(self.request.user).select_related("client").order_by("-created_at")
        status = self.request.query_params.get("status")
        client = self.request.query_params.get("client")
        if status:
            qs = qs.filter(status=status)
        if client:
            qs = qs.filter(client_id=client)
        return qs

    def perform_create(self, serializer):
        extra = {}
        if not serializer.validated_data.get("internal_no"):
            # Placeholder numbering; switch to Jalali-year sequential numbers (jdatetime) later.
            while True:
                number = f"{timezone.localdate().year}-{secrets.token_hex(2).upper()}"
                if not Case.objects.filter(internal_no=number).exists():
                    break
            extra["internal_no"] = number
        obj = serializer.save(**extra)
        _log(self.request, "CREATE", obj)


class CaseScopedViewSet(BaseViewSet):
    """Resources under /cases/<case_id>/... A hidden case returns 404 for every child route."""

    def get_case(self):
        if not hasattr(self, "_case"):
            self._case = get_object_or_404(visible_cases(self.request.user), pk=self.kwargs["case_id"])
        return self._case

    def scoped_queryset(self):
        raise NotImplementedError

    def get_queryset(self):
        return self.scoped_queryset().filter(case=self.get_case())

    def create_kwargs(self, serializer):
        return {"case": self.get_case()}


class PartyViewSet(CaseScopedViewSet):
    serializer_class = PartySerializer

    def scoped_queryset(self):
        return CaseParty.objects.all()


class HearingViewSet(CaseScopedViewSet):
    serializer_class = HearingSerializer

    def scoped_queryset(self):
        return visible_hearings(self.request.user).order_by("starts_at")


class DeadlineViewSet(CaseScopedViewSet):
    serializer_class = DeadlineSerializer

    def scoped_queryset(self):
        return visible_deadlines(self.request.user).order_by("due_on")


class ActivityViewSet(CaseScopedViewSet):
    serializer_class = ActivitySerializer

    def scoped_queryset(self):
        if self.request.user.role in STAFF_ROLES:
            return CaseActivity.objects.order_by("happened_on", "id")
        return CaseActivity.objects.none()

    def create_kwargs(self, serializer):
        return {"case": self.get_case(), "created_by": self.request.user}


class NoteViewSet(CaseScopedViewSet):
    serializer_class = NoteSerializer

    def scoped_queryset(self):
        return visible_notes(self.request.user).order_by("-created_at")

    def create_kwargs(self, serializer):
        return {"case": self.get_case(), "created_by": self.request.user}


class DocumentViewSet(CaseScopedViewSet):
    serializer_class = DocumentSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    def scoped_queryset(self):
        return visible_documents(self.request.user).order_by("-uploaded_at")

    def create_kwargs(self, serializer):
        upload = serializer.validated_data["file"]
        return {
            "case": self.get_case(),
            "uploaded_by": self.request.user,
            "size_bytes": upload.size,
            "mime_type": getattr(upload, "content_type", "") or "",
        }


class DocumentDownloadView(APIView):
    """Checks access, writes a VIEW audit entry, then streams the file (no public file URLs)."""

    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        doc = get_object_or_404(visible_documents(request.user), pk=pk)
        _log(request, "VIEW", doc)
        response = FileResponse(
            doc.file.open("rb"), as_attachment=True, filename=os.path.basename(doc.file.name)
        )
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, no-store"
        return response


class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        today = timezone.localdate()
        cases = visible_cases(user)
        data = {
            "active_cases": cases.filter(status=CaseStatus.ACTIVE).count(),
            "hearings_today": visible_hearings(user).filter(starts_at__date=today).count(),
            "hearings_next_30_days": visible_hearings(user)
            .filter(starts_at__date__gte=today, starts_at__date__lte=today + timedelta(days=30))
            .count(),
        }
        if user.role in STAFF_ROLES:
            data.update(
                total_clients=visible_clients(user).count(),
                closed_cases=cases.filter(status=CaseStatus.CLOSED).count(),
                deadlines_next_7_days=visible_deadlines(user)
                .filter(done_at__isnull=True, due_on__gte=today, due_on__lte=today + timedelta(days=7))
                .count(),
                new_documents_last_7_days=visible_documents(user)
                .filter(uploaded_at__gte=timezone.now() - timedelta(days=7))
                .count(),
            )
        return Response(data)


class CalendarView(APIView):
    """GET /calendar?from=YYYY-MM-DD&to=YYYY-MM-DD (Gregorian; the client converts to Jalali)."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        today = timezone.localdate()
        start = parse_date(request.query_params.get("from", "")) or today
        end = parse_date(request.query_params.get("to", "")) or start + timedelta(days=30)
        if end < start or (end - start).days > 366:
            raise ValidationError("بازه تاریخ معتبر نیست.")
        hearings = (
            visible_hearings(request.user)
            .filter(starts_at__date__gte=start, starts_at__date__lte=end)
            .select_related("case")
            .order_by("starts_at")
        )
        deadlines = (
            visible_deadlines(request.user)
            .filter(due_on__gte=start, due_on__lte=end)
            .select_related("case")
            .order_by("due_on")
        )
        return Response(
            {
                "hearings": [
                    {**HearingSerializer(h).data, "case_id": str(h.case_id), "case_title": h.case.title}
                    for h in hearings
                ],
                "deadlines": [
                    {**DeadlineSerializer(d).data, "case_id": str(d.case_id), "case_title": d.case.title}
                    for d in deadlines
                ],
            }
        )


class OfficeSettingsView(APIView):
    """Lawyer-only switch for the early test stage: turn the SMS login code on or off.
    The switch has an effect only if the server allows it (settings.OTP_BYPASS_ALLOWED)."""

    permission_classes = [IsLawyer]

    @staticmethod
    def _data(office):
        return {
            "otp_required": office.otp_required,
            "bypass_allowed_on_server": bool(getattr(settings, "OTP_BYPASS_ALLOWED", False)),
            "otp_effective": otp_enforced(),
        }

    def get(self, request):
        return Response(self._data(OfficeSettings.load()))

    def patch(self, request):
        value = request.data.get("otp_required")
        if not isinstance(value, bool):
            raise ValidationError({"otp_required": "مقدار باید true یا false باشد."})
        office = OfficeSettings.load()
        office.otp_required = value
        office.save(update_fields=["otp_required", "updated_at"])
        _log(request, "UPDATE", office, {"fields": ["otp_required"], "otp_required": value})
        return Response(self._data(office))


class MeView(APIView):
    """Who is logged in; the app uses `role` to decide which screens to show."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        u = request.user
        return Response({"id": str(u.id), "full_name": u.full_name, "role": u.role, "mobile": u.mobile})
