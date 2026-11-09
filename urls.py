"""Mount with:  path("api/v1/", include("yourapp.urls"))

settings.py essentials (not exhaustive):
    TIME_ZONE = "Asia/Tehran"
    FIELD_ENCRYPT = "yourproject.crypto.encrypt_text"   # str -> bytes (AES-GCM, key outside the database)
    FIELD_DECRYPT = "yourproject.crypto.decrypt_bytes"  # bytes -> str
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework_simplejwt.authentication.JWTAuthentication"],
        "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
        "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
        "PAGE_SIZE": 25,
        "DEFAULT_THROTTLE_RATES": {"otp": "10/hour"},
    }
    DEFAULT_FILE_STORAGE: a private, encrypted, S3-compatible storage (never a public media URL)
"""
from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from . import views
from .otp_auth import OTPRequestView, OTPVerifyView, TOTPVerifyView

router = DefaultRouter()
router.register("clients", views.ClientViewSet, basename="client")
router.register("cases", views.CaseViewSet, basename="case")

NESTED = {
    "parties": views.PartyViewSet,
    "hearings": views.HearingViewSet,
    "deadlines": views.DeadlineViewSet,
    "activity": views.ActivityViewSet,
    "notes": views.NoteViewSet,
    "documents": views.DocumentViewSet,
}

urlpatterns = [
    path("auth/otp/request", OTPRequestView.as_view()),
    path("auth/otp/verify", OTPVerifyView.as_view()),
    path("auth/totp/verify", TOTPVerifyView.as_view()),
    path("auth/token/refresh", TokenRefreshView.as_view()),
    path("me", views.MeView.as_view()),
    path("settings", views.OfficeSettingsView.as_view()),
    path("dashboard", views.DashboardView.as_view()),
    path("calendar", views.CalendarView.as_view()),
    path("documents/<uuid:pk>/download", views.DocumentDownloadView.as_view(), name="document-download"),
]

for prefix, viewset in NESTED.items():
    urlpatterns += [
        path(f"cases/<uuid:case_id>/{prefix}/", viewset.as_view({"get": "list", "post": "create"})),
        path(
            f"cases/<uuid:case_id>/{prefix}/<str:pk>/",
            viewset.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"}),
        ),
    ]

urlpatterns += router.urls
