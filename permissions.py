"""Server-side access rules. Every viewset must build its queryset from these helpers,
so hidden objects return 404 instead of leaking their existence."""
from rest_framework.permissions import SAFE_METHODS, BasePermission

from .models import AccessLevel, Case, Client, Deadline, Document, Hearing, Note, Role

STAFF_ROLES = (Role.LAWYER, Role.SECRETARY)


def visible_clients(user):
    if user.role in STAFF_ROLES:
        return Client.objects.all()
    if user.role == Role.CLIENT:
        return Client.objects.filter(user=user)
    return Client.objects.none()


def visible_cases(user):
    if user.role in STAFF_ROLES:
        return Case.objects.all()
    if user.role == Role.CLIENT:
        return Case.objects.filter(client__user=user)
    return Case.objects.none()  # finance has no case access in phase 1


def visible_hearings(user):
    return Hearing.objects.filter(case__in=visible_cases(user))


def visible_deadlines(user):
    if user.role in STAFF_ROLES:
        return Deadline.objects.all()
    return Deadline.objects.none()  # clients do not see legal deadlines


def _by_level(model, user):
    qs = model.objects.select_related("case")
    if user.role == Role.LAWYER:
        return qs
    if user.role == Role.SECRETARY:
        return qs.filter(level__in=[AccessLevel.STAFF, AccessLevel.CLIENT_VISIBLE])
    if user.role == Role.CLIENT:
        return qs.filter(case__client__user=user, level=AccessLevel.CLIENT_VISIBLE)
    return qs.none()


def visible_documents(user):
    return _by_level(Document, user)


def visible_notes(user):
    return _by_level(Note, user)


class IsLawyer(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user.is_authenticated and request.user.role == Role.LAWYER)


class IsStaff(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user.is_authenticated and request.user.role in STAFF_ROLES)


class StaffWriteClientReadOnly(BasePermission):
    """Staff can read and write; clients can only read (what the queryset already allows)."""

    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False
        if user.role in STAFF_ROLES:
            return True
        return user.role == Role.CLIENT and request.method in SAFE_METHODS


def can_set_level(user, level):
    """Secretaries cannot create or elevate lawyer-only content."""
    if user.role == Role.LAWYER:
        return True
    return user.role == Role.SECRETARY and level != AccessLevel.LAWYER_ONLY
