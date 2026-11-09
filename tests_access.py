from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from .models import AccessLevel, Case, Client, Deadline, Document, DocType, Hearing, Note, Role, User
from .otp_auth import MAX_ATTEMPTS, OTPCode, check_code, issue_code, normalize_mobile
from .permissions import (
    can_set_level,
    visible_cases,
    visible_clients,
    visible_deadlines,
    visible_documents,
    visible_hearings,
    visible_notes,
)


class AccessRulesTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        def mk(mobile, role):
            return User.objects.create_user(mobile=mobile, role=role, full_name=mobile)

        cls.lawyer = mk("09120000001", Role.LAWYER)
        cls.secretary = mk("09120000002", Role.SECRETARY)
        cls.finance = mk("09120000003", Role.FINANCE)
        cls.ahmadi_user = mk("09120000004", Role.CLIENT)
        cls.rezaei_user = mk("09120000005", Role.CLIENT)

        cls.ahmadi = Client.objects.create(client_code="C1", user=cls.ahmadi_user, full_name="احمدی", mobile="09120000004")
        cls.rezaei = Client.objects.create(client_code="C2", user=cls.rezaei_user, full_name="رضایی", mobile="09120000005")

        cls.case_a = Case.objects.create(internal_no="1405-001", client=cls.ahmadi, title="الف")
        cls.case_r = Case.objects.create(internal_no="1405-002", client=cls.rezaei, title="ب")

        for level in AccessLevel.values:
            Document.objects.create(case=cls.case_a, doc_type=DocType.OTHER, title=f"a-{level}", file="x.pdf", level=level)
            Note.objects.create(case=cls.case_a, body=f"a-{level}", level=level, created_by=cls.lawyer)
        Document.objects.create(case=cls.case_r, doc_type=DocType.OTHER, title="r-visible", file="x.pdf", level=AccessLevel.CLIENT_VISIBLE)

        Hearing.objects.create(case=cls.case_a, starts_at=timezone.now() + timedelta(days=3))
        Hearing.objects.create(case=cls.case_r, starts_at=timezone.now() + timedelta(days=4))
        Deadline.objects.create(case=cls.case_a, kind="appeal", due_on=timezone.now().date() + timedelta(days=5))

    def titles(self, qs):
        return set(qs.values_list("title", flat=True))

    def test_lawyer_sees_everything(self):
        self.assertEqual(visible_clients(self.lawyer).count(), 2)
        self.assertEqual(visible_cases(self.lawyer).count(), 2)
        self.assertEqual(visible_documents(self.lawyer).count(), 4)
        self.assertEqual(visible_notes(self.lawyer).count(), 3)

    def test_secretary_cannot_see_lawyer_only(self):
        self.assertNotIn("a-lawyer_only", self.titles(visible_documents(self.secretary)))
        self.assertEqual(visible_documents(self.secretary).count(), 3)
        self.assertFalse(visible_notes(self.secretary).filter(level=AccessLevel.LAWYER_ONLY).exists())

    def test_client_sees_only_own_visible_content(self):
        self.assertEqual(list(visible_cases(self.ahmadi_user)), [self.case_a])
        self.assertEqual(visible_clients(self.ahmadi_user).count(), 1)
        self.assertEqual(self.titles(visible_documents(self.ahmadi_user)), {"a-client_visible"})
        self.assertFalse(visible_notes(self.ahmadi_user).exclude(level=AccessLevel.CLIENT_VISIBLE).exists())

    def test_client_cannot_see_other_clients_data(self):
        self.assertNotIn("r-visible", self.titles(visible_documents(self.ahmadi_user)))
        self.assertEqual(visible_hearings(self.ahmadi_user).count(), 1)
        self.assertEqual(visible_documents(self.rezaei_user).count(), 1)

    def test_client_does_not_see_deadlines(self):
        self.assertEqual(visible_deadlines(self.ahmadi_user).count(), 0)
        self.assertEqual(visible_deadlines(self.secretary).count(), 1)

    def test_finance_has_no_case_access_in_phase_one(self):
        self.assertEqual(visible_cases(self.finance).count(), 0)
        self.assertEqual(visible_clients(self.finance).count(), 0)
        self.assertEqual(visible_documents(self.finance).count(), 0)

    def test_secretary_cannot_set_lawyer_only(self):
        self.assertFalse(can_set_level(self.secretary, AccessLevel.LAWYER_ONLY))
        self.assertTrue(can_set_level(self.secretary, AccessLevel.STAFF))
        self.assertTrue(can_set_level(self.lawyer, AccessLevel.LAWYER_ONLY))
        self.assertFalse(can_set_level(self.ahmadi_user, AccessLevel.CLIENT_VISIBLE))


class OTPTest(TestCase):
    mobile = "09123456789"

    def test_normalize_mobile(self):
        self.assertEqual(normalize_mobile("۰۹۱۲۳۴۵۶۷۸۹"), self.mobile)
        self.assertEqual(normalize_mobile("+989123456789"), self.mobile)
        self.assertEqual(normalize_mobile("9123456789"), self.mobile)
        self.assertIsNone(normalize_mobile("12345"))
        self.assertIsNone(normalize_mobile(None))

    def test_correct_code_works_once(self):
        code = issue_code(self.mobile)
        self.assertTrue(check_code(self.mobile, code))
        self.assertFalse(check_code(self.mobile, code))

    def test_wrong_code_fails(self):
        issue_code(self.mobile)
        self.assertFalse(check_code(self.mobile, "000000x"))

    def test_expired_code_fails(self):
        code = issue_code(self.mobile)
        OTPCode.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertFalse(check_code(self.mobile, code))

    def test_new_code_invalidates_old_one(self):
        old = issue_code(self.mobile)
        new = issue_code(self.mobile)
        if old != new:
            self.assertFalse(check_code(self.mobile, old))
        self.assertTrue(check_code(self.mobile, new))

    def test_too_many_attempts_locks_the_code(self):
        code = issue_code(self.mobile)
        for _ in range(MAX_ATTEMPTS):
            self.assertFalse(check_code(self.mobile, "not-it"))
        self.assertFalse(check_code(self.mobile, code))
