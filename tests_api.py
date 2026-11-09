"""API-level tests. Assumptions:
  * the app urls are mounted at /api/v1/ (change API below otherwise);
  * settings use the REST_FRAMEWORK block from urls.py (page-number pagination -> "results");
  * the default file storage is a local FileSystemStorage (MEDIA_ROOT is redirected to a temp dir here).
"""
import tempfile
from unittest import mock

from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from . import otp_auth
from .models import AccessLevel, AuditLog, Case, Client, Deadline, Document, DocType, Note, Role, User

API = "/api/v1/"
TMP_MEDIA = tempfile.mkdtemp()


def items(response):
    data = response.data
    return data["results"] if isinstance(data, dict) and "results" in data else data


@override_settings(MEDIA_ROOT=TMP_MEDIA)
class ApiAccessTest(TestCase):
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

        def doc(case, level):
            return Document.objects.create(
                case=case, doc_type=DocType.OTHER, title=f"{case.title}-{level}", level=level,
                file=ContentFile(b"%PDF-1.4 test", name="t.pdf"),
            )

        cls.doc_lawyer = doc(cls.case_a, AccessLevel.LAWYER_ONLY)
        cls.doc_staff = doc(cls.case_a, AccessLevel.STAFF)
        cls.doc_client = doc(cls.case_a, AccessLevel.CLIENT_VISIBLE)
        cls.doc_other_client = doc(cls.case_r, AccessLevel.CLIENT_VISIBLE)
        Deadline.objects.create(case=cls.case_a, kind="appeal", due_on="2030-01-01")
        cls.note_lawyer = Note.objects.create(case=cls.case_a, body="secret", level=AccessLevel.LAWYER_ONLY, created_by=cls.lawyer)

    def api(self, user=None):
        client = APIClient()
        if user is not None:
            client.force_authenticate(user)
        return client

    def upload(self, name="a.pdf", level="staff"):
        return {
            "doc_type": "other", "title": "new", "level": level,
            "file": SimpleUploadedFile(name, b"%PDF-1.4 x", content_type="application/pdf"),
        }

    # ---- authentication -------------------------------------------------
    def test_anonymous_gets_401(self):
        self.assertEqual(self.api().get(API + "cases/").status_code, 401)

    def test_finance_has_no_access_to_cases(self):
        self.assertEqual(self.api(self.finance).get(API + "cases/").status_code, 403)

    # ---- clients (موکل) --------------------------------------------------
    def test_client_lists_only_own_cases(self):
        r = self.api(self.ahmadi_user).get(API + "cases/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([c["title"] for c in items(r)], ["الف"])

    def test_client_gets_404_for_other_clients_case_and_children(self):
        c = self.api(self.ahmadi_user)
        self.assertEqual(c.get(f"{API}cases/{self.case_r.id}/").status_code, 404)
        self.assertEqual(c.get(f"{API}cases/{self.case_r.id}/documents/").status_code, 404)
        self.assertEqual(c.get(f"{API}cases/{self.case_r.id}/hearings/").status_code, 404)

    def test_client_sees_only_client_visible_documents(self):
        r = self.api(self.ahmadi_user).get(f"{API}cases/{self.case_a.id}/documents/")
        self.assertEqual([d["title"] for d in items(r)], ["الف-client_visible"])

    def test_client_cannot_see_notes_deadlines_or_activity(self):
        c = self.api(self.ahmadi_user)
        self.assertEqual(items(c.get(f"{API}cases/{self.case_a.id}/notes/")), [])
        self.assertEqual(items(c.get(f"{API}cases/{self.case_a.id}/deadlines/")), [])
        self.assertEqual(items(c.get(f"{API}cases/{self.case_a.id}/activity/")), [])

    def test_client_cannot_write(self):
        c = self.api(self.ahmadi_user)
        self.assertEqual(c.post(API + "cases/", {"client": str(self.ahmadi.id), "title": "x"}, format="json").status_code, 403)
        self.assertEqual(c.post(f"{API}cases/{self.case_a.id}/documents/", self.upload(), format="multipart").status_code, 403)

    def test_client_dashboard_has_no_office_wide_numbers(self):
        r = self.api(self.ahmadi_user).get(API + "dashboard")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("total_clients", r.data)

    # ---- secretary -------------------------------------------------------
    def test_secretary_does_not_see_lawyer_only_content(self):
        c = self.api(self.secretary)
        titles = [d["title"] for d in items(c.get(f"{API}cases/{self.case_a.id}/documents/"))]
        self.assertNotIn("الف-lawyer_only", titles)
        self.assertEqual(c.get(f"{API}cases/{self.case_a.id}/documents/{self.doc_lawyer.id}/").status_code, 404)
        self.assertEqual(items(c.get(f"{API}cases/{self.case_a.id}/notes/")), [])

    def test_secretary_cannot_create_lawyer_only_note(self):
        r = self.api(self.secretary).post(f"{API}cases/{self.case_a.id}/notes/", {"body": "x", "level": "lawyer_only"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_secretary_creates_staff_note_with_author(self):
        r = self.api(self.secretary).post(f"{API}cases/{self.case_a.id}/notes/", {"body": "x", "level": "staff"}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(Note.objects.get(pk=r.data["id"]).created_by, self.secretary)

    def test_secretary_cannot_delete(self):
        self.assertEqual(self.api(self.secretary).delete(f"{API}cases/{self.case_a.id}/").status_code, 403)

    def test_secretary_cannot_raise_document_to_lawyer_only(self):
        r = self.api(self.secretary).patch(
            f"{API}cases/{self.case_a.id}/documents/{self.doc_staff.id}/", {"level": "lawyer_only"}, format="json"
        )
        self.assertEqual(r.status_code, 400)

    # ---- lawyer ----------------------------------------------------------
    def test_lawyer_sees_all_documents(self):
        r = self.api(self.lawyer).get(f"{API}cases/{self.case_a.id}/documents/")
        self.assertEqual(len(items(r)), 3)

    def test_lawyer_can_delete_note(self):
        r = self.api(self.lawyer).delete(f"{API}cases/{self.case_a.id}/notes/{self.note_lawyer.id}/")
        self.assertEqual(r.status_code, 204)
        self.assertTrue(AuditLog.objects.filter(action="DELETE", table_name=Note._meta.db_table).exists())

    def test_creating_a_case_is_audited_and_numbered(self):
        r = self.api(self.lawyer).post(API + "cases/", {"client": str(self.ahmadi.id), "title": "جدید"}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.data["internal_no"])
        self.assertTrue(AuditLog.objects.filter(action="CREATE", row_id=str(r.data["id"])).exists())

    # ---- uploads and downloads -------------------------------------------
    def test_upload_pdf_sets_size_and_uploader(self):
        r = self.api(self.lawyer).post(f"{API}cases/{self.case_a.id}/documents/", self.upload(), format="multipart")
        self.assertEqual(r.status_code, 201)
        saved = Document.objects.get(pk=r.data["id"])
        self.assertEqual(saved.uploaded_by, self.lawyer)
        self.assertGreater(saved.size_bytes, 0)

    def test_upload_rejects_dangerous_extension(self):
        r = self.api(self.lawyer).post(f"{API}cases/{self.case_a.id}/documents/", self.upload("virus.exe"), format="multipart")
        self.assertEqual(r.status_code, 400)

    def test_upload_requires_a_file(self):
        r = self.api(self.lawyer).post(f"{API}cases/{self.case_a.id}/documents/", {"doc_type": "other", "title": "x"}, format="multipart")
        self.assertEqual(r.status_code, 400)

    def test_download_respects_access_and_is_audited(self):
        self.assertEqual(self.api(self.ahmadi_user).get(f"{API}documents/{self.doc_lawyer.id}/download").status_code, 404)
        self.assertEqual(self.api(self.ahmadi_user).get(f"{API}documents/{self.doc_other_client.id}/download").status_code, 404)
        r = self.api(self.ahmadi_user).get(f"{API}documents/{self.doc_client.id}/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "private, no-store")
        self.assertTrue(AuditLog.objects.filter(action="VIEW", row_id=str(self.doc_client.id), user=self.ahmadi_user).exists())

    # ---- registering a client --------------------------------------------
    def test_secretary_registers_client_and_account_is_created(self):
        r = self.api(self.secretary).post(API + "clients/", {"full_name": "کریمی", "mobile": "۰۹۱۲۱۲۳۴۵۶۷"}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.data["mobile"], "09121234567")
        self.assertTrue(r.data["client_code"].startswith("C"))
        self.assertEqual(User.objects.get(mobile="09121234567").role, Role.CLIENT)

    def test_client_registration_rejects_staff_mobile(self):
        r = self.api(self.secretary).post(API + "clients/", {"full_name": "x", "mobile": self.lawyer.mobile}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_client_registration_rejects_bad_mobile_and_national_id(self):
        c = self.api(self.secretary)
        self.assertEqual(c.post(API + "clients/", {"full_name": "x", "mobile": "123"}, format="json").status_code, 400)
        self.assertEqual(
            c.post(API + "clients/", {"full_name": "x", "mobile": "09125550000", "national_id": "123"}, format="json").status_code, 400
        )


@override_settings(SMS_SENDER="tests.send_sms")
class ApiOtpTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(mobile="09120000004", role=Role.CLIENT, full_name="c")

    def test_request_gives_same_answer_for_known_and_unknown_numbers(self):
        with mock.patch.object(otp_auth, "import_string") as imp:
            known = APIClient().post(API + "auth/otp/request", {"mobile": "09120000004"}, format="json")
            unknown = APIClient().post(API + "auth/otp/request", {"mobile": "09129999999"}, format="json")
        self.assertEqual(known.status_code, 200)
        self.assertEqual(known.data, unknown.data)
        self.assertEqual(imp.return_value.call_count, 1)  # SMS only for the real account

    def test_client_role_gets_tokens_after_correct_code(self):
        code = otp_auth.issue_code("09120000004")
        r = APIClient().post(API + "auth/otp/verify", {"mobile": "09120000004", "code": code}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("access", r.data)
        self.assertTrue(AuditLog.objects.filter(action="LOGIN", user=self.user).exists())

    def test_wrong_code_is_rejected(self):
        otp_auth.issue_code("09120000004")
        r = APIClient().post(API + "auth/otp/verify", {"mobile": "09120000004", "code": "111111x"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_staff_without_second_factor_cannot_log_in(self):
        User.objects.create_user(mobile="09127777777", role=Role.LAWYER, full_name="l")
        code = otp_auth.issue_code("09127777777")
        r = APIClient().post(API + "auth/otp/verify", {"mobile": "09127777777", "code": code}, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("access", r.data)
