from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from . import otp_auth
from .models import AuditLog, OfficeSettings, Role, User

API = "/api/v1/"


class OtpToggleTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.lawyer = User.objects.create_user(mobile="09120000001", role=Role.LAWYER, full_name="l")
        cls.secretary = User.objects.create_user(mobile="09120000002", role=Role.SECRETARY, full_name="s")

    def login(self, mobile):
        return APIClient().post(API + "auth/otp/verify", {"mobile": mobile}, format="json")

    def api(self, user):
        c = APIClient()
        c.force_authenticate(user)
        return c

    # --- production behaviour: the switch can never weaken login -------------------------------
    def test_server_without_bypass_always_requires_code(self):
        OfficeSettings.objects.update_or_create(pk=1, defaults={"otp_required": False})
        self.assertTrue(otp_auth.otp_enforced())
        r = self.login(self.secretary.mobile)
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("access", r.data)

    def test_settings_endpoint_reports_that_the_switch_has_no_effect(self):
        r = self.api(self.lawyer).patch(API + "settings", {"otp_required": False}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.data["bypass_allowed_on_server"])
        self.assertTrue(r.data["otp_effective"])

    # --- test-server behaviour ------------------------------------------------------------------
    @override_settings(OTP_BYPASS_ALLOWED=True)
    def test_bypass_logs_in_with_mobile_only_and_is_audited(self):
        OfficeSettings.objects.update_or_create(pk=1, defaults={"otp_required": False})
        r = self.login(self.secretary.mobile)
        self.assertEqual(r.status_code, 200)
        self.assertIn("access", r.data)
        self.assertTrue(r.data["otp_bypass"])
        self.assertTrue(AuditLog.objects.filter(action="LOGIN_NO_OTP", user=self.secretary).exists())

    @override_settings(OTP_BYPASS_ALLOWED=True)
    def test_bypass_skips_staff_second_factor_but_unknown_mobile_still_fails(self):
        OfficeSettings.objects.update_or_create(pk=1, defaults={"otp_required": False})
        self.assertEqual(self.login(self.lawyer.mobile).status_code, 200)
        self.assertEqual(self.login("09129999999").status_code, 400)

    @override_settings(OTP_BYPASS_ALLOWED=True, SMS_SENDER="tests.send_sms")
    def test_request_sends_no_sms_in_test_mode(self):
        OfficeSettings.objects.update_or_create(pk=1, defaults={"otp_required": False})
        with mock.patch.object(otp_auth, "import_string") as imp:
            r = APIClient().post(API + "auth/otp/request", {"mobile": self.secretary.mobile}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.data["otp_required"])
        imp.return_value.assert_not_called()

    @override_settings(OTP_BYPASS_ALLOWED=True)
    def test_switching_back_on_requires_code_again(self):
        c = self.api(self.lawyer)
        self.assertEqual(c.patch(API + "settings", {"otp_required": False}, format="json").data["otp_effective"], False)
        self.assertEqual(self.login(self.secretary.mobile).status_code, 200)
        self.assertEqual(c.patch(API + "settings", {"otp_required": True}, format="json").data["otp_effective"], True)
        self.assertEqual(self.login(self.secretary.mobile).status_code, 400)

    # --- who may change it ----------------------------------------------------------------------
    @override_settings(OTP_BYPASS_ALLOWED=True)
    def test_only_lawyer_can_change_the_switch(self):
        self.assertEqual(self.api(self.secretary).patch(API + "settings", {"otp_required": False}, format="json").status_code, 403)
        self.assertEqual(self.api(self.secretary).get(API + "settings").status_code, 403)
        self.assertEqual(APIClient().patch(API + "settings", {"otp_required": False}, format="json").status_code, 401)

    def test_value_must_be_boolean_and_change_is_audited(self):
        c = self.api(self.lawyer)
        self.assertEqual(c.patch(API + "settings", {"otp_required": "no"}, format="json").status_code, 400)
        self.assertEqual(c.patch(API + "settings", {"otp_required": False}, format="json").status_code, 200)
        self.assertTrue(AuditLog.objects.filter(action="UPDATE", table_name=OfficeSettings._meta.db_table).exists())
