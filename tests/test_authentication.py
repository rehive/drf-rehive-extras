from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, override_settings
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView
from rehive import APIException

from drf_rehive_extras.authentication import (
    HeaderAuthentication, RehiveAuthentication,
)


PLATFORM_USER = {
    "id": "00000000-0000-0000-0000-000000000001",
    "company": "test_company",
    "groups": [{"name": "user", "section": "user"}],
}


class User:
    is_authenticated = True

    def __init__(self, identifier):
        self.identifier = identifier


class TestAuthentication(RehiveAuthentication):
    def get_user(self, request, platform_user):
        if platform_user["company"] == "inactive_company":
            raise exceptions.ValidationError(
                {"non_field_errors": ["Inactive company."]}
            )
        return User(platform_user["id"])


class TestAdminAuthentication(TestAuthentication):
    groups = ["admin", "service"]


class TestView(APIView):
    authentication_classes = (TestAuthentication,)

    def get(self, request):
        return Response({
            "user": request.user.identifier,
            "platform_user": request.user._platform_user["id"],
            "token": request.auth,
        })


class TestAdminView(TestView):
    authentication_classes = (TestAdminAuthentication,)


factory = APIRequestFactory()


def get(view=TestView, **headers):
    return view.as_view()(factory.get("/", **headers))


def mock_rehive(platform_user=None, exc=None):
    """
    Patch the SDK so that `Rehive(token).auth.get()` returns the platform
    user, or raises `exc`.
    """

    patcher = mock.patch("drf_rehive_extras.authentication.Rehive")
    rehive = patcher.start()
    auth_get = rehive.return_value.auth.get
    if exc:
        auth_get.side_effect = exc
    else:
        auth_get.return_value = platform_user or PLATFORM_USER
    return patcher, rehive


class GetAuthHeaderTests(SimpleTestCase):
    def header(self, value, **kwargs):
        request = factory.get("/", HTTP_AUTHORIZATION=value)
        return HeaderAuthentication.get_auth_header(request, **kwargs)

    def test_valid(self):
        self.assertEqual(self.header("Token abc"), "abc")

    def test_scheme_is_case_insensitive(self):
        self.assertEqual(self.header("token abc"), "abc")
        self.assertEqual(self.header("TOKEN abc"), "abc")

    def test_custom_name(self):
        self.assertEqual(self.header("Secret abc", name="secret"), "abc")
        self.assertIsNone(self.header("Token abc", name="secret"))

    def test_malformed(self):
        for value in (
            "", " ", "Token", "Token ", "abc", "Bearer abc",
            "Token abc def", "Tokenabc",
        ):
            with self.subTest(value=value):
                self.assertIsNone(self.header(value))

    def test_missing(self):
        request = factory.get("/")
        self.assertIsNone(HeaderAuthentication.get_auth_header(request))


class MalformedHeaderTests(SimpleTestCase):
    def setUp(self):
        patcher, self.rehive = mock_rehive()
        self.addCleanup(patcher.stop)

    def test_malformed_headers_return_401(self):
        for value in (
            None, "", "Token", "Token ", "abc", "Bearer abc",
            "Token abc def",
        ):
            with self.subTest(value=value):
                headers = {} if value is None else {"HTTP_AUTHORIZATION": value}
                response = get(**headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response["WWW-Authenticate"], "Token")

        # Rehive is never called without a well formed token.
        self.rehive.assert_not_called()


class RehiveAuthenticationTests(SimpleTestCase):
    def test_valid_token(self):
        patcher, rehive = mock_rehive()
        self.addCleanup(patcher.stop)

        response = get(HTTP_AUTHORIZATION="Token abc", REMOTE_ADDR="1.2.3.4")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {
            "user": PLATFORM_USER["id"],
            "platform_user": PLATFORM_USER["id"],
            "token": "abc",
        })
        rehive.assert_called_once_with("abc")
        rehive.return_value.auth.get.assert_called_once_with(
            headers={"X-Forwarded-For": "1.2.3.4"}
        )

    @override_settings(LOAD_BALANCER_XFF_ENTRIES=2)
    def test_untrusted_origin_sends_no_forwarded_for(self):
        patcher, rehive = mock_rehive()
        self.addCleanup(patcher.stop)

        # An X-Forwarded-For that did not come through Cloudflare cannot be
        # trusted, so no IP is forwarded to Rehive.
        response = get(
            HTTP_AUTHORIZATION="Token abc",
            HTTP_X_FORWARDED_FOR="5.6.7.8, 9.9.9.9",
        )

        self.assertEqual(response.status_code, 200)
        rehive.return_value.auth.get.assert_called_once_with(headers=None)

    def test_invalid_token(self):
        patcher, _ = mock_rehive(exc=APIException(
            "Invalid token.", status_code=401,
            data={"status": "error", "message": "Invalid token."},
        ))
        self.addCleanup(patcher.stop)

        response = get(HTTP_AUTHORIZATION="Token bad")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, {"detail": "Invalid token."})

    def test_forbidden_token_keeps_status_and_data(self):
        patcher, _ = mock_rehive(exc=APIException(
            "Forbidden.", status_code=403,
            data={"message": "Forbidden.", "data": {"token": ["Scoped."]}},
        ))
        self.addCleanup(patcher.stop)

        response = get(HTTP_AUTHORIZATION="Token abc")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data, {"token": ["Scoped."]})

    def test_throttled(self):
        patcher, _ = mock_rehive(exc=APIException(
            "Throttled.", status_code=429,
            result=SimpleNamespace(headers={"Retry-After": "30"}),
        ))
        self.addCleanup(patcher.stop)

        response = get(HTTP_AUTHORIZATION="Token abc")

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response["Retry-After"], "30")

    def test_unexpected_error_is_reraised(self):
        exc = APIException("Server error.", status_code=500)
        patcher, _ = mock_rehive(exc=exc)
        self.addCleanup(patcher.stop)

        request = factory.get("/", HTTP_AUTHORIZATION="Token abc")
        with self.assertRaises(APIException) as ctx:
            TestAuthentication().authenticate(request)
        self.assertIs(ctx.exception, exc)

    def test_get_user_can_reject(self):
        patcher, _ = mock_rehive(
            platform_user={**PLATFORM_USER, "company": "inactive_company"}
        )
        self.addCleanup(patcher.stop)

        response = get(HTTP_AUTHORIZATION="Token abc")

        self.assertEqual(response.status_code, 400)

    def test_get_user_is_required(self):
        patcher, _ = mock_rehive()
        self.addCleanup(patcher.stop)

        request = factory.get("/", HTTP_AUTHORIZATION="Token abc")
        with self.assertRaises(NotImplementedError):
            RehiveAuthentication().authenticate(request)

    def test_get_forwarded_for_override(self):
        patcher, rehive = mock_rehive()
        self.addCleanup(patcher.stop)

        class Authentication(TestAuthentication):
            def get_forwarded_for(self, request):
                return "10.0.0.1, 10.0.0.2"

        request = factory.get("/", HTTP_AUTHORIZATION="Token abc")
        Authentication().authenticate(request)

        rehive.return_value.auth.get.assert_called_once_with(
            headers={"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}
        )


class GroupTests(SimpleTestCase):
    def test_user_not_in_groups_is_denied(self):
        patcher, _ = mock_rehive()
        self.addCleanup(patcher.stop)

        with mock.patch.object(TestAdminAuthentication, "get_user") as get_user:
            response = get(TestAdminView, HTTP_AUTHORIZATION="Token abc")

        self.assertEqual(response.status_code, 403)
        # The local user is not looked up for a rejected caller.
        get_user.assert_not_called()

    def test_user_in_groups_is_allowed(self):
        patcher, _ = mock_rehive(platform_user={
            **PLATFORM_USER, "groups": [{"name": "admin", "section": "admin"}]
        })
        self.addCleanup(patcher.stop)

        response = get(TestAdminView, HTTP_AUTHORIZATION="Token abc")

        self.assertEqual(response.status_code, 200)

    def test_no_groups_allows_all(self):
        patcher, _ = mock_rehive(platform_user={**PLATFORM_USER, "groups": []})
        self.addCleanup(patcher.stop)

        response = get(HTTP_AUTHORIZATION="Token abc")

        self.assertEqual(response.status_code, 200)
