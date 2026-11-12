"""
Authentication shared by Rehive services (extensions).

Requires the Rehive Python SDK, which is installed with the `auth` extra:

    pip install drf-rehive-extras[auth]
"""

from django.utils.encoding import smart_str
from rest_framework import authentication, exceptions, status

from .ip import get_origin_ip

try:
    from rehive import Rehive, APIException
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "drf_rehive_extras.authentication requires the Rehive SDK. Install "
        "it with `pip install drf-rehive-extras[auth]`."
    ) from exc


class AuthenticationAPIException(exceptions.APIException):
    """
    Modify the API exception to support optionally setting the following values:

    - status_code
    - message

    This is required for ambiguous errors from the Rehive API.
    """

    def __init__(self, detail=None, code=None, status_code=None, message=None):
        if status_code:
            self.status_code = status_code

        if message:
            self.message = message

        super().__init__(detail, code)


class HeaderAuthentication(authentication.BaseAuthentication):
    """
    Base class for authentication via the `Authorization` header.
    """

    keyword = "Token"

    @staticmethod
    def get_auth_header(request, name="token"):
        """
        Return the credential from an `Authorization: <name> <credential>`
        header, or None.

        Anything other than exactly a matching scheme followed by a single
        credential (no header, a wrong scheme, a scheme with no credential, or
        extra parts) is treated as no credential, so that callers can respond
        with a 401 instead of failing on a malformed header.
        """

        auth = smart_str(request.META.get("HTTP_AUTHORIZATION", "")).split()

        if len(auth) != 2 or auth[0].lower() != name.lower():
            return None

        return auth[1]

    def authenticate_header(self, request):
        # Without a `WWW-Authenticate` value DRF turns `NotAuthenticated` and
        # `AuthenticationFailed` into 403s.
        return self.keyword


class RehiveAuthentication(HeaderAuthentication):
    """
    Authenticate a token in the authorization header against the Rehive API
    (`GET /3/auth/`).

    Services must implement `get_user()` to turn the platform user returned by
    Rehive into their own local user (usually by looking up the company and
    getting or creating the user). The platform user is then attached to the
    returned user as `user._platform_user`.

    Set `groups` to restrict access to users in at least one of the listed
    Rehive groups. An empty list allows all groups.
    """

    groups = []

    def get_user(self, request, platform_user):
        """
        Return the local user for a validated platform user. Raise a DRF
        exception to reject the request (for example, an inactive company).
        """

        raise NotImplementedError(
            "RehiveAuthentication subclasses must implement get_user()."
        )

    def get_forwarded_for(self, request):
        """
        The `X-Forwarded-For` value to send to Rehive, or None to send none.
        """

        return get_origin_ip(request)

    def get_platform_user(self, request, token):
        """
        Validate a token with the Rehive API and return the platform user.
        """

        forwarded_for = self.get_forwarded_for(request)
        rehive = Rehive(token)

        try:
            return rehive.auth.get(
                headers={"X-Forwarded-For": forwarded_for}
                if forwarded_for else None
            )
        except APIException as exc:
            self.raise_api_exception(exc)

    def raise_api_exception(self, exc):
        """
        Convert a Rehive API exception into a DRF exception. Throttling is
        passed through as a 429, and a 400, 401 or 403 from Rehive keeps its
        status code. Anything else is unexpected and re-raised as is.
        """

        status_code = getattr(exc, "status_code", None)

        # Handle 429 throttling errors.
        if status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            try:
                wait = int(exc.result.headers['Retry-After'])
            except (AttributeError, TypeError, KeyError, ValueError):
                wait = None
            raise exceptions.Throttled(wait=wait)

        # Handle other unexpected errors (raise a 500 error).
        elif status_code not in (
                    status.HTTP_400_BAD_REQUEST,
                    status.HTTP_403_FORBIDDEN,
                    status.HTTP_401_UNAUTHORIZED,
                ):
            raise exc

        # Otherwise try and get data from the exception (if it exists).
        try:
            data = exc.data['data']
        except (AttributeError, TypeError, KeyError):
            data = None

        # Otherwise try and get a message from the exception (if it exists).
        try:
            message = exc.data['message']
        except (AttributeError, TypeError, KeyError):
            message = None

        # Use either the data or the message exists.
        detail = data or message

        raise AuthenticationAPIException(
            detail=detail, status_code=status_code, message=message
        )

    def check_groups(self, platform_user):
        """
        Raise `PermissionDenied` unless the platform user is in one of
        `groups` (if any are set).
        """

        if not self.groups:
            return

        groups = [g['name'] for g in platform_user.get('groups') or []]
        if not set(self.groups).intersection(groups):
            raise exceptions.PermissionDenied()

    def authenticate(self, request):
        token = self.get_auth_header(request)

        if not token:
            raise exceptions.NotAuthenticated()

        platform_user = self.get_platform_user(request, token)
        self.check_groups(platform_user)

        user = self.get_user(request, platform_user)

        # Inject the platform user object into the auth user.
        user._platform_user = platform_user

        return user, token
