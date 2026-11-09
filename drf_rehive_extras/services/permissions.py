"""
Permissions shared by Rehive services (extensions).
"""

from logging import getLogger

from django.conf import settings
from rest_framework import permissions

from ..ip import get_origin_ip, parse_ip


logger = getLogger('django')


# The IP addresses that Rehive platform webhooks originate from by default.
DEFAULT_PLATFORM_WEBHOOK_IPS = ('34.91.230.165',)


def get_platform_webhook_ips():
    """
    The IP addresses platform webhooks are allowed to originate from, in the
    canonical `ipaddress` string form. Configured using the
    `PLATFORM_WEBHOOK_IPS` Django setting.
    """

    configured = getattr(
        settings, 'PLATFORM_WEBHOOK_IPS', DEFAULT_PLATFORM_WEBHOOK_IPS
    )

    ips = set()
    for value in configured:
        ip = parse_ip(value)
        if ip:
            ips.add(str(ip))

    return ips


class PlatformWebhookPermission(permissions.BasePermission):
    """
    Only allow requests that originate from the Rehive platform.

    Platform webhooks are sent from a fixed set of IP addresses which are
    configured using the `PLATFORM_WEBHOOK_IPS` setting. The origin IP is
    resolved using `drf_rehive_extras.ip.get_origin_ip`, which fails closed
    when the request did not provably come through Cloudflare.
    """

    def has_permission(self, request, view):
        ip = get_origin_ip(request)

        if not ip or ip not in get_platform_webhook_ips():
            logger.info(f"Webhook rejected from untrusted IP: {ip}.")
            return False

        return True
