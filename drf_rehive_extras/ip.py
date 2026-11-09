"""
Helpers for identifying the origin IP address of a request.
"""

import ipaddress

from django.conf import settings


# Cloudflare edge ranges, https://www.cloudflare.com/ips/ (as of 2026-09-03).
# A request whose load balancer peer is outside these ranges did not come
# through Cloudflare, so its client IP headers cannot be trusted. The list can
# be overridden using the `CLOUDFLARE_IP_RANGES` Django setting.
DEFAULT_CLOUDFLARE_IP_RANGES = (
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/32',
)


def parse_ip(value):
    """
    Parse a plain IPv4/IPv6 address string, else None.
    """

    try:
        ip = ipaddress.ip_address((value or '').strip())
    except ValueError:
        return None

    # Postgres `inet` rejects zone IDs such as fe80::1%eth0.
    if getattr(ip, 'scope_id', None):
        return None

    return ip


def get_cloudflare_ip_ranges():
    """
    The Cloudflare edge ranges as a tuple of `ipaddress` networks.
    """

    ranges = getattr(
        settings, 'CLOUDFLARE_IP_RANGES', DEFAULT_CLOUDFLARE_IP_RANGES
    )
    return tuple(ipaddress.ip_network(n) for n in ranges)


def is_cloudflare_ip(value):
    """
    Check whether an IP address belongs to a Cloudflare edge range.
    """

    ip = parse_ip(value)
    return ip is not None and any(ip in net for net in get_cloudflare_ip_ranges())


def get_origin_ip(request):
    """
    Resolve the client IP of a request, or None if it cannot be trusted.

    Never raises. Logging call sites can store the None; access control call
    sites must treat None as deny (fail closed).

    In production every request arrives via Cloudflare and then the Google
    external load balancer, so REMOTE_ADDR is a Google front-end/node address,
    never the client. Cloudflare sets the single-valued CF-Connecting-IP header
    to the true client IP and overwrites any value the client sent. That header
    is only trusted when the request provably came through Cloudflare: the
    load balancer appends `<peer-ip>, <forwarding-rule-ip>` to X-Forwarded-For,
    so the second-last entry is the address that connected to the load balancer
    and must be a Cloudflare edge. Clients control everything left of that
    entry.

    Without X-Forwarded-For no proxy touched the request (local development,
    tests, in-cluster calls) and the TCP peer is the client.
    """

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if not x_forwarded_for:
        ip = parse_ip(request.META.get('REMOTE_ADDR'))
        return str(ip) if ip else None

    addrs = x_forwarded_for.split(',')
    if len(addrs) < 2 or not is_cloudflare_ip(addrs[-2]):
        return None

    ip = parse_ip(request.META.get('HTTP_CF_CONNECTING_IP'))
    return str(ip) if ip else None
