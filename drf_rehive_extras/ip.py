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

# The number of X-Forwarded-For entries appended by the trusted load balancer.
# The Google external load balancer appends two: the address that connected to
# it followed by its own forwarding rule IP. Can be overridden using the
# `LOAD_BALANCER_XFF_ENTRIES` Django setting.
DEFAULT_LOAD_BALANCER_XFF_ENTRIES = 2


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


def get_load_balancer_xff_entries():
    """
    The number of X-Forwarded-For entries appended by the load balancer.
    """

    return int(
        getattr(
            settings,
            'LOAD_BALANCER_XFF_ENTRIES',
            DEFAULT_LOAD_BALANCER_XFF_ENTRIES,
        )
    )


def is_cloudflare_ip(value):
    """
    Check whether an IP address belongs to a Cloudflare edge range.
    """

    ip = parse_ip(value)
    return ip is not None and any(ip in net for net in get_cloudflare_ip_ranges())


def parse_country(value):
    """
    Parse an ISO 3166-1 alpha-2 country code, else None.
    """

    country = (value or '').strip().upper()
    # Cloudflare's `XX` (unknown) and `T1` (Tor) are not countries.
    if (len(country) != 2
            or not (country.isascii() and country.isalpha())
            or country in ('XX', 'T1',)):
        return None

    return country


def is_cloudflare_request(request):
    """
    Check whether a request provably came through Cloudflare, i.e. the
    address that connected to the load balancer is a Cloudflare edge. Only
    then are the `CF-*` headers set by Cloudflare rather than the client.
    """

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if not x_forwarded_for:
        return False

    addrs = x_forwarded_for.split(',')
    entries = get_load_balancer_xff_entries()
    return len(addrs) >= entries and is_cloudflare_ip(addrs[-entries])


def get_origin(request):
    """
    Resolve the origin of a request as a dict of `ip_address` (the client IP)
    and `ip_country` (the country Cloudflare geolocated it to). Each value is
    None if it cannot be trusted, and the country is always None without a
    trusted IP. Never raises. Logging call sites can store the None; access
    control call sites must treat a None IP as deny (fail closed).

    In production every request arrives via Cloudflare and then the Google
    external load balancer, so REMOTE_ADDR is a Google front-end/node address,
    never the client. Cloudflare sets the single-valued CF-Connecting-IP and
    CF-IPCountry headers and overwrites any values the client sent. Those
    headers are only trusted when the request provably came through
    Cloudflare: the load balancer appends `<peer-ip>, <forwarding-rule-ip>` to
    X-Forwarded-For (`LOAD_BALANCER_XFF_ENTRIES` entries), so the first of
    those is the address that connected to the load balancer and must be a
    Cloudflare edge. Clients control everything left of that entry.

    Cloudflare only overwrites CF-IPCountry when IP Geolocation is enabled on
    the zone; otherwise a client-sent value passes through, so the country
    must only be relied on for zones with it enabled.

    Without X-Forwarded-For no proxy touched the request (local development,
    tests, in-cluster calls) and the TCP peer is the client. There is no
    Cloudflare country then, so callers that need one must geolocate the IP
    themselves.
    """

    origin = {'ip_address': None, 'ip_country': None}

    if not request.META.get('HTTP_X_FORWARDED_FOR'):
        ip = parse_ip(request.META.get('REMOTE_ADDR'))
        origin['ip_address'] = str(ip) if ip else None
        return origin

    if not is_cloudflare_request(request):
        return origin

    ip = parse_ip(request.META.get('HTTP_CF_CONNECTING_IP'))
    if ip:
        origin['ip_address'] = str(ip)
        origin['ip_country'] = parse_country(
            request.META.get('HTTP_CF_IPCOUNTRY')
        )

    return origin


def get_origin_ip(request):
    """
    Resolve the client IP of a request, or None if it cannot be trusted. See
    `get_origin`.
    """

    return get_origin(request)['ip_address']
