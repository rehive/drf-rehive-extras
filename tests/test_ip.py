from django.test import SimpleTestCase, override_settings
from rest_framework.test import APIRequestFactory

from drf_rehive_extras.ip import get_origin_ip, is_cloudflare_ip, parse_ip


CLOUDFLARE_IP = '104.16.1.1'
LOAD_BALANCER_IP = '34.120.0.1'
CLIENT_IP = '34.91.230.165'


class ParseIpTestCase(SimpleTestCase):
    def test_ipv4(self):
        self.assertEqual(str(parse_ip(' 1.2.3.4 ')), '1.2.3.4')

    def test_ipv6_is_canonicalised(self):
        self.assertEqual(
            str(parse_ip('2001:0DB8:0000:0000:0000:0000:0000:0001')),
            '2001:db8::1'
        )

    def test_invalid(self):
        for value in (None, '', 'nope', '1.2.3', '1.2.3.4, 5.6.7.8'):
            self.assertIsNone(parse_ip(value), value)

    def test_zone_id_rejected(self):
        self.assertIsNone(parse_ip('fe80::1%eth0'))


class IsCloudflareIpTestCase(SimpleTestCase):
    def test_cloudflare_ranges(self):
        self.assertTrue(is_cloudflare_ip(CLOUDFLARE_IP))
        self.assertTrue(is_cloudflare_ip('2606:4700::1'))

    def test_other_ranges(self):
        self.assertFalse(is_cloudflare_ip(LOAD_BALANCER_IP))
        self.assertFalse(is_cloudflare_ip('garbage'))

    @override_settings(CLOUDFLARE_IP_RANGES=('10.0.0.0/8',))
    def test_ranges_are_configurable(self):
        self.assertTrue(is_cloudflare_ip('10.1.2.3'))
        self.assertFalse(is_cloudflare_ip(CLOUDFLARE_IP))


class GetOriginIpTestCase(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def origin_ip(self, **extra):
        return get_origin_ip(self.factory.get('/', **extra))

    def test_no_proxy_uses_remote_addr(self):
        # Local development, tests and in-cluster calls.
        self.assertEqual(self.origin_ip(REMOTE_ADDR='127.0.0.1'), '127.0.0.1')

    def test_no_proxy_invalid_remote_addr(self):
        self.assertIsNone(self.origin_ip(REMOTE_ADDR='garbage'))

    def test_cloudflare_then_load_balancer(self):
        # The chain as seen behind Cloudflare and the Google load balancer.
        self.assertEqual(
            self.origin_ip(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=(
                    f'{CLIENT_IP}, {CLOUDFLARE_IP}, {LOAD_BALANCER_IP}'
                ),
                HTTP_CF_CONNECTING_IP=CLIENT_IP
            ),
            CLIENT_IP
        )

    def test_client_supplied_entries_are_ignored(self):
        # Entries to the left of the Cloudflare edge are client controlled.
        self.assertEqual(
            self.origin_ip(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=(
                    f'1.2.3.4, {CLIENT_IP}, {CLOUDFLARE_IP}, {LOAD_BALANCER_IP}'
                ),
                HTTP_CF_CONNECTING_IP=CLIENT_IP
            ),
            CLIENT_IP
        )

    def test_load_balancer_reached_directly(self):
        # Bypassing Cloudflare: the load balancer peer is the attacker, so
        # the forged CF-Connecting-IP header is not trusted.
        self.assertIsNone(
            self.origin_ip(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=f'1.2.3.4, {LOAD_BALANCER_IP}',
                HTTP_CF_CONNECTING_IP=CLIENT_IP
            )
        )

    def test_forged_cloudflare_entry(self):
        # A forged Cloudflare entry is pushed left by the load balancer.
        self.assertIsNone(
            self.origin_ip(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=(
                    f'{CLOUDFLARE_IP}, 1.2.3.4, {LOAD_BALANCER_IP}'
                ),
                HTTP_CF_CONNECTING_IP=CLIENT_IP
            )
        )

    def test_short_chain(self):
        self.assertIsNone(
            self.origin_ip(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=CLIENT_IP,
                HTTP_CF_CONNECTING_IP=CLIENT_IP
            )
        )

    def test_missing_cf_connecting_ip(self):
        self.assertIsNone(
            self.origin_ip(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=(
                    f'{CLIENT_IP}, {CLOUDFLARE_IP}, {LOAD_BALANCER_IP}'
                )
            )
        )

    def test_invalid_cf_connecting_ip(self):
        self.assertIsNone(
            self.origin_ip(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=(
                    f'{CLIENT_IP}, {CLOUDFLARE_IP}, {LOAD_BALANCER_IP}'
                ),
                HTTP_CF_CONNECTING_IP='garbage'
            )
        )
