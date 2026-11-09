from django.test import SimpleTestCase, override_settings
from rest_framework.test import APIRequestFactory

from drf_rehive_extras.services.permissions import (
    PlatformWebhookPermission, get_platform_webhook_ips
)


CLOUDFLARE_IP = '104.16.1.1'
LOAD_BALANCER_IP = '34.120.0.1'
PLATFORM_IP = '34.91.230.165'


class GetPlatformWebhookIpsTestCase(SimpleTestCase):
    def test_default(self):
        self.assertEqual(get_platform_webhook_ips(), {PLATFORM_IP})

    @override_settings(PLATFORM_WEBHOOK_IPS=[' 1.2.3.4 ', '2001:DB8::1', 'x'])
    def test_configured_values_are_canonicalised(self):
        self.assertEqual(get_platform_webhook_ips(), {'1.2.3.4', '2001:db8::1'})


class PlatformWebhookPermissionTestCase(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.permission = PlatformWebhookPermission()

    def has_permission(self, **extra):
        request = self.factory.post('/webhook/', **extra)
        return self.permission.has_permission(request, None)

    def test_platform_via_cloudflare(self):
        self.assertTrue(
            self.has_permission(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=(
                    f'{PLATFORM_IP}, {CLOUDFLARE_IP}, {LOAD_BALANCER_IP}'
                ),
                HTTP_CF_CONNECTING_IP=PLATFORM_IP
            )
        )

    def test_other_client_via_cloudflare(self):
        self.assertFalse(
            self.has_permission(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=(
                    f'1.2.3.4, {CLOUDFLARE_IP}, {LOAD_BALANCER_IP}'
                ),
                HTTP_CF_CONNECTING_IP='1.2.3.4'
            )
        )

    def test_spoofed_headers_bypassing_cloudflare(self):
        self.assertFalse(
            self.has_permission(
                REMOTE_ADDR='10.0.0.1',
                HTTP_X_FORWARDED_FOR=f'{PLATFORM_IP}, 1.2.3.4, {LOAD_BALANCER_IP}',
                HTTP_CF_CONNECTING_IP=PLATFORM_IP
            )
        )

    def test_no_proxy_trusted_remote_addr(self):
        self.assertTrue(self.has_permission(REMOTE_ADDR=PLATFORM_IP))

    def test_no_proxy_untrusted_remote_addr(self):
        self.assertFalse(self.has_permission(REMOTE_ADDR='127.0.0.1'))

    @override_settings(PLATFORM_WEBHOOK_IPS=['127.0.0.1'])
    def test_local_development(self):
        self.assertTrue(self.has_permission(REMOTE_ADDR='127.0.0.1'))
        self.assertFalse(self.has_permission(REMOTE_ADDR=PLATFORM_IP))
