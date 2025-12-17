# -*- coding: utf-8 -*-

from unittest import mock

from cryptoparser.tls.extension import TlsExtensionsBase, TlsNamedCurve
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.dhparam import (
    DHPublicKey,
    DHPublicNumbers,
    DHParamWellKnown,
)
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.dhparams import AnalyzerDHParams

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsDHParams(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(
            host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=L4TransferSocketParams(), ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(TlsExtensionsBase, 'get_item_by_type', side_effect=KeyError)
    def test_error_missing_key_share_extension(self, _):
        result = self.get_result('example.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    @mock.patch.object(AnalyzerDHParams, '_get_public_key', side_effect=StopIteration)
    def test_error_no_respoinse_during_key_reuse_check(self, _):
        result = self.get_result('example.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.key_reuse, None)

    @mock.patch.object(
        AnalyzerDHParams, '_get_public_key', side_effect=StopIteration
    )
    def test_error_key_reuse_undeterminable(self, _):
        result = self.get_result('lamar.edu', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [TlsNamedCurve.FFDHE2048, TlsNamedCurve.FFDHE3072, TlsNamedCurve.FFDHE4096])
        self.assertIsNone(result.dhparam)
        self.assertEqual(result.key_reuse, None)

        result = self.get_result('gimp.org', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ])
        self.assertEqual(result.dhparam, None)
        self.assertEqual(result.key_reuse, None)

    @mock.patch.object(
        TlsExtensionsBase, 'get_item_by_type', side_effect=KeyError
    )
    def test_last_key_share_extension(self, _):
        result = self.get_result('lamar.edu', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [])
        self.assertIsNotNone(result.dhparam, None)

        result = self.get_result('gimp.org', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    def test_size(self):
        result = self.get_result('dh480.badssl.com', 443)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 480)
        self.assertEqual(result.dhparam.prime, True)
        self.assertEqual(result.dhparam.safe_prime, True)
        self.assertEqual(result.dhparam.well_known, None)
        self.assertFalse(result.key_reuse)
        self.assertEqual(
            self.get_log_lines(), [
                'Server offers 480-bit custom DH public parameter (TLS 1.2)',
            ]
        )

    def test_prime(self):
        result = self.get_result('dh-composite.badssl.com', 443)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 2048)
        self.assertEqual(result.dhparam.prime, False)
        self.assertEqual(result.dhparam.safe_prime, False)
        self.assertEqual(result.dhparam.well_known, None)
        self.assertFalse(result.key_reuse)

    def test_safe_prime(self):
        result = self.get_result('dh-small-subgroup.badssl.com', 443)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 2048)
        self.assertEqual(result.dhparam.prime, True)
        self.assertEqual(result.dhparam.safe_prime, False)
        self.assertEqual(result.dhparam.well_known, None)
        self.assertFalse(result.key_reuse)

    def test_well_known_prime(self):
        result = self.get_result('launchpad.net', 443)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 2048)
        self.assertEqual(result.dhparam.prime, True)
        self.assertEqual(result.dhparam.safe_prime, True)
        self.assertEqual(result.dhparam.well_known, DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP)
        self.assertFalse(result.key_reuse)

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    def test_no_dhe_support(self):
        result = self.get_result('static-rsa.badssl.com', 443)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)
        self.assertEqual(result.key_reuse, None)
        self.assertFalse(self.log_stream.getvalue(), '')

    def test_tls_early_version(self):
        result = self.get_result('dh480.badssl.com', 443, TlsProtocolVersion(TlsVersion.TLS1))
        self.assertEqual(result.groups, [])
        self.assertNotEqual(result.dhparam, None)
        self.assertFalse(result.key_reuse)

    def test_tls_1_2_rfc_7919_support(self):
        result = self.get_result('lamar.edu', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [TlsNamedCurve.FFDHE2048, TlsNamedCurve.FFDHE3072, TlsNamedCurve.FFDHE4096])
        self.assertEqual(result.dhparam, None)
        self.assertEqual(
            self.get_log_lines(), [
                'Server offers 2048-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
                'Server offers 3072-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
                'Server offers 4096-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
            ]
        )

    @mock.patch.object(
        AnalyzerDHParams, '_get_public_key_tls_1_x',
        return_value=DHPublicKey(
            DHPublicNumbers(
                0, DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.parameter_numbers
            ),
            4096
        )
    )
    def test_tls_1_2_no_rfc_7919_support(self, _):
        result = self.get_result('office.com', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [])
        self.assertEqual(
            result.dhparam.parameter_numbers,
            DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.parameter_numbers,
        )
        self.assertTrue(result.key_reuse)
        log_lines = self.get_log_lines()
        self.assertEqual(
            log_lines, [
                'Server offers 4096-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
                'Server offers 4096-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
            ]
        )

    def test_tls_1_3(self):
        result = self.get_result('www.cloudflare.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)
        self.assertFalse(result.key_reuse)

        result = self.get_result('archive.org', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ])
        self.assertEqual(result.dhparam, None)
        self.assertFalse(result.key_reuse)
        self.assertEqual(
            self.log_stream.getvalue(),
            'Server offers FFDHE public parameter with size 2048-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 3072-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 4096-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 6144-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 8192-bit (TLS 1.3)\n'
        )

    def test_json(self):
        result = self.get_result('dh480.badssl.com', 443)
        self.assertTrue(result)
        result = self.get_result('www.owasp.org', 443)
        self.assertTrue(result)
