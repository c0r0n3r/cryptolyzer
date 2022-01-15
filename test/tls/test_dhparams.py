# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.extension import TlsExtensionsBase, TlsNamedCurve
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.common.dhparam import WellKnownDHParams

from cryptolyzer.tls.client import L7ClientTlsBase, TlsHandshakeClientHelloKeyExchangeDHE
from cryptolyzer.tls.dhparams import AnalyzerDHParams

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsDHParams(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2), timeout=None, ip=None):
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(TlsExtensionsBase, 'get_item_by_type', side_effect=KeyError)
    def test_error_missing_key_share_extension(self, _):
        self.assertEqual(self.get_result('mega.nz', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_3)).dhparams, [])

    @mock.patch.object(
        TlsHandshakeClientHelloKeyExchangeDHE, '_NAMED_CURVES',
        mock.PropertyMock(return_value=[TlsNamedCurve.FFDHE2048, ])
    )
    def test_last_key_share_extension(self):
        dhparams = self.get_result(
            'mega.nz', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_3), ip='31.216.144.5'
        ).dhparams
        self.assertEqual(
            [dhparam.public_key.public_numbers.parameter_numbers for dhparam in dhparams],
            [WellKnownDHParams.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.dh_param_numbers]
        )

    def test_size(self):
        result = self.get_result('dh480.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 480)
        self.assertEqual(result.dhparams[0].prime, True)
        self.assertEqual(result.dhparams[0].safe_prime, True)
        self.assertEqual(result.dhparams[0].well_known, None)

    def test_prime(self):
        result = self.get_result('dh-composite.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 2048)
        self.assertEqual(result.dhparams[0].prime, False)
        self.assertEqual(result.dhparams[0].safe_prime, False)
        self.assertEqual(result.dhparams[0].well_known, None)

    def test_safe_prime(self):
        result = self.get_result('dh-small-subgroup.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 2048)
        self.assertEqual(result.dhparams[0].prime, True)
        self.assertEqual(result.dhparams[0].safe_prime, False)
        self.assertEqual(result.dhparams[0].well_known, None)

    def test_well_known_prime(self):
        result = self.get_result('ubuntuforums.org', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 2048)
        self.assertEqual(result.dhparams[0].prime, True)
        self.assertEqual(result.dhparams[0].safe_prime, True)
        self.assertEqual(result.dhparams[0].well_known, WellKnownDHParams.RFC3526_2048_BIT_MODP_GROUP)

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, timeout=0.2),
        )
        threaded_server.start()

        self.assertEqual(self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).dhparams, [])

    def test_no_dhe_support(self):
        result = self.get_result('static-rsa.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 0)

    def test_tls_1_3(self):
        self.assertEqual(
            self.get_result('www.cloudflare.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_3)).dhparams,
            []
        )

        result = self.get_result('mega.nz', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_3), ip='31.216.144.5')
        self.assertEqual(
            [dhparam.public_key.public_numbers.parameter_numbers for dhparam in result.dhparams],
            [
                WellKnownDHParams.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.dh_param_numbers,
            ]
        )

    def test_json(self):
        result = self.get_result('dh480.badssl.com', 443)
        self.assertTrue(result)
        result = self.get_result('www.owasp.org', 443)
        self.assertTrue(result)
