# -*- coding: utf-8 -*-

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.common.dhparam import WellKnownDHParams

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.dhparams import AnalyzerDHParams

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsDHParams(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2), timeout=None, ip=None):
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

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

    def test_weel_known_prime(self):
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

    def test_json(self):
        result = self.get_result('dh480.badssl.com', 443)
        self.assertTrue(result)
        result = self.get_result('www.owasp.org', 443)
        self.assertTrue(result)
