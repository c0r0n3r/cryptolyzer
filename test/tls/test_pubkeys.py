# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsPubKeys(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2), timeout=None, ip=None):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        AnalyzerPublicKeys, '_get_tls_certificate_chain',
        side_effect=[ValueError, ValueError, ValueError]
    )
    def test_error_unparsable_pubkey(self, _):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 0)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=[
            [],
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
        ]
    )
    def test_error_response_error_no_response_last_time(self, _):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 0)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME)
    )
    def test_error_unrecognized_name(self, mocked_do_tls_handshake):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 0)
        self.assertEqual(mocked_do_tls_handshake.call_count, 2)

    def test_eq(self):
        result_badssl_com = self.get_result('badssl.com', 443)
        result_wrong_host_badssl_com = self.get_result('wrong.host.badssl.com', 443)
        self.assertEqual(
            result_badssl_com.pubkeys[0].tls_certificate_chain,
            result_wrong_host_badssl_com.pubkeys[0].tls_certificate_chain
        )

        result_expired_badssl_com = self.get_result('expired.badssl.com', 443)
        result_self_signed_badssl_com = self.get_result('self-signed.badssl.com', 443)
        result_untrusted_root_badssl_com = self.get_result('untrusted-root.badssl.com', 443)
        result_revoked_badssl_com = self.get_result('revoked.badssl.com', 443)
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].tls_certificate_chain,
            result_self_signed_badssl_com.pubkeys[0].tls_certificate_chain
        )
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].tls_certificate_chain,
            result_untrusted_root_badssl_com.pubkeys[0].tls_certificate_chain
        )
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].tls_certificate_chain,
            result_revoked_badssl_com.pubkeys[0].tls_certificate_chain
        )

    def test_subject_match(self):
        result = self.get_result('badssl.com', 443)
        self.assertTrue(result.pubkeys[0].subject_matches)

        result = self.get_result('wrong.host.badssl.com', 443)
        self.assertFalse(result.pubkeys[0].subject_matches)

    def test_fallback_certificate(self):
        result = self.get_result('unexisting-hostname-to-get-wildcard-certificate-without-sni.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

    def test_certificate_chain(self):
        result = self.get_result('badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

        trusted_root_chain = result.pubkeys[0].tls_certificate_chain
        self.assertEqual(len(trusted_root_chain.items), 2)
        self.assertFalse(trusted_root_chain.contains_anchor)
        self.assertTrue(trusted_root_chain.verified)
        self.assertTrue(trusted_root_chain.ordered)

        result = self.get_result('self-signed.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

        self_signed_chain = result.pubkeys[0].tls_certificate_chain
        self.assertEqual(len(self_signed_chain.items), 1)
        self.assertTrue(self_signed_chain.contains_anchor)
        self.assertEqual(self_signed_chain.ordered, None)
        self.assertEqual(self_signed_chain.verified, None)

        result = self.get_result('untrusted-root.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

        untrusted_root_chain = result.pubkeys[0].tls_certificate_chain
        self.assertEqual(len(untrusted_root_chain.items), 2)
        self.assertEqual(untrusted_root_chain.contains_anchor, None)
        self.assertEqual(untrusted_root_chain.ordered, None)
        self.assertEqual(untrusted_root_chain.verified, None)

        self.assertNotEqual(self_signed_chain.items[0], untrusted_root_chain.items[1])

        result = self.get_result('incomplete-chain.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

        incomplete_chain = result.pubkeys[0].tls_certificate_chain
        self.assertEqual(len(incomplete_chain.items), 1)
        self.assertFalse(incomplete_chain.contains_anchor)
        self.assertEqual(incomplete_chain.ordered, None)
        self.assertEqual(incomplete_chain.verified, None)

        self.assertEqual(trusted_root_chain.items[0], incomplete_chain.items[0])

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, timeout=0.2),
        )
        threaded_server.start()
        self.assertEqual(
            self.get_result(
                'localhost',
                threaded_server.l7_server.l4_transfer.bind_port,
                TlsProtocolVersionFinal(TlsVersion.TLS1_0)
            ).pubkeys,
            []
        )

    def test_json(self):
        result = self.get_result('expired.badssl.com', 443)
        self.assertTrue(result.as_json())

        result = self.get_result('self-signed.badssl.com', 443)
        self.assertTrue(result.as_json())

        result = self.get_result('untrusted-root.badssl.com', 443)
        self.assertTrue(result.as_json())

        result = self.get_result('revoked.badssl.com', 443)
        self.assertTrue(result.as_json())
