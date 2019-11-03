#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

import cryptography.x509 as cryptography_x509

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.common.exception import ResponseError, ResponseErrorType
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys

from .classes import TestTlsCases


class TestTlsPubKeys(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2), timeout=None):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        AnalyzerPublicKeys, '_get_tls_certificate_chain',
        side_effect=[
            ValueError,
            mock.DEFAULT,
        ]
    )
    def test_error_response_error_no_response(self, _):
        result = self.get_result('badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=[
            [],
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
        ]
    )
    def test_error_response_error_no_response_last_time(self, _):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 0)

    @mock.patch.object(
        cryptography_x509, 'load_der_x509_certificate',
        side_effect=ValueError
    )
    def test_error_load_certificate(self, _):
        result = self.get_result('badssl.com', 443)
        self.assertEqual(result.pubkeys, [])

    def test_eq(self):
        result_badssl_com = self.get_result('badssl.com', 443)
        result_wrong_host_badssl_com = self.get_result('wrong.host.badssl.com', 443)
        self.assertEqual(
            result_badssl_com.pubkeys[0].certificate_chain,
            result_wrong_host_badssl_com.pubkeys[0].certificate_chain
        )

        result_expired_badssl_com = self.get_result('expired.badssl.com', 443)
        result_self_signed_badssl_com = self.get_result('self-signed.badssl.com', 443)
        result_untrusted_root_badssl_com = self.get_result('untrusted-root.badssl.com', 443)
        result_revoked_badssl_com = self.get_result('revoked.badssl.com', 443)
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].certificate_chain,
            result_self_signed_badssl_com.pubkeys[0].certificate_chain
        )
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].certificate_chain,
            result_untrusted_root_badssl_com.pubkeys[0].certificate_chain
        )
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].certificate_chain,
            result_revoked_badssl_com.pubkeys[0].certificate_chain
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

        trusted_root_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(trusted_root_chain.items), 2)
        self.assertFalse(trusted_root_chain.contains_anchor)
        self.assertTrue(trusted_root_chain.ordered)
        self.assertTrue(trusted_root_chain.verified)

        result = self.get_result('self-signed.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

        self_signed_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(self_signed_chain.items), 1)
        self.assertTrue(self_signed_chain.contains_anchor)
        self.assertEqual(self_signed_chain.ordered, None)
        self.assertEqual(self_signed_chain.verified, None)

        result = self.get_result('untrusted-root.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

        untrusted_root_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(untrusted_root_chain.items), 2)
        self.assertTrue(untrusted_root_chain.contains_anchor)
        self.assertTrue(untrusted_root_chain.ordered)
        self.assertTrue(untrusted_root_chain.verified)

        self.assertNotEqual(self_signed_chain.items[0], untrusted_root_chain.items[1])

        result = self.get_result('incomplete-chain.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)

        incomplete_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(incomplete_chain.items), 1)
        self.assertFalse(incomplete_chain.contains_anchor)
        self.assertEqual(incomplete_chain.ordered, None)
        self.assertEqual(incomplete_chain.verified, None)

        self.assertEqual(trusted_root_chain.items[0], incomplete_chain.items[0])

    def test_certificate_chain_cross_signed_cas(self):
        result = self.get_result('www.gov.tw', 443)
        self.assertEqual(len(result.pubkeys), 1)

        cross_signed_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(cross_signed_chain.items), 4)
        self.assertFalse(cross_signed_chain.contains_anchor)
        self.assertTrue(cross_signed_chain.ordered)
        self.assertTrue(cross_signed_chain.verified)

        self.assertEqual(cross_signed_chain.items[-1].subject, cross_signed_chain.items[-2].issuer)
        self.assertEqual(cross_signed_chain.items[-2].subject, cross_signed_chain.items[-1].issuer)

    def test_plain_text_response(self):
        self.assertEqual(self.get_result('ptt.cc', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_0)).pubkeys, [])
        self.assertEqual(self.get_result('cplusplus.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_0)).pubkeys, [])

    def test_json(self):
        result = self.get_result('expired.badssl.com', 443)
        self.assertTrue(result.as_json())

        result = self.get_result('self-signed.badssl.com', 443)
        self.assertTrue(result.as_json())

        result = self.get_result('untrusted-root.badssl.com', 443)
        self.assertTrue(result.as_json())

        result = self.get_result('revoked.badssl.com', 443)
        self.assertTrue(result.as_json())
