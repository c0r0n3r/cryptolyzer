#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

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

    def test_plain_text_response(self):
        self.assertEqual(self.get_result('ptt.cc', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_0)).pubkeys, [])
        self.assertEqual(self.get_result('cplusplus.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_0)).pubkeys, [])
