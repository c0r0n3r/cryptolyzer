# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from collections import OrderedDict

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.common.result import AnalyzerTargetTls

from cryptolyzer.tls.all import AnalyzerAll
from cryptolyzer.tls.ciphers import AnalyzerResultCipherSuites
from cryptolyzer.tls.client import L7ClientTlsBase

from .classes import TestTlsCases


class TestTlsAll(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0), timeout=None, ip=None):
        analyzer = AnalyzerAll()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    def test_is_ecdhe_supported(self):
        target = AnalyzerTargetTls('tls', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_ecdhe_supported(OrderedDict([
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), None)

        self.assertEqual(AnalyzerAll.is_ecdhe_supported(OrderedDict([
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
                ], False, False)
            ),
        ])), TlsProtocolVersionFinal(TlsVersion.TLS1_2))

    def test_is_dhe_supported(self):
        target = AnalyzerTargetTls('tls', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_dhe_supported(OrderedDict([
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), None)

        self.assertEqual(AnalyzerAll.is_dhe_supported(OrderedDict([
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), TlsProtocolVersionFinal(TlsVersion.TLS1_1))

    def test_is_public_key_supported(self):
        target = AnalyzerTargetTls('tls', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_public_key_supported(OrderedDict([
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), None)

        self.assertEqual(AnalyzerAll.is_public_key_supported(OrderedDict([
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
            (
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), TlsProtocolVersionFinal(TlsVersion.TLS1_1))

    def test_markdown(self):
        result = self.get_result('rc4-md5.badssl.com', 443)
        markdown_result = result.as_markdown()

        target_index = markdown_result.find('Target')
        self.assertNotEqual(target_index, -1)
        target_index = markdown_result.find('Target', target_index + 1)
        self.assertEqual(target_index, -1)

    def test_missing_parts(self):

        with mock.patch.object(AnalyzerAll, 'is_public_key_supported', return_value=None):
            result = self.get_result('static-rsa.badssl.com', 443)

        self.assertEqual(result.curves, None)
        self.assertEqual(result.dhparams, None)
        self.assertEqual(result.pubkeys, None)
        self.assertNotEqual(result.ciphers, None)
        self.assertNotEqual(result.pubkeyreq, None)
        self.assertNotEqual(result.versions, None)

        result = self.get_result('tls-v1-0.badssl.com', 1010)
        self.assertEqual(result.sigalgos, None)
        self.assertNotEqual(result.ciphers, None)
        self.assertNotEqual(result.dhparams, None)
        self.assertNotEqual(result.pubkeys, None)
        self.assertNotEqual(result.pubkeyreq, None)
        self.assertNotEqual(result.versions, None)
