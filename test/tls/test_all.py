# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from collections import OrderedDict

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsNamedCurve
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.result import AnalyzerTargetTls
from cryptolyzer.common.dhparam import DHParamWellKnown

from cryptolyzer.tls.all import AnalyzerAll
from cryptolyzer.tls.ciphers import AnalyzerResultCipherSuites
from cryptolyzer.tls.client import L7ClientTlsBase

from .classes import TestTlsCases


class TestTlsAll(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1), timeout=None, ip=None):
        analyzer = AnalyzerAll()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    def test_is_ecdhe_supported(self):
        target = AnalyzerTargetTls('tls', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_ecdhe_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), None)

        self.assertEqual(AnalyzerAll.is_ecdhe_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
                ], False, False)
            ),
        ])), TlsProtocolVersion(TlsVersion.TLS1_2))

    def test_is_public_key_supported(self):
        target = AnalyzerTargetTls('tls', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_public_key_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), None)

        self.assertEqual(AnalyzerAll.is_public_key_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), TlsProtocolVersion(TlsVersion.TLS1_1))

    def test_real(self):
        result = self.get_result('dh1024.badssl.com', 443)
        self.assertEqual(result.dhparams.groups, [])
        self.assertNotEqual(result.dhparams.dhparam, None)
        self.assertFalse(result.vulns.ciphers.null_encryption)
        self.assertFalse(result.vulns.ciphers.sweet32)
        self.assertTrue(result.vulns.dhparams.logjam)
        self.assertTrue(result.vulns.versions.early_tls_version)

        result = self.get_result('rc4-md5.badssl.com', 443)
        self.assertTrue(result.vulns.ciphers.rc4)
        self.assertFalse(result.vulns.ciphers.null_encryption)
        self.assertFalse(result.vulns.ciphers.sweet32)
        self.assertFalse(result.vulns.dhparams.logjam)
        self.assertTrue(result.vulns.versions.early_tls_version)

        result = self.get_result('openssl.org', 443)
        self.assertEqual(result.dhparams.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ])
        self.assertEqual(
            result.dhparams.dhparam.parameter_numbers,
            DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP.value.parameter_numbers
        )

        result = self.get_result('imagemagick.org', 443)
        self.assertEqual(result.dhparams.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192
        ])
        self.assertNotEqual(result.dhparams.dhparam, None)

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
