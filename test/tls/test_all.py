# -*- coding: utf-8 -*-

from unittest import mock

from collections import OrderedDict

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsNamedCurve
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.result import AnalyzerTargetTls
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.tls.all import AnalyzerAll
from cryptolyzer.tls.ciphers import AnalyzerResultCipherSuites
from cryptolyzer.tls.client import L7ClientTlsBase

from .classes import TestTlsCases


class TestTlsAll(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(
            host,
            port,
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            l4_socket_params=L4TransferSocketParams(),
            ip=None,
            scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerAll()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
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
        self.assertFalse(result.vulns.ciphers.null_encryption.value)
        self.assertFalse(result.vulns.ciphers.sweet32.value)
        self.assertTrue(result.vulns.dhparams.weak_dh.value)
        self.assertTrue(result.vulns.versions.early_tls_version.value)

        result = self.get_result('rc4-md5.badssl.com', 443)
        self.assertTrue(result.vulns.ciphers.rc4.value)
        self.assertFalse(result.vulns.ciphers.null_encryption.value)
        self.assertFalse(result.vulns.ciphers.sweet32.value)
        self.assertFalse(result.vulns.dhparams.weak_dh.value)
        self.assertTrue(result.vulns.versions.early_tls_version.value)

        result = self.get_result('archive.org', 443)
        self.assertEqual(result.dhparams.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ])
        self.assertEqual(result.dhparams.dhparam.key_size.value, 2048)

        result = self.get_result('xenproject.org', 443)
        self.assertTrue(all(map(
            lambda version: version > TlsProtocolVersion(TlsVersion.TLS1_2), result.versions.versions
        )))
        self.assertEqual(set(result.ciphers[-1].cipher_suites), set([
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ]))
        self.assertEqual(result.dhparams.dhparam, None)
        self.assertEqual(result.dhparams.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192
        ])
        self.assertEqual(set(result.curves.curves), set([
            TlsNamedCurve.X25519,
            TlsNamedCurve.SECP256R1,
            TlsNamedCurve.X448,
            TlsNamedCurve.SECP521R1,
            TlsNamedCurve.SECP384R1,
        ]))

        result = self.get_result('pq.cloudflareresearch.com', 443)
        self.assertTrue(all(map(
            lambda version: version >= TlsProtocolVersion(TlsVersion.TLS1), result.versions.versions
        )))
        self.assertEqual(set(result.ciphers[-1].cipher_suites), set([
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ]))
        self.assertEqual(result.dhparams, None)
        curves = result.curves.curves
        # different instances run with different configuration, the following is the common subset
        self.assertIn(TlsNamedCurve.X25519_KYBER_768_R3, curves)
        self.assertIn(TlsNamedCurve.X25519, curves)
        self.assertIn(TlsNamedCurve.SECP256R1, curves)

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
