# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.tls.algorithm import TlsECPointFormat

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionType, TlsNamedCurve

from cryptolyzer.ja3.decode import AnalyzerDecode, JA3ClientTag


class TestJA3Decode(unittest.TestCase):
    @staticmethod
    def get_result(tag_str):
        analyzer = AnalyzerDecode()
        result = analyzer.analyze(JA3ClientTag(tag_str))
        return result

    def test_tag_empty_lists(self):
        result = self.get_result('771,,,,')
        self.assertEqual(result.tls_protocol_version, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.cipher_suites, [])
        self.assertEqual(result.extension_types, [])
        self.assertEqual(result.named_curves, [])
        self.assertEqual(result.ec_point_formats, [])

    def test_tag_one_element_lists(self):
        result = self.get_result('771,3,2,1,0')
        self.assertEqual(result.tls_protocol_version, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.cipher_suites, [TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5])
        self.assertEqual(result.extension_types, [TlsExtensionType.CLIENT_CERTIFICATE_URL])
        self.assertEqual(result.named_curves, [TlsNamedCurve.SECT163K1])
        self.assertEqual(result.ec_point_formats, [TlsECPointFormat.UNCOMPRESSED])

    def test_tag_two_element_lists(self):
        result = self.get_result('771,7-6,5-4,3-2,1-0')
        self.assertEqual(
            result.tls_protocol_version, TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            result.cipher_suites,
            [TlsCipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA, TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5]
        )
        self.assertEqual(
            result.extension_types,
            [TlsExtensionType.STATUS_REQUEST, TlsExtensionType.TRUNCATED_HMAC]
        )
        self.assertEqual(
            result.named_curves,
            [TlsNamedCurve.SECT163R2, TlsNamedCurve.SECT163R1]
        )
        self.assertEqual(
            result.ec_point_formats,
            [TlsECPointFormat.ANSIX962_COMPRESSED_PRIME, TlsECPointFormat.UNCOMPRESSED]
        )
