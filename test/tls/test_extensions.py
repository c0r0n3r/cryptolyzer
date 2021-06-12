#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.algorithm import TlsProtocolName
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import (
    TlsExtensionApplicationLayerProtocolNegotiation,
)
from cryptoparser.tls.subprotocol import (
    TlsCompressionMethod,
    TlsHandshakeServerHello,
    TlsHandshakeType,
)
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.extensions import AnalyzerExtensions


class TestTlsExtensions(unittest.TestCase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2), timeout=None, ip=None):
        analyzer = AnalyzerExtensions()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        return_value={
            TlsHandshakeType.SERVER_HELLO:
            TlsHandshakeServerHello(
                cipher_suite=TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                extensions=[
                    TlsExtensionApplicationLayerProtocolNegotiation([TlsProtocolName.HTTP_1_1, ])
                ]
            )
        }
    )
    def test_error_application_layer_protocols(self, _):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(
            set(result.application_layer_protocols),
            set([TlsProtocolName.HTTP_1_1, ])
        )

    def test_application_layer_protocols(self):
        result = self.get_result('www.mail.ru', 443)
        self.assertEqual(result.application_layer_protocols, [])

        result = self.get_result('www.wikipedia.org', 443)
        self.assertEqual(
            set(result.application_layer_protocols),
            set([TlsProtocolName.HTTP_1_0, TlsProtocolName.H2, TlsProtocolName.HTTP_1_1])
        )

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=[
            {
                TlsHandshakeType.SERVER_HELLO:
                TlsHandshakeServerHello(
                    cipher_suite=TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                    compression_method=TlsCompressionMethod.NULL,
                    extensions=[
                        TlsExtensionApplicationLayerProtocolNegotiation([TlsProtocolName.HTTP_1_1, ])
                    ]
                )
            },
            {
                TlsHandshakeType.SERVER_HELLO:
                TlsHandshakeServerHello(
                    cipher_suite=TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                    compression_method=TlsCompressionMethod.DEFLATE,
                    extensions=[
                        TlsExtensionApplicationLayerProtocolNegotiation([TlsProtocolName.HTTP_1_1, ])
                    ]
                )
            },
            {
                TlsHandshakeType.SERVER_HELLO:
                TlsHandshakeServerHello(
                    cipher_suite=TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                    compression_method=TlsCompressionMethod.LZS,
                    extensions=[
                        TlsExtensionApplicationLayerProtocolNegotiation([TlsProtocolName.HTTP_1_1, ])
                    ]
                )
            }
        ]
    )
    def test_compression_method_all(self, _):
        analyzer = AnalyzerExtensions()
        l7_client = L7ClientTlsBase.from_scheme('tls', 'www.cloudflare.com', 443)
        compression_methods = analyzer._analyze_compression_methods(  # pylint: disable=protected-access
            l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )

        self.assertEqual(
            set(compression_methods),
            set([TlsCompressionMethod.NULL, TlsCompressionMethod.DEFLATE, TlsCompressionMethod.LZS])
        )

    def test_compression_method(self):
        result = self.get_result('www.cloudflare.com', 443)

        self.assertEqual(
            set(result.compression_methods),
            set([TlsCompressionMethod.NULL, ])
        )

    def test_encrypt_then_mac(self):
        result = self.get_result('tls-v1-0.badssl.com', 1010, TlsProtocolVersionFinal(TlsVersion.TLS1_0))
        self.assertFalse(result.encrypt_then_mac_supported)

        result = self.get_result('www.cloudflare.com', 443)
        self.assertFalse(result.encrypt_then_mac_supported)

        result = self.get_result('www.facebook.com', 443)
        self.assertTrue(result.encrypt_then_mac_supported)

        result = self.get_result('www.protonmail.com', 443)
        self.assertIsNone(result.encrypt_then_mac_supported)

    def test_extended_master_secret(self):
        result = self.get_result('tls-v1-2.badssl.com', 1012)
        self.assertFalse(result.extended_master_secret_supported)

        result = self.get_result('www.cloudflare.com', 443)
        self.assertTrue(result.extended_master_secret_supported)

    def test_clock_is_accurate(self):
        result = self.get_result('www.facebook.com', 443)
        self.assertFalse(result.clock_is_accurate)

        result = self.get_result('www.cloudflare.com', 443)
        self.assertTrue(result.clock_is_accurate)

    def test_renegotiation_info(self):
        result = self.get_result('www.deloton.com', 443)
        self.assertFalse(result.renegotiation_supported)

        result = self.get_result('www.cloudflare.com', 443)
        self.assertTrue(result.renegotiation_supported)

    def test_session_ticket(self):
        result = self.get_result('www.github.com', 443)
        self.assertFalse(result.session_ticket_supported)

        result = self.get_result('www.cloudflare.com', 443)
        self.assertTrue(result.session_ticket_supported)
