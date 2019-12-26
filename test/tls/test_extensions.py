#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

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
