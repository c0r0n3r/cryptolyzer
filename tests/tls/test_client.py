#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import sys
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.tls.versions import AnalyzerVersions


class TestL7Client(unittest.TestCase):
    @staticmethod
    def get_result(proto, host, port, timeout=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme(proto, host, port, timeout)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    @unittest.skipIf(
        sys.version_info < (3, 0),
        'There is no ConnectionRefusedError in Python < 3.0'
    )
    def test_error_connection_refused(self):
        with mock.patch.object(L7ClientTlsBase, '_setup_connection', side_effect=ConnectionRefusedError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @unittest.skipIf(
        sys.version_info >= (3, 0),
        'ConnectionRefusedError is raised instead of socket.error in Python >= 3.0'
    )
    def test_error_connection_refused_socket_error(self):
        with mock.patch.object(L7ClientTlsBase, '_setup_connection', side_effect=socket.error), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(L7ClientTlsBase, '_send', return_value=0)
    def test_error_send(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_tls_client(self):
        self.assertEqual(
            self.get_result('tls', 'badssl.com', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_https_client(self):
        self.assertEqual(
            self.get_result('https', 'badssl.com', None).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_pop3_client(self):
        self.assertEqual(
            self.get_result('pop3', 'pop3.comcast.net', None, 10).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_pop3s_client(self):
        self.assertEqual(
            self.get_result('pop3s', 'pop.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_imap_client(self):
        self.assertEqual(
            self.get_result('imap', 'imap.comcast.net', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_imaps_client(self):
        self.assertEqual(
            self.get_result('imaps', 'imap.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_smtp_client(self):
        self.assertEqual(
            self.get_result('smtp', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_smtps_client(self):
        self.assertEqual(
            self.get_result('smtps', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
