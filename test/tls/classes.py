# -*- coding: utf-8 -*-

import abc
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from test.common.classes import TestThreaderServer

from cryptoparser.tls.subprotocol import TlsAlertDescription

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert


class TestTlsCases:
    class TestTlsBase(unittest.TestCase):
        @staticmethod
        @abc.abstractmethod
        def get_result(host, port, protocol_version=None, timeout=None):
            raise NotImplementedError()

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_CONNECTION)
        )
        def test_error_network_error_no_response(self, _):
            with self.assertRaises(NetworkError) as context_manager:
                self.get_result('badssl.com', 443)
            self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
        )
        def test_error_tls_alert(self, _):
            with self.assertRaises(TlsAlert) as context_manager:
                self.get_result('badssl.com', 443)
            self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)


class L7ServerTlsTest(TestThreaderServer):
    def __init__(self, l7_server, fallback_to_ssl):
        self.l7_server = l7_server
        super(L7ServerTlsTest, self).__init__(self.l7_server)

        self.fallback_to_ssl = fallback_to_ssl

    def run(self):
        if self.fallback_to_ssl is None:
            self.l7_server.do_ssl_handshake()
        else:
            self.l7_server.do_tls_handshake(fallback_to_ssl=self.fallback_to_ssl)
