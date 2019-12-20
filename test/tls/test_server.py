# -*- coding: utf-8 -*-

import unittest

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.record import SslRecord, TlsRecord
from cryptoparser.tls.subprotocol import (
    SslCipherKind,
    SslErrorMessage,
    SslErrorType,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsExtensions,
    TlsHandshakeType,
    TlsHandshakeServerHello,
)

from cryptolyzer.common.transfer import L4ClientTCP
from cryptolyzer.tls.client import (
    L7ClientTls,
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsAlert,
    TlsHandshakeClientHelloAnyAlgorithm
)
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration

from .classes import L7ServerTlsTest


class TestL7ServerBase(unittest.TestCase):
    def setUp(self):
        self.threaded_server = None

    @staticmethod
    def create_server(configuration=None):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, timeout=0.2, configuration=configuration))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @staticmethod
    def create_client(client_class, l7_server):
        return client_class(l7_server.address, l7_server.l4_transfer.bind_port, ip=l7_server.ip)

    def _assert_on_more_data(self, client):
        with self.assertRaises(NotEnoughData) as context_manager:
            client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def _send_binary_message(self, message, expected_response, ssl_expected=False):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.send(message)
        l4_client.receive(len(expected_response.compose()))
        if ssl_expected:
            actual_response = SslRecord.parse_exact_size(l4_client.buffer)
            self.assertEqual(actual_response.message, expected_response.message)
        else:
            actual_response = TlsRecord.parse_exact_size(l4_client.buffer)
            self.assertEqual(actual_response.messages, expected_response.messages)
        self._assert_on_more_data(l4_client)
        l4_client.close()

    def _test_ssl_handshake(self):
        client_hello = SslHandshakeClientHelloAnyAlgorithm()
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        server_messages = l7_client.do_ssl_handshake(hello_message=client_hello)
        self.assertEqual(len(server_messages), 1)
        self.assertEqual(server_messages[SslMessageType.SERVER_HELLO].cipher_kinds, list(SslCipherKind))

        self.threaded_server.join()

    def _test_tls_handshake(self):
        protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([protocol_version, ], self.threaded_server.l7_server.address)
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        server_messages = l7_client.do_tls_handshake(hello_message=client_hello)
        self.assertEqual(list(server_messages.keys()), [TlsHandshakeType.SERVER_HELLO])

        self.threaded_server.join()


class TestL7ServerTlsBase(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server()

    def test_error_no_data(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.send(b'')
        self._assert_on_more_data(l4_client)
        l4_client.close()


class TestL7ServerSsl(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(fallback_to_ssl=True))

    def test_error_plain_text(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.send(b'Plain text request' * 1000)
        expected_response = SslRecord(SslErrorMessage(SslErrorType.NO_CIPHER_ERROR))
        l4_client.receive(len(expected_response.compose()))
        actual_response = SslRecord.parse_exact_size(l4_client.buffer)
        self.assertEqual(actual_response.message, expected_response.message)
        self._assert_on_more_data(l4_client)
        l4_client.close()

    def test_error_invalid_type(self):
        expected_response = SslRecord(SslErrorMessage(SslErrorType.NO_CIPHER_ERROR))
        self._send_binary_message(b'\x00\x01\x00\xff\x00', expected_response, ssl_expected=True)

    def test_not_enough_data(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.send(b'\x00')
        self._assert_on_more_data(l4_client)
        l4_client.close()

    def test_error_alert_in_request(self):
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        hello_message = SslErrorMessage(SslErrorType.NO_CIPHER_ERROR)
        with self.assertRaises(SslError) as context_manager:
            l7_client.do_ssl_handshake(hello_message=hello_message)
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CIPHER_ERROR)

    def test_handshake(self):
        self._test_ssl_handshake()


class TestL7ServerTls(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server()

    def test_error_plain_text(self):
        expected_response = TlsRecord([TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR), ])
        self._send_binary_message(b'Plain text request', expected_response)

    def test_error_invalid_type(self):
        expected_response = TlsRecord([TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR), ])
        self._send_binary_message(b'\xff' + (TlsRecord.HEADER_SIZE - 1) * b'\x00', expected_response)

    def test_error_first_request_not_client_hello(self):
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        hello_message = TlsHandshakeServerHello(
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            cipher_suite=TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            extensions=TlsExtensions([]),
        )
        with self.assertRaises(TlsAlert) as context_manager:
            l7_client.do_tls_handshake(hello_message=hello_message)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)

    def test_error_alert_in_request(self):
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        hello_message = TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)
        with self.assertRaises(TlsAlert) as context_manager:
            l7_client.do_tls_handshake(hello_message=hello_message)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)

    def test_handshake(self):
        self._test_tls_handshake()


class TestL7ServerTlsFallbackToSsl(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(fallback_to_ssl=True))

    def test_not_enough_data(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.send(b'\x00')
        self._assert_on_more_data(l4_client)
        l4_client.close()

    def test_ssl_handshake(self):
        self._test_ssl_handshake()

    def test_tls_handshake(self):
        self._test_tls_handshake()


class TestL7ServerTlsCloseOnError(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(close_on_error=True))

    def test_tls_handshake(self):
        self._test_tls_handshake()
