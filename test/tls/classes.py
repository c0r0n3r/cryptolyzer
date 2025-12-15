# -*- coding: utf-8 -*-

import datetime

import abc
from unittest import mock

from test.common.classes import TestThreadedServer, TestLoggerBase

import attr

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionsClient
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.subprotocol import (
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsContentType,
    TlsHandshakeHelloRandom,
    TlsHandshakeServerHello,
)
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.server import L7ServerTls, L7ServerStartTlsTextBase, TlsServerHandshake


class TestTlsCases:
    class TestTlsBase(TestLoggerBase):
        @staticmethod
        @abc.abstractmethod
        def get_result(host, port, protocol_version=None, l4_socket_params=None, ip=None):
            raise NotImplementedError()

        @staticmethod
        def create_server(configuration=None):
            threaded_server = L7ServerTlsTest(L7ServerTls(
                'localhost', 0, L4TransferSocketParams(timeout=0.2), configuration=configuration
            ))
            threaded_server.wait_for_server_listen()
            return threaded_server

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)
        )
        def test_error_security_error_unparsable_message(self, _):
            self.get_result('badssl.com', 443)

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_CONNECTION)
        )
        def test_error_network_error_no_connection(self, _):
            with self.assertRaises(NetworkError) as context_manager:
                self.get_result('badssl.com', 443)
            self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_RESPONSE)
        )
        def test_error_network_error_no_response(self, _):
            self.get_result('badssl.com', 443)

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
        )
        def test_error_tls_alert(self, _):
            with self.assertRaises(TlsAlert) as context_manager:
                self.get_result('badssl.com', 443)
            self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)


class L7ServerTlsTest(TestThreadedServer):
    def __init__(self, l7_server):
        self.l7_server = l7_server
        super().__init__(self.l7_server)

    def run(self):
        self.l7_server.do_handshake()


@attr.s
class TlsServerMockResponse(TlsServerHandshake):
    def _get_mock_responses(self):
        raise NotImplementedError()

    def _init_connection(self, last_handshake_message_type):
        mock_responses = self._get_mock_responses()
        self.l7_transfer.send(bytearray().join(mock_responses))

    def _parse_record(self):
        if not self.l7_transfer.buffer:
            raise NotEnoughData(1)

        return None, len(self.l7_transfer.buffer), True

    def _parse_message(self, record):
        return None

    def _process_handshake_message(self, message, last_handshake_message_type):
        pass

    def _process_invalid_message(self):
        pass


class L7ServerTlsMockResponse(L7ServerTls):
    def _get_handshake_class(self):
        return TlsServerMockResponse


class TlsServerPlainTextResponse(TlsServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):
        self.l7_transfer.send(
            b'<!DOCTYPE html><html><body>Typical plain text response to TLS client hello message</body></html>'
        )


class L7ServerTlsPlainTextResponse(L7ServerTls):
    def _get_handshake_class(self):
        return TlsServerPlainTextResponse


class TlsServerCloseDuringHandshake(TlsServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):
        self.l7_transfer.send(
            TlsRecord(
                TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.USER_CANCELED).compose(),
                content_type=TlsContentType.ALERT,
            ).compose()[:TlsRecord.HEADER_SIZE],
        )


class L7ServerTlsCloseDuringHandshake(L7ServerTls):
    def _get_handshake_class(self):
        return TlsServerCloseDuringHandshake


class TlsServerOneMessageInMultipleRecords(TlsServerHandshake):
    SERVER_HELLO_MESSAGE = TlsHandshakeServerHello(
        protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
        random=TlsHandshakeHelloRandom(datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)),
        cipher_suite=TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        extensions=TlsExtensionsClient([]),
    )

    def _process_handshake_message(self, message, last_handshake_message_type):
        for hello_message_byte in self.SERVER_HELLO_MESSAGE.compose():
            self.l7_transfer.send(TlsRecord(fragment=bytes((hello_message_byte,))).compose())


class L7ServerTlsOneMessageInMultipleRecords(L7ServerTls):
    def _get_handshake_class(self):
        return TlsServerOneMessageInMultipleRecords


class TlsServerAlert(TlsServerHandshake):
    def _get_alert_message(self):
        raise NotImplementedError()

    def _process_handshake_message(self, message, last_handshake_message_type):
        handshake_message_bytes = self._get_alert_message().compose()
        self.l7_transfer.send(TlsRecord(handshake_message_bytes + handshake_message_bytes).compose())


class L7ServerTlsAlert(L7ServerTls):
    def _get_handshake_class(self):
        return TlsServerAlert


class TlsServerLongCipherSuiteListIntolerance(TlsServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):
        if len(message.cipher_suites) >= 192:
            self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE)
            raise StopIteration()

        super()._process_handshake_message(
            message, last_handshake_message_type
        )


class L7ServerTlsLongCipherSuiteListIntolerance(L7ServerTls):
    def _get_handshake_class(self):
        return TlsServerLongCipherSuiteListIntolerance


class L7ServerStartTlsTest(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'test'

    @classmethod
    def get_default_port(cls):
        return 1234

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'CAPABILITIES'

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'STARTTLS',
            b'',
        ])

    @classmethod
    def _get_greeting(cls):
        return b'Greeting\r\n'

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'STARTTLS'

    @classmethod
    def _get_starttls_response(cls):
        return b'OK\r\n'
