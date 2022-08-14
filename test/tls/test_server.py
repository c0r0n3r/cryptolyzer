# -*- coding: utf-8 -*-

import ftplib
import nntplib
import poplib
import smtplib
import ssl
import sys
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

import six

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.ldap import LDAPExtendedRequestStartTLS
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.record import SslRecord, TlsRecord
from cryptoparser.tls.postgresql import SslRequest
from cryptoparser.tls.rdp import (
    TPKT,
    COTPConnectionRequest,
    RDPProtocol,
    RDPNegotiationRequest,
)
from cryptoparser.tls.subprotocol import (
    SslCipherKind,
    SslErrorMessage,
    SslErrorType,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsContentType,
    TlsExtensionsClient,
    TlsHandshakeType,
    TlsHandshakeServerHello,
)

from cryptolyzer.common.transfer import L4ClientTCP
from cryptolyzer.tls.client import (
    ClientFTP,
    ClientLDAP,
    ClientLMTP,
    ClientNNTP,
    ClientPOP3,
    ClientPostgreSQL,
    ClientRDP,
    ClientSieve,
    ClientSMTP,
    L7ClientTls,
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsAlert,
    TlsHandshakeClientHelloAnyAlgorithm
)
from cryptolyzer.tls.server import (
    L7ServerTls,
    L7ServerTlsFTP,
    L7ServerTlsLDAP,
    L7ServerTlsLMTP,
    L7ServerTlsNNTP,
    L7ServerTlsPOP3,
    L7ServerTlsPostgreSQL,
    L7ServerTlsRDP,
    L7ServerTlsSieve,
    L7ServerTlsSMTP,
    TlsServerConfiguration,
)

from .classes import L7ServerTlsTest, L7ServerStartTlsTest


class TestL7ServerBase(unittest.TestCase):
    def setUp(self):
        self.threaded_server = None
        if sys.version_info.major == 3 and sys.version_info.minor == 4:
            if sys.implementation == 'cpython':
                self.ssl_exception_reason = 'WRONG_SSL_VERSION'
            else:
                self.ssl_exception_reason = 'SSLV3_ALERT_HANDSHAKE_FAILURE'
        else:
            self.ssl_exception_reason = 'UNEXPECTED_MESSAGE'

    @staticmethod
    def create_server(configuration=None, l7_server_class=L7ServerTls):
        threaded_server = L7ServerTlsTest(l7_server_class('localhost', 0, timeout=2, configuration=configuration))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @staticmethod
    def create_client(client_class, l7_server):
        return client_class(l7_server.address, l7_server.l4_transfer.bind_port, ip=l7_server.ip)

    def _assert_on_more_data(self, client):
        buffer_length = len(client.buffer)
        try:
            client.receive(16)
        except NotEnoughData:
            pass
        self.assertEqual(client.buffer[buffer_length:], bytearray())

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
            self.assertEqual(actual_response.fragment, expected_response.fragment)
        self._assert_on_more_data(l4_client)
        l4_client.close()

    def _test_ssl_handshake(self):
        client_hello = SslHandshakeClientHelloAnyAlgorithm()
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        server_messages = l7_client.do_ssl_handshake(hello_message=client_hello)
        self.assertEqual(len(server_messages), 1)
        self.assertEqual(server_messages[SslMessageType.SERVER_HELLO].cipher_kinds, list(SslCipherKind))

        self.threaded_server.join()

    def _test_tls_handshake(
        self,
        protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
        last_handshake_message_type=TlsHandshakeType.SERVER_HELLO,
        l7_client_class=L7ClientTls
    ):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([protocol_version, ], self.threaded_server.l7_server.address)
        l7_client = self.create_client(l7_client_class, self.threaded_server.l7_server)
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=last_handshake_message_type
        )
        self.assertEqual(list(server_messages.keys()), [last_handshake_message_type])

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
        expected_response = TlsRecord(
            TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR).compose(),
            content_type=TlsContentType.ALERT,
        )
        self._send_binary_message(b'Plain text request', expected_response)

    def test_error_invalid_type(self):
        expected_response = TlsRecord(
            TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR).compose(),
            content_type=TlsContentType.ALERT,
        )
        self._send_binary_message(b'\xff' + (TlsRecord.HEADER_SIZE - 1) * b'\x00', expected_response)

    def test_error_first_request_not_client_hello(self):
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        hello_message = TlsHandshakeServerHello(
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            cipher_suite=TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            extensions=TlsExtensionsClient([]),
        )
        with self.assertRaises(TlsAlert) as context_manager:
            l7_client.do_tls_handshake(hello_message=hello_message)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)

    @mock.patch.object(
        TlsRecord, 'compose',
        return_value=TlsRecord(
            TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY).compose(),
            TlsProtocolVersionFinal(TlsVersion.TLS1_0),
            TlsContentType.ALERT,
        ).compose()
    )
    def test_error_alert_in_request(self, _):
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        hello_message = TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)
        with self.assertRaises(TlsAlert) as context_manager:
            l7_client.do_tls_handshake(hello_message=hello_message)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.CLOSE_NOTIFY)

    def test_handshake(self):
        self._test_tls_handshake(TlsProtocolVersionFinal(TlsVersion.TLS1_2))


class TestL7ServerTls13(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server()

    def test_handshake(self):
        self._test_tls_handshake(
            TlsProtocolVersionFinal(TlsVersion.TLS1_3),
            TlsHandshakeType.HELLO_RETRY_REQUEST
        )


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
        self._test_tls_handshake(TlsProtocolVersionFinal(TlsVersion.TLS1_2))


class TestL7ServerTlsCloseOnError(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(close_on_error=True))

    def test_tls_handshake(self):
        self._test_tls_handshake(TlsProtocolVersionFinal(TlsVersion.TLS1_2))


class TestL7ServerTlsRDP(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsRDP)

    def test_error_alert_in_request(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()

        neg_req = RDPNegotiationRequest([], [RDPProtocol.RDP, ])
        cotp = COTPConnectionRequest(src_ref=0, user_data=neg_req.compose())
        tpkt = TPKT(version=3, message=cotp.compose())
        request_bytes = tpkt.compose()

        l4_client.send(request_bytes)
        self._assert_on_more_data(l4_client)

        l4_client.close()

    def test_default_port(self):
        self.assertEqual(ClientRDP.get_default_port(), L7ServerTlsRDP.get_default_port())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientRDP)


class TestL7ServerTlsLDAP(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsLDAP)

    def test_error_unfinished_tls_request(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()

        self._assert_on_more_data(l4_client)

        l4_client.close()

    def test_error_invlaid_tls_request(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()

        l4_client.send((LDAPExtendedRequestStartTLS.HEADER_SIZE + 1) * b'\x00')
        self._assert_on_more_data(l4_client)

        l4_client.close()

    def test_default_port(self):
        self.assertEqual(
            ClientLDAP.get_default_port() // 100 * 1000 + ClientLDAP.get_default_port(),
            L7ServerTlsLDAP.get_default_port()
        )

    def test_scheme(self):
        self.assertEqual(ClientLDAP.get_scheme(), L7ServerTlsLDAP.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientLDAP)


class TestL7ServerTlsPostgreSQL(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsPostgreSQL)

    def test_error_invlaid_tls_request(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()

        l4_client.send(SslRequest.MESSAGE_SIZE * b'\x00')
        self._assert_on_more_data(l4_client)

        l4_client.close()

    def test_default_port(self):
        self.assertEqual(ClientPostgreSQL.get_default_port(), L7ServerTlsPostgreSQL.get_default_port())

    def test_scheme(self):
        self.assertEqual(ClientPostgreSQL.get_scheme(), L7ServerTlsPostgreSQL.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientPostgreSQL)


class TestL7ServerTlsSieve(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsSieve)

    def test_error_invlaid_tls_request(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()

        while True:
            l4_client.receive_line()
            line = l4_client.buffer
            l4_client.flush_buffer()

            if line.startswith(b'OK'):
                break

        l4_client.send(b'\x00\r\n')
        self._assert_on_more_data(l4_client)

        l4_client.close()

    def test_default_port(self):
        self.assertEqual(ClientSieve.get_default_port(), L7ServerTlsSieve.get_default_port())

    def test_scheme(self):
        self.assertEqual(ClientSieve.get_scheme(), L7ServerTlsSieve.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientSieve)


class TestL7ServerStartTls(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerStartTlsTest)

        self.l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        self.l4_client.init_connection()

    def tearDown(self):
        self.l4_client.close()

    def _test_no_response(self):
        self._assert_on_more_data(self.l4_client)

    def test_greeting(self):
        self.l4_client.receive_line()
        self.assertEqual(self.l4_client.buffer, b'Greeting\r\n')
        self.l4_client.flush_buffer()

    def test_error_not_capabilities_and_not_starttls(self):
        self.test_greeting()
        self.l4_client.send(b'NO CAPABILITIES NO STARTTLS\r\n')
        self._test_no_response()

    def test_error_not_starttls(self):
        self.test_capabilities()
        self.l4_client.send(b'NOT STARTTLS\r\n')
        self._test_no_response()

    @mock.patch.object(L7ServerStartTlsTest, '_get_capabilities_request_prefix', return_value=None)
    def test_no_capabilities(self, _):
        self.test_greeting()
        self._test_no_response()

    def _test_capabilities(self):
        self.test_greeting()

        self.l4_client.send(b'CAPABILITIES\r\n')
        self.l4_client.receive_line()
        self.assertEqual(self.l4_client.buffer, b'STARTTLS\r\n')
        self.l4_client.flush_buffer()

    def test_capabilities(self):
        self._test_capabilities()
        self._test_no_response()

    def _test_starttls(self):
        self.l4_client.send(b'STARTTLS\r\n')
        self.l4_client.receive_line()
        self.assertEqual(self.l4_client.buffer, b'OK\r\n')

    def test_starttls_with_capabilities(self):
        self._test_capabilities()
        self._test_starttls()
        self._test_no_response()

    def test_starttls_without_capabilities(self):
        self.test_greeting()
        self._test_starttls()
        self._test_no_response()


class TestL7ServerTlsFTP(TestL7ServerBase):
    def setUp(self):
        super(TestL7ServerTlsFTP, self).setUp()

        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsFTP)

    def test_default_port(self):
        self.assertEqual(
            ClientFTP.get_default_port() * 100 + ClientFTP.get_default_port(),
            L7ServerTlsFTP.get_default_port()
        )

    def test_scheme(self):
        self.assertEqual(ClientFTP.get_scheme(), L7ServerTlsFTP.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientFTP)

    def test_real_with_capabilities(self):
        client = ftplib.FTP_TLS()
        client.connect(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )
        client.sendcmd('FEAT')
        with self.assertRaises(ssl.SSLError) as context_manager:
            client.auth()

        self.assertEqual(context_manager.exception.reason, self.ssl_exception_reason)

    def test_real_without_capabilities(self):
        client = ftplib.FTP_TLS()
        client.connect(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )
        with self.assertRaises(ssl.SSLError) as context_manager:
            client.auth()

        self.assertEqual(context_manager.exception.reason, self.ssl_exception_reason)


class TestL7ServerTlsPOP3(TestL7ServerBase):
    def setUp(self):
        super(TestL7ServerTlsPOP3, self).setUp()

        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsPOP3)

    def test_default_port(self):
        self.assertEqual(
            ClientPOP3.get_default_port() * 10 + 10,
            L7ServerTlsPOP3.get_default_port()
        )

    def test_scheme(self):
        self.assertEqual(ClientPOP3.get_scheme(), L7ServerTlsPOP3.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientPOP3)

    @unittest.skipIf(six.PY2, 'There is no poplib.POP3.stls in Python < 3.0')
    def test_real_with_capabilities_stls(self):
        client = poplib.POP3(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )
        with self.assertRaises(ssl.SSLError) as context_manager:
            client.stls()

        self.assertEqual(context_manager.exception.reason, self.ssl_exception_reason)

    @unittest.skipIf(six.PY3, 'There is no poplib.POP3.stls in Python < 3.0')
    def test_real_with_capabilities_cmd(self):
        client = poplib.POP3(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )

        response, capabilities, _ = client._longcmd('CAPABILITIES')  # pylint: disable=protected-access
        self.assertEqual(response, '+OK')
        self.assertEqual(capabilities, ['CAPA', 'STLS'])

        response = client._shortcmd('STLS')  # pylint: disable=protected-access
        self.assertEqual(response, '+OK Begin TLS negotiation now.')


class TestL7ServerTlsLMTP(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsLMTP)

    def test_default_port(self):
        self.assertEqual(
            ClientLMTP.get_default_port() * 100 + ClientLMTP.get_default_port(),
            L7ServerTlsLMTP.get_default_port()
        )

    def test_scheme(self):
        self.assertEqual(ClientLMTP.get_scheme(), L7ServerTlsLMTP.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientLMTP)

    def test_real_with_capabilities(self):
        client = smtplib.LMTP(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )
        with self.assertRaises(smtplib.SMTPServerDisconnected) as context_manager:
            client.starttls()

        self.assertEqual(context_manager.exception.args[0], 'Connection unexpectedly closed')


class TestL7ServerTlsSMTP(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsSMTP)

    def test_default_port(self):
        self.assertEqual(
            ClientSMTP.get_default_port() // 100 * 1000 + ClientSMTP.get_default_port(),
            L7ServerTlsSMTP.get_default_port()
        )

    def test_scheme(self):
        self.assertEqual(ClientSMTP.get_scheme(), L7ServerTlsSMTP.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientSMTP)

    def test_real_with_capabilities(self):
        client = smtplib.SMTP(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )
        with self.assertRaises(smtplib.SMTPServerDisconnected) as context_manager:
            client.starttls()

        self.assertEqual(context_manager.exception.args[0], 'Connection unexpectedly closed')


class TestL7ServerTlsNNTP(TestL7ServerBase):
    def setUp(self):
        super(TestL7ServerTlsNNTP, self).setUp()

        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsNNTP)

    def test_default_port(self):
        self.assertEqual(
            ClientNNTP.get_default_port() // 100 * 1000 + ClientNNTP.get_default_port(),
            L7ServerTlsNNTP.get_default_port()
        )

    def test_scheme(self):
        self.assertEqual(ClientNNTP.get_scheme(), L7ServerTlsNNTP.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientNNTP)

    @unittest.skipIf(six.PY2, 'There is no nntplib.NNTP.starttls in Python < 3.0')
    def test_real_with_capabilities(self):
        client = nntplib.NNTP(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )
        with self.assertRaises(ssl.SSLError) as context_manager:
            client.starttls()

        self.assertEqual(context_manager.exception.reason, self.ssl_exception_reason)
