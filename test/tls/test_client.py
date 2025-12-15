# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import ftplib
import imaplib
import socket
import unittest
from unittest import mock

from test.common.classes import TestLoggerBase

import urllib3


from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.tls.ciphersuite import SslCipherKind
from cryptoparser.tls.ldap import LDAPMessageParsableBase, LDAPExtendedResponseStartTLS, LDAPResultCode
from cryptoparser.tls.mysql import MySQLCapability, MySQLRecord, MySQLCharacterSet, MySQLHandshakeV10, MySQLVersion
from cryptoparser.tls.openvpn import (
    OpenVpnPacketHardResetClientV2,
    OpenVpnPacketHardResetServerV2,
    OpenVpnPacketWrapperTcp,
)
from cryptoparser.tls.rdp import COTPConnectionConfirm, TPKT, RDPNegotiationResponse

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.record import ParsableBase, TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import (
    SslErrorMessage,
    SslErrorType,
    SslHandshakeClientHello,
    SslHandshakeServerHello,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsChangeCipherSpecMessage,
    TlsContentType,
    TlsHandshakeServerHello,
    TlsHandshakeType,
)
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.tls.client import (
    ClientIMAP,
    ClientOpenVpnBase,
    ClientXMPPClient,
    ClientXMPPServer,
    L7ClientHTTPS,
    L7ClientTls,
    L7ClientTlsBase,
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsAlert,
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloBlockCipherModeCBC,
    TlsHandshakeClientHelloBulkCipherBlockSize64,
    TlsHandshakeClientHelloBulkCipherNull,
    TlsHandshakeClientHelloKeyExchangeAnonymousDH,
    TlsHandshakeClientHelloStreamCipherRC4,
)
from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.exception import (
    NetworkError,
    NetworkErrorType,
    SecurityError,
    SecurityErrorType
)
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.server import (
    L7ServerTls,
    L7ServerTlsBase,
    SslServerHandshake,
    TlsServerConfiguration,
    TlsServerHandshake,
)
from cryptolyzer.common.transfer import L4TransferBase, L4ClientTCP, L4ClientUDP, L7TransferBase
from cryptolyzer.tls.dhparams import AnalyzerDHParams
from cryptolyzer.tls.versions import AnalyzerVersions

from .classes import (
    L7ServerTlsCloseDuringHandshake,
    L7ServerTlsMockResponse,
    L7ServerTlsOneMessageInMultipleRecords,
    L7ServerTlsTest,
    TlsServerOneMessageInMultipleRecords,
    TlsServerMockResponse,
)


class TestTlsHandshakeClientHello(unittest.TestCase):
    _PROTOCOL_VERSION = TlsProtocolVersion(TlsVersion.TLS1_2)
    _HOSTNAME = 'hostname'

    def test_block_cipher_mode_cbc(self):
        self.assertEqual(
            list(TlsHandshakeClientHelloBlockCipherModeCBC(self._PROTOCOL_VERSION, self._HOSTNAME).cipher_suites),
            TlsHandshakeClientHelloBlockCipherModeCBC.CIPHER_SUITES

        )

    def test_bulk_cipher_block_size_64(self):
        self.assertEqual(
            list(TlsHandshakeClientHelloBulkCipherBlockSize64(self._PROTOCOL_VERSION, self._HOSTNAME).cipher_suites),
            TlsHandshakeClientHelloBulkCipherBlockSize64.CIPHER_SUITES

        )

    def test_bulk_cipher_null(self):
        self.assertEqual(
            list(TlsHandshakeClientHelloBulkCipherNull(self._PROTOCOL_VERSION, self._HOSTNAME).cipher_suites),
            TlsHandshakeClientHelloBulkCipherNull.CIPHER_SUITES

        )

    def test_key_exchange_anonymous_dh(self):
        self.assertEqual(
            list(TlsHandshakeClientHelloKeyExchangeAnonymousDH(self._PROTOCOL_VERSION, self._HOSTNAME).cipher_suites),
            TlsHandshakeClientHelloKeyExchangeAnonymousDH.CIPHER_SUITES

        )

    def test_stream_cipher_rc4(self):
        self.assertEqual(
            list(TlsHandshakeClientHelloStreamCipherRC4(self._PROTOCOL_VERSION, self._HOSTNAME).cipher_suites),
            TlsHandshakeClientHelloStreamCipherRC4.CIPHER_SUITES

        )


class L7ServerTlsFatalResponse(TlsServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):
        self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.USER_CANCELED)
        raise StopIteration()


class L7ServerSslPlainTextResponse(SslServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):
        self.l7_transfer.send(b'\x00\x01\x00\xff\x00')
        raise StopIteration()


class TestTlsAlert(unittest.TestCase):
    def test_repr_and_str(self):
        alert = TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)
        self.assertEqual(str(alert), repr(alert))


class TestL7ClientBase(TestLoggerBase):
    @staticmethod
    def get_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            proto,
            host,
            port,
            l4_socket_params=L4TransferSocketParams(),
            ip=None,
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            analyzer=None
    ):
        if analyzer is None:
            analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme(proto, host, port, l4_socket_params, ip=ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return l7_client, result

    @staticmethod
    def _start_mock_server():
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()

        return threaded_server

    def _get_mock_server_response(self, scheme):
        threaded_server = self._start_mock_server()
        return self.get_result(  # pylint: disable = expression-not-assigned
            scheme, 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )


class L7ClientTlsMock(L7ClientTls):
    pass


class TestL7ClientTlsBase(TestL7ClientBase):
    def test_error_unexisting_hostname(self):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'unexisting.hostname', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    @mock.patch.object(socket, 'getaddrinfo', return_value=[])
    def test_error_hostname_with_no_address(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'hostname.with.no.address', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_error_invalid_address(self):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443, ip='not.an.ip.address')
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    @mock.patch.object(L4ClientTCP, '_send', return_value=0)
    def test_error_send(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_error_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            self.get_result('unsupported_scheme', 'badssl.com', 443)

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=[
        TlsRecord(
            TlsHandshakeServerHello(cipher_suite=TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_MD5).compose(),
            content_type=TlsContentType.HANDSHAKE,
        ).compose(),
        TlsRecord(
            TlsChangeCipherSpecMessage().compose(),
            content_type=TlsContentType.CHANGE_CIPHER_SPEC,
        ).compose(),
    ])
    def test_different_content_types_in_one_message(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()

        client_hello = TlsHandshakeClientHelloAnyAlgorithm([TlsProtocolVersion(TlsVersion.TLS1_2), ], 'localhost')
        l7_client = L7ClientTlsBase.from_scheme(
            'tls', 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )
        server_messages = l7_client.do_tls_handshake(client_hello, last_handshake_message_type=None)
        self.assertEqual(list(server_messages.keys()), [TlsHandshakeType.SERVER_HELLO])

    def test_default_port(self):
        l7_client = L7ClientTlsMock('badssl.com')
        self.assertEqual(l7_client.port, 443)

    def test_error_connection_timeout_on_close(self):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsMock('badssl.com', 443)
        self.assertEqual(
            analyzer.analyze(l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)).versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        )

    def test_tls_client(self):
        _, result = self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        )

    def test_https_client(self):
        _, result = self.get_result('https', 'badssl.com', None)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        )


class TestL7ClientStartTlsTextBase(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'+OK Server ready.\r\n',
            b'+OK\r\n',
            'αβγ'.encode('utf-8'),
            b'\r\n',
            b'.\r\n',
        ]),
    ))
    def test_error_unsupported_capabilities(self, _):
        l7_client, result = self._get_mock_server_response('pop3')
        self.assertEqual(l7_client.greeting, ['+OK Server ready.'])
        self.assertEqual(result.versions, [])


class TestClientPOP3(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'+OK Server ready.\r\n',
            b'-ERR Command not permitted\r\n',
        ]),
    ))
    def test_error_unsupported_capabilities(self, _):
        l7_client, result = self._get_mock_server_response('pop3')
        self.assertEqual(l7_client.greeting, ['+OK Server ready.'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'+OK Server ready.\r\n',
            b'+OK\r\n',
            b'.\r\n',
        ]),
    ))
    def test_error_unsupported_starttls(self, _):
        l7_client, result = self._get_mock_server_response('pop3')
        self.assertEqual(l7_client.greeting, ['+OK Server ready.'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'+OK Server ready.\r\n',
            b'+OK\r\n',
            b'STLS\r\n',
            b'.\r\n',
            b'-ERR Command not permitted\r\n',
        ]),
    ))
    def test_error_starttls_error(self, _):
        l7_client, result = self._get_mock_server_response('pop3')
        self.assertEqual(l7_client.greeting, ['+OK Server ready.'])
        self.assertEqual(result.versions, [])

    def test_pop3_client(self):
        l7_client, result = self.get_result('pop3', 'pop3.comcast.net', None, L4TransferSocketParams(timeout=10))
        self.assertEqual(l7_client.greeting, ['+OK Dovecot ready.'])
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)

    def test_pop3s_client_port(self):
        client = L7ClientTlsBase.from_scheme('pop3s', 'localhost')
        self.assertEqual(client.port, 995)


class TestClientIMAP(TestL7ClientBase):
    @mock.patch.object(
        ClientIMAP, '_capabilities',
        mock.PropertyMock(return_value=(
            'IMAP4REV1',
            'LITERAL+',
            'SASL-IR',
            'LOGIN-REFERRALS',
            'ID',
            'ENABLE',
            'IDLE',
            'LOGINDISABLED',
        )),
        create=True
    )
    def test_error_unsupported_starttls(self):
        _, result = self.get_result('imap', 'imap.comcast.net', None, L4TransferSocketParams(timeout=10))
        self.assertEqual(result.versions, [])

    @mock.patch.object(imaplib.IMAP4, '__init__', side_effect=imaplib.IMAP4.error)
    def test_error_imap_error(self, _):
        _, result = self.get_result('imap', 'imap.comcast.net', None, L4TransferSocketParams(timeout=10))
        self.assertEqual(result.versions, [])

    @mock.patch.object(
        imaplib.IMAP4, 'xatom',
        return_value=[('BAD', 'command unknown or arguments invalid'), mock.DEFAULT]
    )
    @mock.patch.object(imaplib.IMAP4, 'shutdown', side_effect=imaplib.IMAP4.error)
    def test_error_starttls_error(self, _, __):
        _, result = self.get_result('imap', 'imap.comcast.net', None, L4TransferSocketParams(timeout=10))
        self.assertEqual(result.versions, [])

    def test_imap_client(self):
        _, result = self.get_result('imap', 'imap.comcast.net', None, L4TransferSocketParams(timeout=10))
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)

    def test_imaps_client_port(self):
        client = L7ClientTlsBase.from_scheme('imaps', 'localhost')
        self.assertEqual(client.port, 993)


class TestClientLMTP(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'220 localhost LMTP Server\r\n',
            b'502 Command not implemented\r\n',
        ]),
    ))
    def test_error_unsupported_capabilities(self, _):
        l7_client, result = self._get_mock_server_response('lmtp')
        self.assertEqual(l7_client.greeting, ['220 localhost LMTP Server'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'220 localhost LMTP Server\r\n',
            b'250-server at your service\r\n',
        ]),
    ))
    def test_error_unsupported_starttls(self, _):
        l7_client, result = self._get_mock_server_response('lmtp')
        self.assertEqual(l7_client.greeting, ['220 localhost LMTP Server'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'220 localhost LMTP Server\r\n',
            b'250-server at your service\r\n',
            b'250-STARTTLS\r\n',
            b'502 Command not implemented\r\n',
        ]),
    ))
    def test_error_starttls_error(self, _):
        l7_client, result = self._get_mock_server_response('lmtp')
        self.assertEqual(l7_client.greeting, ['220 localhost LMTP Server'])
        self.assertEqual(result.versions, [])

    def test_default_port(self):
        l7_client = L7ClientTlsBase.from_scheme('lmtp', 'localhost')
        self.assertEqual(l7_client.port, 24)


class TestClientSMTP(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'220 localhost ESMTP Server\r\n',
            b'502 Command not implemented\r\n',
        ]),
    ))
    def test_error_unsupported_capabilities(self, _):
        l7_client, result = self._get_mock_server_response('smtp')
        self.assertEqual(l7_client.greeting, ['220 localhost ESMTP Server'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'220 localhost ESMTP Server\r\n',
            b'250-server at your service\r\n',
        ]),
    ))
    def test_error_unsupported_starttls(self, _):
        l7_client, result = self._get_mock_server_response('smtp')
        self.assertEqual(l7_client.greeting, ['220 localhost ESMTP Server'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'220 localhost ESMTP Server\r\n',
            b'250-server at your service\r\n',
            b'250-STARTTLS\r\n',
            b'502 Command not implemented\r\n',
        ]),
    ))
    def test_error_starttls_error(self, _):
        l7_client, result = self._get_mock_server_response('smtp')
        self.assertEqual(l7_client.greeting, ['220 localhost ESMTP Server'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'220-localhost ESMTP\r\n',
            b'220 second line\r\n',
        ]),
    ))
    def test_multiline_greeting(self, _):
        l7_client, result = self._get_mock_server_response('smtp')
        self.assertEqual(l7_client.greeting, ['220-localhost ESMTP', '220 second line'])
        self.assertEqual(result.versions, [])

    def test_smtp_client(self):
        l7_client, result = self.get_result('smtp', 'smtp.gmail.com', None)
        self.assertEqual(len(l7_client.greeting), 1)
        self.assertRegex(l7_client.greeting[0], '220 smtp.gmail.com')
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(version)
                for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2, TlsVersion.TLS1_3, ]
            ]
        )

    def test_smtps_client_port(self):
        client = L7ClientTlsBase.from_scheme('smtps', 'localhost')
        self.assertEqual(client.port, 465)


class TestClientFTP(TestL7ClientBase):
    @mock.patch.object(ftplib.FTP, '__init__', side_effect=ftplib.error_reply)
    def test_error_ftplib_error(self, _):
        _, result = self.get_result('ftp', 'slackware.org.uk', None)
        self.assertEqual(result.versions, [])

    @mock.patch.object(ftplib.FTP, 'sendcmd', return_value='502 Command not implemented')
    def test_error_unsupported_starttls(self, _):
        _, result = self.get_result('ftp', 'slackware.org.uk', None)
        self.assertEqual(result.versions, [])

    @mock.patch.object(ftplib.FTP, 'connect', return_value='534 Could Not Connect to Server - Policy Requires SSL')
    @mock.patch.object(ftplib.FTP, 'quit', side_effect=ftplib.error_perm)
    def test_error_ftp_error_on_connect(self, _, __):
        _, result = self.get_result('ftp', 'slackware.org.uk', None)
        self.assertEqual(result.versions, [])

    @mock.patch.object(ftplib.FTP, 'quit', side_effect=ftplib.error_reply)
    def test_error_ftp_error_on_quit(self, _):
        _, result = self.get_result('ftp', 'slackware.org.uk', None)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1_2, TlsVersion.TLS1_3]]
        )

    def test_ftp_client(self):
        _, result = self.get_result('ftp', 'slackware.org.uk', None)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1_2, TlsVersion.TLS1_3]]
        )

    def test_ftps_client_port(self):
        client = L7ClientTlsBase.from_scheme('ftps', 'localhost')
        self.assertEqual(client.port, 990)


RDP_NEGOTIATION_RESPONSE_LENGTH = 19


class TestClientRDP(TestL7ClientBase):
    def test_error_send_timeout_error(self):
        with mock.patch.object(L7ClientTlsBase, '_init_connection', side_effect=TimeoutError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('rdp', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(ParsableBase, 'parse_exact_size', side_effect=InvalidType)
    def test_error_parse_invalid_type(self, _):
        _, result = self.get_result('rdp', 'badssl.com', 443)
        self.assertEqual(result.versions, [])

    @mock.patch.object(ParsableBase, 'parse_exact_size', side_effect=InvalidValue('x', int))
    def test_error_parse_invalid_value(self, _):
        _, result = self.get_result('rdp', 'badssl.com', 443)
        self.assertEqual(result.versions, [])

    @mock.patch.object(
        L4ClientTCP, '_receive_bytes',
        return_value=TPKT(
            3, COTPConnectionConfirm(
                src_ref=1, dst_ref=1, user_data=RDPNegotiationResponse([], []).compose()
            ).compose()
        ).compose()
    )
    def test_error_no_ssl_support(self, _):
        _, result = self.get_result('rdp', 'badssl.com', 443)
        self.assertEqual(result.versions, [])


class TestClientLDAP(TestL7ClientBase):
    def test_error_send_timeout_error(self):
        with mock.patch.object(L7ClientTlsBase, '_init_connection', side_effect=TimeoutError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('ldap', 'ldap.uchicago.edu', None)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(LDAPMessageParsableBase, '_parse_asn1', side_effect=InvalidType)
    def test_error_parse_invalid_type(self, _):
        _, result = self.get_result('ldap', 'ldap.uchicago.edu', None)
        self.assertEqual(result.versions, [])

    @mock.patch.object(
        TlsServerMockResponse,
        '_get_mock_responses',
        return_value=(LDAPExtendedResponseStartTLS(LDAPResultCode.AUTH_METHOD_NOT_SUPPORTED).compose(), )
    )
    def test_ldap_header_not_received(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result('ldap', 'localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'\x30\x03\x02\x01\x01', ))
    def test_ldap_no_starttls_support(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(  # pylint: disable = expression-not-assigned
            'ldap', 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )
        self.assertEqual(result.versions, [])

    def test_ldap_client(self):
        _, result = self.get_result('ldap', 'ldap.uchicago.edu', None, L4TransferSocketParams(timeout=10))
        self.assertEqual(result.versions, [
            TlsProtocolVersion(TlsVersion.TLS1),
            TlsProtocolVersion(TlsVersion.TLS1_1),
            TlsProtocolVersion(TlsVersion.TLS1_2),
        ])

    def test_ldaps_client_port(self):
        client = L7ClientTlsBase.from_scheme('ldaps', 'localhost')
        self.assertEqual(client.port, 636)


class TestClientNNTP(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'200 Server ready\r\n',
            b'502 Command unavailable\r\n',
        ]),
    ))
    def test_error_unsupported_capabilities(self, _):
        l7_client, result = self._get_mock_server_response('nntp')
        self.assertEqual(l7_client.greeting, ['200 Server ready'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'200 Server ready\r\n',
            b'101 capability list\r\n',
            b'.\r\n',
        ]),
    ))
    def test_error_unsupported_starttls(self, _):
        l7_client, result = self._get_mock_server_response('nntp')
        self.assertEqual(l7_client.greeting, ['200 Server ready'])
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'200 Server ready\r\n',
            b'101 capability list\r\n',
            b'STARTTLS\r\n',
            b'.\r\n',
            b'502 Command unavailable\r\n',
        ]),
    ))
    def test_error_starttls_error(self, _):
        l7_client, result = self._get_mock_server_response('nntp')
        self.assertEqual(l7_client.greeting, ['200 Server ready'])
        self.assertEqual(result.versions, [])

    def test_default_port(self):
        l7_client = L7ClientTlsBase.from_scheme('nntp', 'localhost')
        self.assertEqual(l7_client.port, 119)

    def test_nntp_client(self):
        _, result = self.get_result('nntps', 'secure-us.news.easynews.com', None)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(tls_version)
                for tls_version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2, TlsVersion.TLS1_3, ]
            ]
        )


class TestClientMySQL(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'X', ))
    def test_error_not_enough_data(self, _):
        _, result = self._get_mock_server_response('mysql')
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'\x21\x00\x00\x00\xff' + 33 * b'\x00',
    ))
    def test_error_invalid_data(self, _):
        _, result = self._get_mock_server_response('mysql')
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b''.join([
            b'\x11\x00\x00',                      # packet_length
            b'\x00',                              # packet_number
            b'\x09',                              # protocol_version
            b'\x00',                              # server_version
            b'\x00\x00\x00\x00',                  # connection_id
            b'\x00\x00\x00\x00\x00\x00\x00\x00',  # auth_plugin_data
            b'\x00',                              # filler
            b'\x00\x00',                          # capabilities
        ]),
    ))
    def test_error_no_ssl_support(self, _):
        _, result = self._get_mock_server_response('mysql')
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(MySQLRecord(0, MySQLHandshakeV10(
        protocol_version=MySQLVersion.MYSQL_9,
        server_version='version',
        connection_id=1,
        auth_plugin_data=b'\x00\x00\x00\x00\x00\x00\x00\x00',
        capabilities=set([]),
        character_set=MySQLCharacterSet.UTF8,
        states=set(),
    ).compose()).compose(),))
    def test_error_client_ssl_no_response(self, _):
        _, result = self._get_mock_server_response('mysql')
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(MySQLRecord(0, MySQLHandshakeV10(
        protocol_version=MySQLVersion.MYSQL_9,
        server_version='version',
        connection_id=1,
        auth_plugin_data=b'\x00\x00\x00\x00\x00\x00\x00\x00',
        capabilities=set([MySQLCapability.CLIENT_SECURE_CONNECTION, ]),
        character_set=MySQLCharacterSet.UTF8,
        states=set(),
    ).compose()).compose(),))
    def test_error_client_secure_connection_no_response(self, _):
        _, result = self._get_mock_server_response('mysql')
        self.assertEqual(result.versions, [])

    def test_default_port(self):
        l7_client = L7ClientTlsBase.from_scheme('mysql', 'localhost')
        self.assertEqual(l7_client.port, 3306)

    def test_mysql_client(self):
        _, result = self.get_result('mysql', 'db4free.net', None, L4TransferSocketParams(timeout=10))
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)


class TestClientPostgreSQL(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'X', ))
    def test_error_starttls_error(self, _):
        _, result = self._get_mock_server_response('postgresql')
        self.assertEqual(result.versions, [])

    def test_default_port(self):
        l7_client = L7ClientTlsBase.from_scheme('postgresql', 'localhost')
        self.assertEqual(l7_client.port, 5432)


class TestClientSieve(TestL7ClientBase):
    def test_error_send_timeout_error(self):
        with mock.patch.object(L7ClientTlsBase, '_init_connection', side_effect=TimeoutError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('sieve', 'ldap.uchicago.edu', None)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(
        TlsServerMockResponse,
        '_get_mock_responses',
        return_value=(b'"STARTTLS"\r\n', b'OK\r\n')
    )
    def test_no_starttls_response(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(  # pylint: disable = expression-not-assigned
            'sieve', 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(
        TlsServerMockResponse,
        '_get_mock_responses',
        return_value=(b'"STARTTLS"\r\n', b'OK\r\n', b'ERROR\r\n')
    )
    def test_starttls_responses_error(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(  # pylint: disable = expression-not-assigned
            'sieve', 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(
        TlsServerMockResponse,
        '_get_mock_responses',
        return_value=('αβγ'.encode('utf-8') + b'\r\n', )
    )
    def test_response_not_ascii(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(  # pylint: disable = expression-not-assigned
            'sieve', 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(
        TlsServerMockResponse,
        '_get_mock_responses',
        return_value=(b'OK', )
    )
    def test_response_no_valid_response(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(  # pylint: disable = expression-not-assigned
            'sieve', 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'OK\r\n', ))
    def test_no_starttls_support(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(  # pylint: disable = expression-not-assigned
            'sieve', 'localhost', threaded_server.l7_server.l4_transfer.bind_port
        )
        self.assertEqual(result.versions, [])

    def test_sieve_client(self):
        _, result = self.get_result('sieve', 'mail.aa.net.uk', None, analyzer=AnalyzerDHParams())
        self.assertEqual(result.dhparam.well_known, DHParamWellKnown.RFC3526_4096_BIT_MODP_GROUP)


class TestClientXMPP(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'<stream:error>', ))
    def test_error_stream_error(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port, L4TransferSocketParams(timeout=0.2)
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>',
    ))
    def test_error_no_features(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port, L4TransferSocketParams(timeout=0.2)
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>',
        b'<stream:features></stream:features>',
    ))
    def test_error_no_tls_feature(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port, L4TransferSocketParams(timeout=0.2)
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>' +
        b'  <stream:features>' +
        b'    <starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"></starttls>' +
        b'  </stream:features>',
        b'<failure xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'
    ))
    def test_error_starttls_error(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port, L4TransferSocketParams(timeout=0.2)
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>' +
        b'  <stream:features>' +
        b'    <starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"></starttls>' +
        b'  </stream:features>',
        b'<stream:error><host-unknown/></stream:error>'
    ))
    def test_error_host_unknown(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port, L4TransferSocketParams(timeout=0.2)
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>' +
        b'  <stream:features>' +
        b'    <starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"></starttls>' +
        b'  </stream:features>',
        b'<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'
    ))
    def test_empty_starttls(self, _):
        _, result = self.get_result('xmppclient', 'xmpp.co', None)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ]
        )

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>' +
        b'  <stream:features>' +
        b'    <starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>' +
        b'  </stream:features>',
        b'<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'
    ))
    def test_empty_starttls_short(self, _):
        _, result = self.get_result('xmppclient', 'xmpp.co', None)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ]
        )

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>' +
        b'  <stream:features>' +
        b'    <starttls xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\'/>' +
        b'  </stream:features>',
        b'<proceed xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\'/>'
    ))
    def test_starttls_apostrophe(self, _):
        _, result = self.get_result('xmppclient', 'xmpp.co', None)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ]
        )

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        b'<stream:stream>' +
        b'  <stream:features>' +
        b'    <starttls xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\' />' +
        b'  </stream:features>',
        b'<proceed xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\' />'
    ))
    def test_starttls_whitespace(self, _):
        _, result = self.get_result('xmppclient', 'xmpp.co', None)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ]
        )

    def test_stream_open_message(self):
        self.assertEqual(
            ClientXMPPClient._get_stream_open_message('address', None),  # pylint: disable=protected-access
            b'<stream:stream xmlns="jabber:client" ' +
            b'xmlns:stream="http://etherx.jabber.org/streams" ' +
            b'xmlns:tls="http://www.ietf.org/rfc/rfc2595.txt" ' +
            b'to="address" ' +
            b'xml:lang="en" ' +
            b'version="1.0">'
        )

        self.assertEqual(
            ClientXMPPServer._get_stream_open_message('address', 'stream_to'),  # pylint: disable=protected-access
            b'<stream:stream xmlns="jabber:server" ' +
            b'xmlns:stream="http://etherx.jabber.org/streams" ' +
            b'xmlns:tls="http://www.ietf.org/rfc/rfc2595.txt" ' +
            b'to="stream_to" ' +
            b'xml:lang="en" ' +
            b'version="1.0">'
        )

    def test_xmpp_client(self):
        _, result = self.get_result('xmppclient', 'xmpp.co', None)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ]
        )

        analyzer = AnalyzerVersions()
        handler = ProtocolHandlerBase.from_protocol('tls')
        result = handler.analyze(analyzer, urllib3.util.parse_url('xmppclient://xmpp.co/?stream_to=xmpp.co'))
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ]
        )


class TestClientDoH(TestL7ClientBase):
    def test_doh_client(self):
        _, result = self.get_result('doh', 'dns.google', None)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1_2, TlsVersion.TLS1_3, ]]
        )


class TestClientOpenVpn(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
       OpenVpnPacketWrapperTcp(OpenVpnPacketHardResetServerV2(
            session_id=1, packet_id_array=[0x58585858], remote_session_id=0xffffffffffffffff, packet_id=0,
       ).compose()).compose(),
    ))
    def test_error_invalid_session_id_tcp(self, _):
        l7_client, result = self._get_mock_server_response('openvpntcp')
        self.assertEqual(l7_client.buffer, b'')
        self.assertTrue(l7_client.buffer_is_plain_text)
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
       OpenVpnPacketHardResetServerV2(
            session_id=1, packet_id_array=[0x58585858], remote_session_id=0xffffffffffffffff, packet_id=0,
       ).compose(),
    ))
    def test_error_invalid_session_id_udp(self, _):
        l7_client, result = self._get_mock_server_response('openvpn')
        self.assertEqual(l7_client.buffer, b'')
        self.assertTrue(l7_client.buffer_is_plain_text)
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'', ))
    def test_error_no_response_to_client_hard_reset_tcp(self, _):
        l7_client, result = self._get_mock_server_response('openvpntcp')
        self.assertEqual(l7_client.buffer, b'')
        self.assertTrue(l7_client.buffer_is_plain_text)
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'', ))
    def test_error_no_response_to_client_hard_reset_udp(self, _):
        l7_client, result = self._get_mock_server_response('openvpn')
        self.assertEqual(l7_client.buffer, b'')
        self.assertTrue(l7_client.buffer_is_plain_text)
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(
        OpenVpnPacketWrapperTcp(OpenVpnPacketHardResetServerV2(0, 0xff58585858585858 + 1, [0], 1).compose()).compose() +
        OpenVpnPacketWrapperTcp(
            b'\xff' + OpenVpnPacketHardResetServerV2(0, 0xff58585858585858 + 1, [0], 1).compose()[1:]
        ).compose(),
    ))
    def test_error_invalid_response_to_in_hard_reset_tcp(self, _):
        l7_client, result = self._get_mock_server_response('openvpntcp')
        self.assertEqual(l7_client.buffer, b'')
        self.assertTrue(l7_client.buffer_is_plain_text)
        self.assertEqual(result.versions, [])

    @mock.patch.object(L7TransferBase, 'receive', side_effect=NotEnoughData)
    @mock.patch.object(L4TransferBase, 'buffer', mock.PropertyMock(return_value=b'\x00'))
    def test_error_no_response(self, _):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 443)
        l7_client.session_id = 0xfffffffffffffffe
        with self.assertRaises(NetworkError) as context_manager:
            l7_client.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(
        L4ClientUDP, '_receive_bytes',
        return_value=OpenVpnPacketHardResetServerV2(1, 0xffffffffffffffff, [0], 1).compose()
    )
    @mock.patch.object(
        L4ClientTCP, 'send', return_value=None
    )
    def test_error_not_enough_packet_byte_udp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 443)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    @mock.patch.object(
        L4ClientTCP, '_receive_bytes',
        return_value=OpenVpnPacketWrapperTcp(
            OpenVpnPacketHardResetServerV2(1, 0xffffffffffffffff, [0], 1).compose()
        ).compose()
    )
    @mock.patch.object(
        L4ClientTCP, 'send', return_value=None
    )
    def test_error_not_enough_packet_byte_tcp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'badssl.com', 443)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    @mock.patch.object(ClientOpenVpnBase, '_reset_session', return_value=None)
    @mock.patch.object(
        ClientOpenVpnBase, '_receive_packets',
        return_value=[OpenVpnPacketHardResetClientV2(0xffffffffffffffff, 1), ]
    )
    def test_error_invalid_op_code_udp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 443)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(InvalidType):
            l7_client.receive(1)
        l7_client.l4_transfer.close()

    @mock.patch.object(ClientOpenVpnBase, '_reset_session', return_value=None)
    @mock.patch.object(
        ClientOpenVpnBase, '_receive_packets',
        return_value=[OpenVpnPacketHardResetClientV2(0xffffffffffffffff, 1), ]
    )
    def test_error_invalid_op_code_tcp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'badssl.com', 443)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(InvalidType):
            l7_client.receive(1)
        l7_client.l4_transfer.close()

    @mock.patch.object(
        L4ClientTCP, '_receive_bytes',
        return_value=OpenVpnPacketWrapperTcp(
            OpenVpnPacketHardResetServerV2(1, 0xffffffffffffffff, [0], 1).compose()
        ).compose()
    )
    @mock.patch.object(
        L4ClientTCP, 'send', return_value=None
    )
    def test_error_receive_unexpected_server_reset_tcp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'badssl.com', 443)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    def test_openvpn_tcp_client(self):
        _, result = self.get_result(
            'openvpntcp', 'gr1.vpnjantit.com', 992,
            L4TransferSocketParams(timeout=10), analyzer=AnalyzerDHParams()
        )
        self.assertEqual(result.dhparam.well_known, DHParamWellKnown.RFC2539_1024_BIT_MODP_GROUP)

        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'localhost')
        self.assertEqual(l7_client.port, L7ClientHTTPS.get_default_port())

    @mock.patch.object(
        L4ClientUDP, '_receive_bytes',
        return_value=OpenVpnPacketHardResetServerV2(1, 0xffffffffffffffff, [0], 1).compose()
    )
    @mock.patch.object(
        L4ClientUDP, 'send', return_value=None
    )
    def test_error_receive_unexpected_server_reset_udp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 1194)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    def test_openvpn_udp_client(self):
        _, result = self.get_result(
            'openvpn', 'gr1.vpnjantit.com', 1194,
            L4TransferSocketParams(timeout=10), analyzer=AnalyzerDHParams()
        )
        self.assertEqual(result.dhparam.well_known, DHParamWellKnown.RFC2539_1024_BIT_MODP_GROUP)

        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'localhost')
        self.assertEqual(l7_client.port, 1194)


class TestTlsClientHandshake(TestL7ClientBase):
    def test_error_connection_closed_during_the_handshake(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsCloseDuringHandshake('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()

        l7_client = L7ClientTlsBase.from_scheme('tls', 'localhost', threaded_server.l7_server.l4_transfer.bind_port)

        client_hello = TlsHandshakeClientHelloAnyAlgorithm([TlsProtocolVersion(TlsVersion.TLS1_2), ], 'localhost')

        with self.assertRaises(NetworkError) as context_manager:
            l7_client.do_tls_handshake(client_hello)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_error_always_alert_wargning(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTls(
                'localhost', 0,
                L4TransferSocketParams(timeout=0.2), configuration=TlsServerConfiguration(protocol_versions=[])
            ),
        )
        threaded_server.start()

        _, result = self.get_result('https', 'localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.versions, [])

    @mock.patch.object(
        TlsRecord, 'parse_immutable', return_value=(
            TlsRecord(
                TlsChangeCipherSpecMessage().compose(),
                content_type=TlsContentType.CHANGE_CIPHER_SPEC,
            ),
            1,
        )
    )
    def test_error_non_handshake_message(self, _):
        with self.assertRaises(TlsAlert) as context_manager:
            self.get_result('https', 'badssl.com', None, L4TransferSocketParams(timeout=10))
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)

    @mock.patch.object(L7ServerTlsBase, '_get_handshake_class', return_value=L7ServerTlsFatalResponse)
    def test_error_fatal_alert(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.wait_for_server_listen()
        l7_client = L7ClientTlsBase.from_scheme('tls', 'localhost', threaded_server.l7_server.l4_transfer.bind_port)

        client_hello = TlsHandshakeClientHelloAnyAlgorithm([TlsProtocolVersion(TlsVersion.TLS1_2), ], 'localhost')
        with self.assertRaises(NetworkError) as context_manager:
            l7_client.do_tls_handshake(client_hello)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

    @mock.patch.object(L7ServerTlsBase, '_get_handshake_class', return_value=L7ServerSslPlainTextResponse)
    def test_error_plain_text_response(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()
        l7_client = L7ClientTls('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        client_hello = SslHandshakeClientHelloAnyAlgorithm()
        with self.assertRaises(SecurityError) as context_manager:
            l7_client.do_ssl_handshake(client_hello)
        self.assertEqual(context_manager.exception.error, SecurityErrorType.UNPARSABLE_MESSAGE)

    def test_one_message_in_multiple_records(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsOneMessageInMultipleRecords('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()

        l7_client = L7ClientTlsBase.from_scheme('tls', 'localhost', threaded_server.l7_server.l4_transfer.bind_port)

        client_hello = TlsHandshakeClientHelloAnyAlgorithm([TlsProtocolVersion(TlsVersion.TLS1_2), ], 'localhost')

        self.assertEqual(
            l7_client.do_tls_handshake(client_hello),
            {TlsHandshakeType.SERVER_HELLO: TlsServerOneMessageInMultipleRecords.SERVER_HELLO_MESSAGE}
        )


class TestSslClientHandshake(unittest.TestCase):
    @mock.patch.object(
        SslRecord, 'parse_exact_size', return_value=SslRecord(SslErrorMessage(SslErrorType.NO_CIPHER_ERROR))
    )
    def test_error_ssl_error_replied(self, _):
        with self.assertRaises(SslError) as context_manager:
            L7ClientTls('badssl.com', 443).do_ssl_handshake(SslHandshakeClientHello(list(SslCipherKind)))
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CIPHER_ERROR)

    @mock.patch.object(L4ClientTCP, 'receive', side_effect=NotEnoughData(100))
    @mock.patch.object(
        L4ClientTCP, 'buffer',
        mock.PropertyMock(side_effect=[
            b'',
            True,
            b'some text content',
            b'some text content',
            b'some text content'
        ])
    )
    def test_error_unparsable_response(self, _):
        with self.assertRaises(SecurityError) as context_manager:
            L7ClientTls('badssl.com', 443).do_ssl_handshake(SslHandshakeClientHello(list(SslCipherKind)))
        self.assertEqual(context_manager.exception.error, SecurityErrorType.PLAIN_TEXT_MESSAGE)

    @mock.patch.object(L4ClientTCP, 'receive', side_effect=NotEnoughData(100))
    @mock.patch.object(
        L4ClientTCP, 'buffer',
        mock.PropertyMock(side_effect=[
            TlsRecord(
                TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY).compose(),
                content_type=TlsContentType.ALERT,
            ).compose() +
            TlsRecord(
                TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE).compose(),
                content_type=TlsContentType.ALERT,
            ).compose(),
            True,
            b'some text content',
            b'some text content',
            b'some text content'
        ])
    )
    def test_error_multiple_record_resonse(self, _):
        with self.assertRaises(SecurityError) as context_manager:
            L7ClientTls('badssl.com', 443).do_ssl_handshake(SslHandshakeClientHello(list(SslCipherKind)))
        self.assertEqual(context_manager.exception.error, SecurityErrorType.PLAIN_TEXT_MESSAGE)

    @mock.patch.object(L4ClientTCP, 'receive', side_effect=NotEnoughData(100))
    @mock.patch.object(
        L4ClientTCP, 'buffer',
        mock.PropertyMock(side_effect=[
            b'',
            True,
            TlsRecord(
                TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE).compose(),
                content_type=TlsContentType.ALERT
            ).compose()
        ])
    )
    def test_error_unacceptable_tls_error_replied(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            L7ClientTls('badssl.com', 443).do_ssl_handshake(SslHandshakeClientHello(list(SslCipherKind)))
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(L4ClientTCP, 'receive', return_value=b'')
    @mock.patch.object(
        SslRecord, 'parse_exact_size', side_effect=[
            SslRecord(SslHandshakeServerHello(b'', SslCipherKind)),
            SslRecord(SslErrorMessage(SslErrorType.NO_CERTIFICATE_ERROR)),
        ]
    )
    def test_multiple_messages(self, _, __):
        with self.assertRaises(SslError) as context_manager:
            L7ClientTls('badssl.com', 443).do_ssl_handshake(
                SslHandshakeClientHello(list(SslCipherKind)),
                SslMessageType.ERROR
            )
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CERTIFICATE_ERROR)
