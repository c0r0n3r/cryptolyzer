# SPDX-License-Identifier: MPL-2.0
# pylint: disable=too-many-lines

import ftplib
import poplib
import smtplib
import ssl
import sys
import unittest
from unittest import mock

from test.common.classes import OFFLINE_PARTIAL_RESPONSE_L4_SOCKET_PARAMS, OFFLINE_L4_SOCKET_PARAMS

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionType, TlsNamedCurve
from cryptoparser.tls.ldap import LDAPExtendedRequestStartTLS
from cryptoparser.tls.openvpn import OpenVpnPacketControlV1, OpenVpnPacketHardResetServerV2
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion
from cryptoparser.tls.record import SslRecord, TlsRecord
from cryptoparser.tls.mysql import MySQLRecord, MySQLHandshakeSslRequest
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
    TlsClientCertificateType,
    TlsContentType,
    TlsExtensionsClient,
    TlsHandshakeType,
    TlsHandshakeServerHello,
    TlsSessionIdVector,
)

from cryptodatahub.tls.algorithm import TlsNextProtocolName, TlsProtocolName, TlsSignatureAndHashAlgorithm

from cryptolyzer.common.dhparam import DHParamWellKnown, parse_tls_dh_params, parse_ecdh_params
from cryptolyzer.common.transfer import L4ClientTCP, L4ClientUDP
from cryptolyzer.tls.client import (
    ClientFTP,
    ClientIMAP,
    ClientLDAP,
    ClientLMTP,
    ClientMySQL,
    ClientNNTP,
    ClientOpenVpn,
    ClientOpenVpnTcp,
    ClientPOP3,
    ClientPostgreSQL,
    ClientRDP,
    ClientSieve,
    ClientSMTP,
    L7ClientTls,
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsAlert,
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloKeyExchangeDHE,
    TlsHandshakeClientHelloKeyExchangeECDHx,
)
from cryptolyzer.tls.server import (
    L7ServerTls,
    L7ServerTlsBase,
    L7ServerTlsFTP,
    L7ServerTlsIMAP,
    L7ServerTlsLDAP,
    L7ServerTlsLMTP,
    L7ServerTlsMySQL,
    L7ServerTlsNNTP,
    L7ServerTlsOpenVpn,
    L7ServerTlsOpenVpnTcp,
    L7ServerTlsPOP3,
    L7ServerTlsPostgreSQL,
    L7ServerTlsRDP,
    L7ServerTlsSieve,
    L7ServerTlsSMTP,
    L7ServerTlsXMPP,
    TlsServerConfiguration,
    TlsServerHandshake,
)

from .classes import L7ServerTlsTest, L7ServerStartTlsTest


class TestL7ServerBase(unittest.TestCase):
    def setUp(self):
        self.threaded_server = None
        if sys.version_info.major == 3 and sys.version_info.minor == 4 and sys.implementation == 'cpython':
            self.ssl_exception_reason = 'WRONG_SSL_VERSION'
        else:
            self.ssl_exception_reason = 'SSLV3_ALERT_HANDSHAKE_FAILURE'

    @staticmethod
    def create_server(configuration=None, l7_server_class=L7ServerTls):
        threaded_server = L7ServerTlsTest(l7_server_class(
            'localhost', 0, OFFLINE_L4_SOCKET_PARAMS, configuration=configuration
        ))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @staticmethod
    def create_client(client_class, l7_server):
        return client_class(
            l7_server.address,
            l7_server.l4_transfer.bind_port,
            OFFLINE_PARTIAL_RESPONSE_L4_SOCKET_PARAMS,
            ip=l7_server.l4_transfer.bind_address,
        )

    def _assert_on_more_data(self, client):
        buffer_length = len(client.buffer)
        try:
            client.receive(1)
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

        self.threaded_server.stop()

    def _test_tls_handshake(
        self,
        protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
        last_handshake_message_type=TlsHandshakeType.SERVER_HELLO,
        l7_client_class=L7ClientTls
    ):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([protocol_version, ], self.threaded_server.l7_server.address)
        l7_client = self.create_client(l7_client_class, self.threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=last_handshake_message_type
        )
        self.assertEqual(list(server_messages.keys()), [last_handshake_message_type])

        self.threaded_server.stop()


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
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
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
            TlsProtocolVersion(TlsVersion.TLS1),
            TlsContentType.ALERT,
        ).compose()
    )
    def test_error_alert_in_request(self, _):
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        hello_message = TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)
        with self.assertRaises(TlsAlert) as context_manager:
            l7_client.do_tls_handshake(hello_message=hello_message)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.CLOSE_NOTIFY)

    @mock.patch.object(L7ServerTlsBase, 'send', side_effect=ConnectionResetError)
    def test_error_connection_closed_during_handshake(self, _):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        client_hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1_2), ], self.threaded_server.l7_server.address
        )
        l4_client.send(TlsRecord(client_hello.compose()).compose())
        self._assert_on_more_data(l4_client)
        l4_client.close()

    @mock.patch.object(TlsServerHandshake, '_handle_error', side_effect=BrokenPipeError)
    def test_error_connection_closed_before_close_notify(self, _):
        self._test_tls_handshake(TlsProtocolVersion(TlsVersion.TLS1_2))

    def test_default_port(self):
        self.assertEqual(L7ServerTls.get_default_port(), 4433)

    def test_scheme(self):
        self.assertEqual(L7ServerTls.get_scheme(), 'tls')

    def test_handshake(self):
        self._test_tls_handshake(TlsProtocolVersion(TlsVersion.TLS1_2))


class TestL7ServerTlsConfiguration(unittest.TestCase):
    def test_error_min_version_greater_than_max_version(self):
        with self.assertRaises(ValueError):
            TlsServerConfiguration(
                min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
                max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            )

    def test_error_cipher_suite_max_version_below_min_version(self):
        with self.assertRaises(ValueError):
            TlsServerConfiguration(
                min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
            )

    def test_error_cipher_suite_min_version_above_max_version(self):
        with self.assertRaises(ValueError):
            TlsServerConfiguration(
                min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
                max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
                cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256],
            )

    def test_error_dh_param_without_dhe_cipher_suite(self):
        with self.assertRaises(ValueError):
            TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
                dh_param=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
            )

    def test_error_curves_without_ecdhe_cipher_suite(self):
        with self.assertRaises(ValueError):
            TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
                curves=[TlsNamedCurve.SECP256R1],
            )

    def test_error_certificate_authorities_without_certificate(self):
        with self.assertRaises(ValueError):
            TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
                certificate_authorities=[b'fake distinguished name'],
            )


class TestL7ServerTlsCertificate(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
            certificates=[b'fake certificate'],
        ))

    def test_handshake_certificate_and_server_hello_done(self):
        protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        client_hello = TlsHandshakeClientHelloAnyAlgorithm(
            [protocol_version], self.threaded_server.l7_server.address
        )
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE,
        )
        self.assertIn(TlsHandshakeType.CERTIFICATE, server_messages)
        self.assertIn(TlsHandshakeType.SERVER_HELLO_DONE, server_messages)
        certificate_chain = list(server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain)
        self.assertEqual(len(certificate_chain), 1)
        self.assertEqual(certificate_chain[0].certificate, b'fake certificate')
        self.threaded_server.stop()


class TestL7ServerTlsCertificateRequest(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
            certificates=[b'fake certificate'],
            certificate_authorities=[b'fake distinguished name'],
        ))

    def _test_handshake_certificate_request(self, protocol_version):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm(
            [protocol_version], self.threaded_server.l7_server.address
        )
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE,
        )
        self.assertIn(TlsHandshakeType.CERTIFICATE_REQUEST, server_messages)
        self.assertIn(TlsHandshakeType.SERVER_HELLO_DONE, server_messages)
        certificate_request = server_messages[TlsHandshakeType.CERTIFICATE_REQUEST]
        self.assertEqual(
            list(certificate_request.certificate_types),
            [
                TlsClientCertificateType.RSA_SIGN,
                TlsClientCertificateType.DSS_SIGN,
                TlsClientCertificateType.ECDSA_SIGN,
            ]
        )
        self.assertEqual(
            [
                bytes(bytearray(certificate_authority))
                for certificate_authority in certificate_request.certificate_authorities
            ],
            [b'fake distinguished name']
        )
        self.threaded_server.stop()
        return certificate_request

    def test_handshake_certificate_request(self):
        certificate_request = self._test_handshake_certificate_request(TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(
            list(certificate_request.supported_signature_algorithms),
            list(TlsSignatureAndHashAlgorithm)
        )

    def test_handshake_certificate_request_without_signature_algorithms(self):
        certificate_request = self._test_handshake_certificate_request(TlsProtocolVersion(TlsVersion.TLS1_1))
        self.assertEqual(certificate_request.supported_signature_algorithms, None)


class TestL7ServerTlsDHE(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA],
            dh_param=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
        ))

    def test_handshake_server_key_exchange(self):
        protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        client_hello = TlsHandshakeClientHelloKeyExchangeDHE(
            protocol_version, self.threaded_server.l7_server.address
        )
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE,
        )
        self.assertIn(TlsHandshakeType.SERVER_KEY_EXCHANGE, server_messages)
        dh_public_key = parse_tls_dh_params(
            server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE].param_bytes
        )
        self.assertEqual(
            dh_public_key.public_numbers.parameter_numbers.p,
            DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP.value.parameter_numbers.p,
        )
        self.threaded_server.stop()


class TestL7ServerTlsECDHE(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA],
            curves=[TlsNamedCurve.SECP256R1],
        ))

    def test_handshake_server_key_exchange(self):
        protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(
            protocol_version, self.threaded_server.l7_server.address
        )
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE,
        )
        self.assertIn(TlsHandshakeType.SERVER_KEY_EXCHANGE, server_messages)
        named_curve, _ = parse_ecdh_params(
            server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE].param_bytes
        )
        self.assertEqual(named_curve, TlsNamedCurve.SECP256R1)
        self.threaded_server.stop()

    def test_handshake_no_supported_groups_extension(self):
        protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(
            protocol_version, self.threaded_server.l7_server.address,
            named_curves=[],
        )
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE,
        )
        self.assertNotIn(TlsHandshakeType.SERVER_KEY_EXCHANGE, server_messages)
        self.assertIn(TlsHandshakeType.SERVER_HELLO_DONE, server_messages)
        self.threaded_server.stop()

    def test_handshake_no_matching_curve(self):
        protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(
            protocol_version, self.threaded_server.l7_server.address,
            named_curves=[TlsNamedCurve.X25519],
        )
        l7_client = self.create_client(L7ClientTls, self.threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE,
        )
        self.assertNotIn(TlsHandshakeType.SERVER_KEY_EXCHANGE, server_messages)
        self.assertIn(TlsHandshakeType.SERVER_HELLO_DONE, server_messages)
        self.threaded_server.stop()


class TestL7ServerTls13(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256]
        ))

    def test_handshake(self):
        self._test_tls_handshake(TlsProtocolVersion(TlsVersion.TLS1_3))


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
        self._test_tls_handshake(TlsProtocolVersion(TlsVersion.TLS1_2))


class TestL7ServerTlsCloseOnError(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(TlsServerConfiguration(close_on_error=True))

    def test_tls_handshake(self):
        self._test_tls_handshake(TlsProtocolVersion(TlsVersion.TLS1_2))


class TestL7ServerTlsExtensions(TestL7ServerBase):
    def _get_server_hello(self, configuration):
        threaded_server = self.create_server(configuration)
        client_hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1_2)], threaded_server.l7_server.address
        )
        l7_client = self.create_client(L7ClientTls, threaded_server.l7_server)
        l7_client.init_connection()
        server_messages = l7_client.do_tls_handshake(
            hello_message=client_hello,
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO,
        )
        threaded_server.stop()
        return server_messages[TlsHandshakeType.SERVER_HELLO]

    def test_handshake_encrypt_then_mac(self):
        server_hello = self._get_server_hello(TlsServerConfiguration(encrypt_then_mac_supported=True))
        extension = server_hello.extensions.get_item_by_type(TlsExtensionType.ENCRYPT_THEN_MAC)
        self.assertEqual(extension.extension_type, TlsExtensionType.ENCRYPT_THEN_MAC)

    def test_handshake_extended_master_secret(self):
        server_hello = self._get_server_hello(TlsServerConfiguration(extended_master_secret_supported=True))
        extension = server_hello.extensions.get_item_by_type(TlsExtensionType.EXTENDED_MASTER_SECRET)
        self.assertEqual(extension.extension_type, TlsExtensionType.EXTENDED_MASTER_SECRET)

    def test_handshake_renegotiation_info(self):
        server_hello = self._get_server_hello(TlsServerConfiguration(renegotiation_supported=True))
        extension = server_hello.extensions.get_item_by_type(TlsExtensionType.RENEGOTIATION_INFO)
        self.assertEqual(extension.extension_type, TlsExtensionType.RENEGOTIATION_INFO)

    def test_handshake_session_cache(self):
        server_hello = self._get_server_hello(TlsServerConfiguration(session_cache_supported=True))
        self.assertNotEqual(server_hello.session_id, TlsSessionIdVector(()))

    def test_handshake_session_ticket(self):
        server_hello = self._get_server_hello(TlsServerConfiguration(session_ticket_supported=True))
        extension = server_hello.extensions.get_item_by_type(TlsExtensionType.SESSION_TICKET)
        self.assertEqual(extension.extension_type, TlsExtensionType.SESSION_TICKET)

    def test_handshake_next_protocols(self):
        server_hello = self._get_server_hello(TlsServerConfiguration(
            next_protocols=[TlsNextProtocolName.HTTP_1_1],
        ))
        extension = server_hello.extensions.get_item_by_type(TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION)
        self.assertEqual(list(extension.protocol_names), [TlsNextProtocolName.HTTP_1_1])

    def test_handshake_application_layer_protocols(self):
        server_hello = self._get_server_hello(TlsServerConfiguration(
            application_layer_protocols=[TlsProtocolName.HTTP_1_1],
        ))
        extension = server_hello.extensions.get_item_by_type(TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        self.assertEqual(list(extension.protocol_names), [TlsProtocolName.HTTP_1_1])


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

    def test_scheme(self):
        self.assertEqual(ClientRDP.get_scheme(), L7ServerTlsRDP.get_scheme())

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


class TestL7ServerTlsMySQL(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsMySQL)

    def _read_initial_handshake_from_server(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()

        l4_client.receive(MySQLRecord.HEADER_SIZE)
        try:
            MySQLRecord.parse_immutable(l4_client.buffer)
        except NotEnoughData as e:
            l4_client.receive(e.bytes_needed)

        return l4_client

    def test_error_invlaid_tls_request(self):
        l4_client = self._read_initial_handshake_from_server()
        l4_client.send(SslRequest.MESSAGE_SIZE * b'\x00')
        self._assert_on_more_data(l4_client)

        l4_client.close()

    def test_error_missing_ssl_capability(self):
        l4_client = self._read_initial_handshake_from_server()
        l4_client.send(MySQLRecord(0, MySQLHandshakeSslRequest(set(), 1).compose()).compose())
        self._assert_on_more_data(l4_client)

        l4_client.close()

    def test_default_port(self):
        self.assertEqual(ClientMySQL.get_default_port(), L7ServerTlsMySQL.get_default_port())

    def test_scheme(self):
        self.assertEqual(ClientMySQL.get_scheme(), L7ServerTlsMySQL.get_scheme())

    def test_tls_handshake(self):
        self._test_tls_handshake(l7_client_class=ClientMySQL)


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
        super().setUp()

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
        super().setUp()

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

    def test_real_with_capabilities_stls(self):
        client = poplib.POP3(
            host=str(self.threaded_server.l7_server.address),
            port=self.threaded_server.l7_server.l4_transfer.bind_port
        )
        with self.assertRaises(ssl.SSLError) as context_manager:
            client.stls()

        self.assertEqual(context_manager.exception.reason, self.ssl_exception_reason)


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
        super().setUp()

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


class TestL7ServerTlsOpenVpn(TestL7ServerBase):
    def test_default_port(self):
        self.assertEqual(ClientOpenVpn.get_default_port(), L7ServerTlsOpenVpn.get_default_port())

    def test_scheme(self):
        self.assertEqual(ClientOpenVpn.get_scheme(), L7ServerTlsOpenVpn.get_scheme())

    def test_error_missing_hard_reset_client(self):
        threaded_server = self.create_server(l7_server_class=L7ServerTlsOpenVpn)
        threaded_server.l7_server.max_handshake_count = 1

        l4_client = self.create_client(L4ClientUDP, threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.send(OpenVpnPacketHardResetServerV2(1, 2, [], 0).compose())
        self._assert_on_more_data(l4_client)
        l4_client.close()

        threaded_server.stop()

    def test_error_plain_text_data(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsOpenVpn)
        self.threaded_server.l7_server.max_handshake_count = 1

        l7_client = self.create_client(ClientOpenVpn, self.threaded_server.l7_server)
        l7_client.init_connection()

        l7_client.l4_transfer.send(OpenVpnPacketControlV1(
            l7_client.session_id, [], l7_client.remote_session_id, l7_client.client_packet_id + 1, b'plain text data'
        ).compose())

        expected_error_message_bytes = TlsRecord(
            TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR).compose(),
            content_type=TlsContentType.ALERT,
        ).compose()

        l7_client.receive(len(expected_error_message_bytes))
        self.assertEqual(l7_client.buffer, expected_error_message_bytes)

        l7_client.l4_transfer.close()
        self.threaded_server.stop()

    def test_tls_handshake(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsOpenVpn)
        self.threaded_server.l7_server.max_handshake_count = 1

        l7_client = self.create_client(ClientOpenVpn, self.threaded_server.l7_server)
        self.assertEqual(l7_client.buffer, b'')
        l7_client.init_connection()

        self.assertEqual(l7_client.buffer, b'')

        l7_client.send(
            TlsRecord(TlsHandshakeServerHello(
                protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
                cipher_suite=TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                extensions=TlsExtensionsClient([]),
            ).compose()).compose()
        )

        expected_error_message_bytes = TlsRecord(
            TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE).compose(),
            content_type=TlsContentType.ALERT,
        ).compose()
        l7_client.receive(len(expected_error_message_bytes))
        self.assertEqual(l7_client.buffer, expected_error_message_bytes)

        l7_client.l4_transfer.close()
        self.threaded_server.stop()


class TestL7ServerTlsOpenVpnTcp(TestL7ServerBase):
    def test_default_port(self):
        self.assertEqual(ClientOpenVpnTcp.get_default_port(), L7ServerTlsOpenVpnTcp.get_default_port())

    def test_scheme(self):
        self.assertEqual(ClientOpenVpnTcp.get_scheme(), L7ServerTlsOpenVpnTcp.get_scheme())

    def test_error_plain_text_data(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsOpenVpn)
        self.threaded_server.l7_server.max_handshake_count = 1

        l7_client = self.create_client(ClientOpenVpn, self.threaded_server.l7_server)
        l7_client.init_connection()

        l7_client.l4_transfer.send(OpenVpnPacketControlV1(
            l7_client.session_id, [], l7_client.remote_session_id, l7_client.client_packet_id + 1, b'plain text data'
        ).compose())

        expected_error_message_bytes = TlsRecord(
            TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR).compose(),
            content_type=TlsContentType.ALERT,
        ).compose()

        l7_client.receive(len(expected_error_message_bytes))
        self.assertEqual(l7_client.buffer, expected_error_message_bytes)

        l7_client.l4_transfer.close()
        self.threaded_server.stop()

    def test_tls_handshake(self):
        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsOpenVpnTcp)
        self.threaded_server.l7_server.max_handshake_count = 1

        l7_client = self.create_client(ClientOpenVpnTcp, self.threaded_server.l7_server)
        self.assertEqual(l7_client.buffer, b'')
        l7_client.init_connection()

        self.assertEqual(l7_client.buffer, b'')

        l7_client.send(
            TlsRecord(TlsHandshakeServerHello(
                protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
                cipher_suite=TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                extensions=TlsExtensionsClient([]),
            ).compose()).compose()
        )

        expected_error_message_bytes = TlsRecord(
            TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE).compose(),
            content_type=TlsContentType.ALERT,
        ).compose()
        l7_client.receive(len(expected_error_message_bytes))
        self.assertEqual(l7_client.buffer, expected_error_message_bytes)

        l7_client.l4_transfer.close()
        self.threaded_server.stop()


class TestL7ServerTlsIMAP(TestL7ServerBase):
    def setUp(self):
        super().setUp()

        self.threaded_server = self.create_server(l7_server_class=L7ServerTlsIMAP)

    def test_default_port(self):
        self.assertEqual(ClientIMAP.get_default_port(), L7ServerTlsIMAP.get_default_port())

    def test_scheme(self):
        self.assertEqual(ClientIMAP.get_scheme(), L7ServerTlsIMAP.get_scheme())

    def test_error_no_capability_command(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.receive_until(b'\n')  # read greeting
        l4_client.flush_buffer()
        l4_client.send(b'A001 LOGIN user pass\r\n')
        self._assert_on_more_data(l4_client)
        l4_client.close()

    def test_error_no_starttls_command(self):
        l4_client = self.create_client(L4ClientTCP, self.threaded_server.l7_server)
        l4_client.init_connection()
        l4_client.receive_until(b'\n')  # read greeting
        l4_client.flush_buffer()
        l4_client.send(b'A001 CAPABILITY\r\n')
        l4_client.receive_until(b'completed\r\n')  # read capability response
        l4_client.flush_buffer()
        l4_client.send(b'A002 LOGIN user pass\r\n')
        self._assert_on_more_data(l4_client)
        l4_client.close()


class TestL7ServerTlsXMPP(unittest.TestCase):
    def test_scheme(self):
        self.assertEqual(L7ServerTlsXMPP.get_scheme(), 'xmpp')
