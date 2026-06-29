# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import ftplib
import logging
import socket
import unittest
from unittest import mock

from test.common.classes import BADSSL_COM_L4_SOCKET_PARAMS, TestLoggerBase
from test.common.markers import live_server

import urllib3


from cryptodatahub.common.algorithm import Authentication
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.tls.ciphersuite import SslCipherKind, TlsCipherSuite
from cryptoparser.tls.extension import (
    TlsExtensionKeyShareClient,
    TlsExtensionKeyShareServer,
    TlsExtensionSignatureAlgorithms,
    TlsExtensionSignatureAlgorithmsCert,
    TlsKeyShareEntry,
    TlsNamedCurve,
)
from cryptoparser.tls.ldap import LDAPMessageParsableBase, LDAPExtendedResponseStartTLS, LDAPResultCode
from cryptoparser.tls.mysql import MySQLCapability, MySQLRecord, MySQLCharacterSet, MySQLHandshakeV10, MySQLVersion
from cryptoparser.tls.openvpn import (
    OpenVpnPacketHardResetClientV2,
    OpenVpnPacketHardResetServerV2,
    OpenVpnPacketWrapperTcp,
)
from cryptoparser.tls.rdp import COTPConnectionConfirm, TPKT, RDPNegotiationResponse
from cryptoparser.tls.record import ParsableBase, TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import (
    SslErrorMessage,
    SslErrorType,
    SslHandshakeClientHello,
    SslHandshakeServerHello,
    SslMessageType,
    TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM,
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
    ClientOpenVpnBase,
    ClientPOP3,
    ClientRDP,
    ClientXMPPClient,
    ClientXMPPServer,
    L7ClientHTTPS,
    L7ClientTls,
    L7ClientTlsBase,
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsAlert,
    TlsClientHandshake,
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationSM2,
    TlsHandshakeClientHelloKeyExchangeECDHx,
    TlsHandshakeClientHelloBlockCipherModeCBC,
    TlsHandshakeClientHelloSpecalization,
    TlsHandshakeClientHelloBulkCipherBlockSize64,
    TlsHandshakeClientHelloBulkCipherNull,
    TlsHandshakeClientHelloKeyExchangeAnonymousDH,
    TlsHandshakeClientHelloStreamCipherRC4,
    key_share_entry_from_named_curve,
)
from cryptolyzer.tls.crypto import (
    Tls13HandshakeDecryptor,
    _EphemeralKeyExchangeBackendCryptodome,
    dhe_ephemeral_material_backend,
)
from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.exception import (
    NetworkError,
    NetworkErrorType,
    SecurityError,
    SecurityErrorType
)
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.tls.server import (
    L7ServerTls,
    L7ServerTlsBase,
    L7ServerTlsFTP,
    L7ServerTlsIMAP,
    L7ServerTlsIMAPBase,
    L7ServerTlsIMAPEarlyClose,
    L7ServerTlsIMAPInvalidGreeting,
    L7ServerTlsIMAPNoStartTLS,
    L7ServerTlsIMAPStartTLSBad,
    L7ServerTlsXMPP,
    L7ServerTlsXMPPBase,
    L7ServerTlsXMPPNoStartTLS,
    L7ServerTlsXMPPStartTLSBad,
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

    def test_authentication_sm2_tls1_3(self):
        client_hello = TlsHandshakeClientHelloAuthenticationSM2(
            TlsProtocolVersion(TlsVersion.TLS1_3), self._HOSTNAME
        )
        self.assertIsNotNone(client_hello)

    def test_key_share_curve_not_implemented(self):
        client_hello = TlsHandshakeClientHelloSpecalization(
            hostname=self._HOSTNAME,
            protocol_versions=[TlsProtocolVersion(TlsVersion.TLS1_3)],
            cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256],
            named_curves=None,
            signature_algorithms=None,
            extensions=[],
            key_share_curves=[TlsNamedCurve.ARBITRARY_EXPLICIT_PRIME_CURVES],
        )
        self.assertIsNotNone(client_hello)


class TestTls13ClientHelloKeyShare(unittest.TestCase):
    # pylint: disable=protected-access

    def test_full_named_curve_list_uses_bounded_key_share(self):
        full = list(TlsNamedCurve)
        subset = _EphemeralKeyExchangeBackendCryptodome._select_curves_for_tls13_key_share(full)
        self.assertLess(len(subset), len(full))
        self.assertLessEqual(len(subset), 8)

    def test_tls13_client_hello_default_key_share_is_empty(self):
        hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1_3)], 'localhost'
        )
        key_share_extensions = [
            extension for extension in hello.extensions
            if isinstance(extension, TlsExtensionKeyShareClient)
        ]
        self.assertEqual(len(key_share_extensions), 1)
        for extension in key_share_extensions:
            self.assertEqual(len(extension.key_share_entries), 0)

    def test_tls13_pubkeys_client_hello_fills_key_share(self):
        pubkeys_extensions, _pubkeys_key_exchange = dhe_ephemeral_material_backend.build_tls13_key_shares()
        hello = TlsHandshakeClientHelloAuthenticationRSA(
            TlsProtocolVersion(TlsVersion.TLS1_3),
            'localhost',
            extensions=pubkeys_extensions,
        )
        key_share_extensions = [
            extension for extension in hello.extensions
            if isinstance(extension, TlsExtensionKeyShareClient)
        ]
        self.assertEqual(len(key_share_extensions), 1)
        for extension in key_share_extensions:
            self.assertGreater(len(extension.key_share_entries), 0)

    def test_named_curves_for_tls13_no_preferred(self):
        preferred = _EphemeralKeyExchangeBackendCryptodome._TLS13_KEY_SHARE_PREFERRED_ORDER
        full_offer = _EphemeralKeyExchangeBackendCryptodome._TLS13_KEY_SHARE_CURVE_COUNT_FULL_OFFER
        non_preferred = [curve for curve in TlsNamedCurve if curve not in preferred]
        large_subset = non_preferred[:full_offer + 1]
        result = _EphemeralKeyExchangeBackendCryptodome._select_curves_for_tls13_key_share(large_subset)
        self.assertEqual(result, large_subset[:full_offer])

    def test_key_share_entry_elliptic_curve(self):
        entry = key_share_entry_from_named_curve(TlsNamedCurve.SECP256R1)
        self.assertEqual(entry.group, TlsNamedCurve.SECP256R1)
        self.assertGreater(len(entry.key_exchange), 0)

    def test_key_share_entry_finite_field(self):
        entry = key_share_entry_from_named_curve(TlsNamedCurve.FFDHE2048)
        self.assertEqual(entry.group, TlsNamedCurve.FFDHE2048)
        self.assertGreater(len(entry.key_exchange), 0)

    def test_key_share_entry_named_group_none(self):
        none_group = next(curve for curve in TlsNamedCurve if curve.value.named_group is None)
        with self.assertRaises(NotImplementedError):
            key_share_entry_from_named_curve(none_group)

    def test_tls13_pubkeys_key_share_extensions_skips_none_named_group(self):
        none_group_curves = [curve for curve in TlsNamedCurve if curve.value.named_group is None]
        self.assertGreater(len(none_group_curves), 0)
        extensions, key_exchange = dhe_ephemeral_material_backend.build_tls13_key_shares(none_group_curves)
        self.assertEqual(len(extensions[0].key_share_entries), 0)
        self.assertEqual(key_exchange, {})

    def test_tls13_pubkeys_key_share_extensions_skips_unsupported_curve(self):
        with mock.patch(
            'cryptolyzer.tls.crypto._EphemeralKeyExchangeBackendCryptodome.create_ephemeral_material',
            side_effect=NotImplementedError('unsupported')
        ):
            extensions, key_exchange = dhe_ephemeral_material_backend.build_tls13_key_shares([TlsNamedCurve.SECP256R1])
        self.assertEqual(len(extensions[0].key_share_entries), 0)
        self.assertEqual(key_exchange, {})


class TestTls13SplitInnerPlaintext(unittest.TestCase):
    def test_strips_trailing_zero_padding(self):
        inner_plaintext = b'\x01\x02\x03' + bytes([TlsContentType.HANDSHAKE]) + b'\x00\x00'
        content_type, payload = Tls13HandshakeDecryptor.split_inner_plaintext(inner_plaintext)
        self.assertEqual(content_type, TlsContentType.HANDSHAKE)
        self.assertEqual(payload, b'\x01\x02\x03')

    def test_all_zero_raises_bad_record_mac(self):
        with self.assertRaises(TlsAlert) as context_manager:
            Tls13HandshakeDecryptor.split_inner_plaintext(b'\x00\x00\x00')
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.BAD_RECORD_MAC)


class TestTls13TryInitHandshakeDecryptor(TestLoggerBase):
    # pylint: disable=protected-access

    def setUp(self):
        super().setUp()
        self.addCleanup(LogSingleton().setLevel, LogSingleton().level)
        LogSingleton().setLevel(logging.DEBUG)

    @staticmethod
    def _make_handshake(protection=None):
        handshake = TlsClientHandshake()
        handshake.server_messages = {}
        handshake._tls13_handshake_key_exchange_by_named_curve = protection
        handshake._client_hello_for_tls13 = None
        handshake._tls13_record_decryptor = None
        return handshake

    @staticmethod
    def _server_hello(*, random=b'\x00' * 32, last_version=TlsVersion.TLS1_3, extensions=None):
        server_hello = mock.Mock()
        server_hello.random = random
        server_hello.cipher_suite = mock.Mock()
        server_hello.cipher_suite.value.last_version = last_version
        if extensions is None:
            extensions = mock.Mock()
            extensions.get_item_by_type.side_effect = KeyError
        server_hello.extensions = extensions
        return server_hello

    def test_returns_when_no_protection(self):
        handshake = self._make_handshake(protection=None)
        handshake._tls13_try_init_handshake_decryptor(self._server_hello(), TlsHandshakeType.CERTIFICATE)
        self.assertIsNone(handshake._tls13_record_decryptor)

    def test_returns_when_last_handshake_message_not_certificate(self):
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: mock.Mock()})
        handshake._tls13_try_init_handshake_decryptor(
            self._server_hello(), TlsHandshakeType.SERVER_HELLO_DONE
        )
        self.assertIsNone(handshake._tls13_record_decryptor)

    def test_returns_on_hello_retry_request_random(self):
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: mock.Mock()})
        server_hello = self._server_hello(random=TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM)
        handshake._tls13_try_init_handshake_decryptor(server_hello, TlsHandshakeType.CERTIFICATE)
        self.assertIsNone(handshake._tls13_record_decryptor)

    def test_returns_when_cipher_suite_not_tls13(self):
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: mock.Mock()})
        server_hello = self._server_hello(last_version=TlsVersion.TLS1_2)
        handshake._tls13_try_init_handshake_decryptor(server_hello, TlsHandshakeType.CERTIFICATE)
        self.assertIsNone(handshake._tls13_record_decryptor)

    def test_returns_when_key_share_extension_missing(self):
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: mock.Mock()})
        handshake._tls13_try_init_handshake_decryptor(
            self._server_hello(), TlsHandshakeType.CERTIFICATE
        )
        self.assertIsNone(handshake._tls13_record_decryptor)

    def test_returns_when_group_not_in_protection(self):
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: mock.Mock()})
        key_share_extension = mock.Mock(spec=TlsExtensionKeyShareServer)
        entry = mock.Mock(spec=TlsKeyShareEntry)
        entry.group = TlsNamedCurve.SECP384R1
        key_share_extension.key_share_entry = entry
        extensions = mock.Mock()
        extensions.get_item_by_type.return_value = key_share_extension
        server_hello = self._server_hello(extensions=extensions)
        handshake._tls13_try_init_handshake_decryptor(server_hello, TlsHandshakeType.CERTIFICATE)
        self.assertIsNone(handshake._tls13_record_decryptor)

    def test_swallows_compute_shared_secret_failures(self):
        key_exchange = mock.Mock()
        key_exchange.compute_shared_secret.side_effect = ValueError('bad key')
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: key_exchange})
        key_share_extension = mock.Mock(spec=TlsExtensionKeyShareServer)
        entry = mock.Mock(spec=TlsKeyShareEntry)
        entry.group = TlsNamedCurve.SECP256R1
        entry.key_exchange = b'\x04' + b'\x00' * 64
        key_share_extension.key_share_entry = entry
        extensions = mock.Mock()
        extensions.get_item_by_type.return_value = key_share_extension
        server_hello = self._server_hello(extensions=extensions)
        handshake._tls13_try_init_handshake_decryptor(server_hello, TlsHandshakeType.CERTIFICATE)
        self.assertIsNone(handshake._tls13_record_decryptor)

    def test_skips_decryptor_on_unsupported_group(self):
        key_exchange = mock.Mock()
        key_exchange.compute_shared_secret.side_effect = NotImplementedError('unsupported group')
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: key_exchange})
        key_share_extension = mock.Mock(spec=TlsExtensionKeyShareServer)
        entry = mock.Mock(spec=TlsKeyShareEntry)
        entry.group = TlsNamedCurve.SECP256R1
        entry.key_exchange = b'\x04' + b'\x00' * 64
        key_share_extension.key_share_entry = entry
        extensions = mock.Mock()
        extensions.get_item_by_type.return_value = key_share_extension
        server_hello = self._server_hello(extensions=extensions)
        handshake._tls13_try_init_handshake_decryptor(server_hello, TlsHandshakeType.CERTIFICATE)
        self.assertIsNone(handshake._tls13_record_decryptor)
        self.assertIn(
            'TLS 1.3 record decryptor init skipped; reason=unsupported group',
            '\n'.join(self.get_log_lines()),
        )

    def test_skips_decryptor_on_unmapped_algorithm(self):
        key_exchange = mock.Mock()
        key_exchange.compute_shared_secret.side_effect = KeyError('unmapped algorithm')
        handshake = self._make_handshake(protection={TlsNamedCurve.SECP256R1: key_exchange})
        key_share_extension = mock.Mock(spec=TlsExtensionKeyShareServer)
        entry = mock.Mock(spec=TlsKeyShareEntry)
        entry.group = TlsNamedCurve.SECP256R1
        entry.key_exchange = b'\x04' + b'\x00' * 64
        key_share_extension.key_share_entry = entry
        extensions = mock.Mock()
        extensions.get_item_by_type.return_value = key_share_extension
        server_hello = self._server_hello(extensions=extensions)
        handshake._tls13_try_init_handshake_decryptor(server_hello, TlsHandshakeType.CERTIFICATE)
        self.assertIsNone(handshake._tls13_record_decryptor)
        self.assertIn(
            'TLS 1.3 record decryptor init skipped; reason=unmapped algorithm',
            '\n'.join(self.get_log_lines()),
        )


class TestTls13RecordDecryptError(unittest.TestCase):
    # pylint: disable=protected-access

    def test_value_error_on_decrypt_raises_bad_record_mac(self):
        application_record = TlsRecord(
            b'\x00' * 32,
            TlsProtocolVersion(TlsVersion.TLS1_2),
            TlsContentType.APPLICATION_DATA,
        )
        record_bytes = application_record.compose()

        decryptor = mock.Mock()
        decryptor.decrypt.side_effect = ValueError('bad mac')

        handshake = TlsClientHandshake()

        def fake_send_hello(_transfer, _hello, _record_version):
            handshake._tls13_record_decryptor = decryptor

        transfer = mock.Mock()
        transfer.buffer = record_bytes
        transfer.flush_buffer = mock.Mock()

        hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1_3)], 'localhost',
        )

        with mock.patch.object(TlsClientHandshake, '_send_hello', side_effect=fake_send_hello):
            with self.assertRaises(TlsAlert) as context_manager:
                handshake.do_handshake(transfer, hello)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.BAD_RECORD_MAC)


class TestTlsClientHandshakeSendHello(unittest.TestCase):
    # pylint: disable=protected-access

    def test_send_socket_timeout_raises_no_connection(self):
        hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1_2)], 'localhost',
        )
        transfer = mock.Mock()
        transfer.send.side_effect = socket.timeout('timed out')
        with self.assertRaises(NetworkError) as context_manager:
            TlsClientHandshake._send_hello(transfer, hello, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_send_other_exception_propagates(self):
        hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1_2)], 'localhost',
        )
        transfer = mock.Mock()
        transfer.send.side_effect = RuntimeError('boom')
        with self.assertRaises(RuntimeError):
            TlsClientHandshake._send_hello(transfer, hello, TlsProtocolVersion(TlsVersion.TLS1_2))


class TestTlsClientHandshakeProcessHandshakeMessage(unittest.TestCase):
    # pylint: disable=protected-access

    @staticmethod
    def _make_handshake():
        handshake = TlsClientHandshake()
        handshake.server_messages = {}
        handshake._tls13_handshake_key_exchange_by_named_curve = None
        handshake._client_hello_for_tls13 = None
        handshake._tls13_record_decryptor = None
        return handshake

    @staticmethod
    def _server_hello(*, last_version=TlsVersion.TLS1_2, protocol_version=None):
        server_hello = mock.Mock()
        server_hello.get_handshake_type.return_value = TlsHandshakeType.SERVER_HELLO
        server_hello.random = TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM
        server_hello.cipher_suite = mock.Mock()
        server_hello.cipher_suite.value.last_version = last_version
        server_hello.protocol_version = (
            protocol_version if protocol_version is not None
            else TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        return server_hello

    def test_repeated_handshake_message_raises_unexpected(self):
        handshake = self._make_handshake()
        handshake.server_messages[TlsHandshakeType.SERVER_HELLO] = self._server_hello()
        with self.assertRaises(TlsAlert) as context_manager:
            handshake._process_handshake_message(
                TlsProtocolVersion(TlsVersion.TLS1_2), self._server_hello(), None,
            )
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)

    def test_mismatching_protocol_version_raises(self):
        handshake = self._make_handshake()
        server_hello = self._server_hello(protocol_version=TlsProtocolVersion(TlsVersion.TLS1_1))
        server_hello.random = b'\x00' * 32
        with self.assertRaises(TlsAlert) as context_manager:
            handshake._process_handshake_message(
                TlsProtocolVersion(TlsVersion.TLS1_2), server_hello, None,
            )
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.PROTOCOL_VERSION)

    def test_server_hello_done_stops_iteration_when_last_is_none(self):
        handshake = self._make_handshake()
        message = mock.Mock()
        message.get_handshake_type.return_value = TlsHandshakeType.SERVER_HELLO_DONE
        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(
                TlsProtocolVersion(TlsVersion.TLS1_2), message, None,
            )

    def test_tls13_server_hello_stops_iteration_when_last_is_none(self):
        handshake = self._make_handshake()
        server_hello = self._server_hello(last_version=TlsVersion.TLS1_3)
        server_hello.random = b'\x00' * 32
        server_hello.protocol_version = TlsProtocolVersion(TlsVersion.TLS1_3)
        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(
                TlsProtocolVersion(TlsVersion.TLS1_3), server_hello, None,
            )


class TestTlsClientHelloKeyExchangeECDHxDefaults(unittest.TestCase):
    def test_default_named_curves(self):
        hello = TlsHandshakeClientHelloKeyExchangeECDHx(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'localhost',
        )
        self.assertGreater(len(hello.cipher_suites), 0)


class TestDefaultPorts(unittest.TestCase):
    def test_pop3_default_port(self):
        self.assertEqual(ClientPOP3.get_default_port(), 110)

    def test_rdp_default_port(self):
        self.assertEqual(ClientRDP.get_default_port(), 3389)


class TestSignatureAlgorithmsBranches(unittest.TestCase):
    @staticmethod
    def _sigalg_authentications(hello):
        for ext in hello.extensions:
            if isinstance(ext, (TlsExtensionSignatureAlgorithms, TlsExtensionSignatureAlgorithmsCert)):
                return {sigalg.value.signature_algorithm for sigalg in ext.hash_and_signature_algorithms}
        return set()

    def test_tls13_typed_rsa_includes_rsa(self):
        hello = TlsHandshakeClientHelloAuthenticationRSA(
            TlsProtocolVersion(TlsVersion.TLS1_3), 'localhost'
        )
        self.assertIn(Authentication.RSA, self._sigalg_authentications(hello))

    def test_tls12_typed_rsa_includes_rsa(self):
        hello = TlsHandshakeClientHelloAuthenticationRSA(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'localhost'
        )
        self.assertIn(Authentication.RSA, self._sigalg_authentications(hello))

    def test_mixed_pre_tls12_and_tls13_excludes_dss_and_anonymous(self):
        hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1), TlsProtocolVersion(TlsVersion.TLS1_3)],
            'localhost',
        )
        authentications = self._sigalg_authentications(hello)
        self.assertNotIn(Authentication.DSS, authentications)
        self.assertNotIn(Authentication.ANONYMOUS, authentications)

    def test_pre_tls12_only_has_no_signature_algorithms(self):
        hello = TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1)], 'localhost'
        )
        self.assertEqual(self._sigalg_authentications(hello), set())


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
            self.get_result('tls', 'localhost', 443, ip='not.an.ip.address')
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    @mock.patch.object(L4ClientTCP, '_send', return_value=0)
    def test_error_send(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.wait_for_server_listen()
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'localhost', threaded_server.l7_server.l4_transfer.bind_port)
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
        l7_client = L7ClientTlsMock('localhost')
        self.assertEqual(l7_client.port, 443)

    @live_server
    def test_error_connection_timeout_on_close(self):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsMock('badssl.com', 443, L4TransferSocketParams(timeout=10))
        self.assertEqual(
            analyzer.analyze(l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)).versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        )

    @live_server
    def test_tls_client(self):
        _, result = self.get_result('tls', 'badssl.com', 443, L4TransferSocketParams(timeout=10))
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        )

    @live_server
    def test_https_client(self):
        _, result = self.get_result('https', 'badssl.com', None, L4TransferSocketParams(timeout=10))
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

    def test_pop3s_client_port(self):
        client = L7ClientTlsBase.from_scheme('pop3s', 'localhost')
        self.assertEqual(client.port, 995)


class TestClientIMAP(TestL7ClientBase):
    @staticmethod
    def _start_imap_server(l7_server_class):
        threaded_server = L7ServerTlsTest(
            l7_server_class('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        return threaded_server

    def test_error_unsupported_starttls(self):
        threaded_server = self._start_imap_server(L7ServerTlsIMAPNoStartTLS)
        _, result = self.get_result(
            'imap',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertEqual(result.versions, [])

    def test_imap_client(self):
        threaded_server = self._start_imap_server(L7ServerTlsIMAP)
        _, result = self.get_result(
            'imap',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)

    def test_error_starttls_error(self):
        threaded_server = self._start_imap_server(L7ServerTlsIMAPStartTLSBad)
        _, result = self.get_result(
            'imap',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertEqual(result.versions, [])

    def test_error_invalid_greeting(self):
        threaded_server = self._start_imap_server(L7ServerTlsIMAPInvalidGreeting)
        _, result = self.get_result(
            'imap',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertEqual(result.versions, [])

    def test_error_early_close(self):
        threaded_server = self._start_imap_server(L7ServerTlsIMAPEarlyClose)
        _, result = self.get_result(
            'imap',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertEqual(result.versions, [])

    def test_imap_client_port(self):
        client = L7ClientTlsBase.from_scheme('imap', 'localhost')
        self.assertEqual(client.port, 143)

    def test_imap_server_port(self):
        self.assertEqual(L7ServerTlsIMAPBase.get_default_port(), 143)

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

    @live_server
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
    @staticmethod
    def _start_ftp_server(l7_server_class):
        threaded_server = L7ServerTlsTest(
            l7_server_class('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        return threaded_server

    @mock.patch.object(ftplib.FTP, '__init__', side_effect=ftplib.error_reply)
    def test_error_ftplib_error(self, _):
        _, result = self.get_result('ftp', 'localhost', None)
        self.assertEqual(result.versions, [])

    @mock.patch.object(ftplib.FTP, 'sendcmd', return_value='502 Command not implemented')
    def test_error_unsupported_starttls(self, _):
        threaded_server = self._start_ftp_server(L7ServerTlsFTP)
        _, result = self.get_result(
            'ftp',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(ftplib.FTP, 'connect', return_value='534 Could Not Connect to Server - Policy Requires SSL')
    @mock.patch.object(ftplib.FTP, 'quit', side_effect=ftplib.error_perm)
    def test_error_ftp_error_on_connect(self, _, __):
        threaded_server = self._start_ftp_server(L7ServerTlsFTP)
        _, result = self.get_result(
            'ftp',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertEqual(result.versions, [])

    @mock.patch.object(ftplib.FTP, 'quit', side_effect=ftplib.error_reply)
    def test_error_ftp_error_on_quit(self, _):
        threaded_server = self._start_ftp_server(L7ServerTlsFTP)
        _, result = self.get_result(
            'ftp',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)

    def test_ftp_client(self):
        threaded_server = self._start_ftp_server(L7ServerTlsFTP)
        _, result = self.get_result(
            'ftp',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)

    def test_ftps_client_port(self):
        client = L7ClientTlsBase.from_scheme('ftps', 'localhost')
        self.assertEqual(client.port, 990)


RDP_NEGOTIATION_RESPONSE_LENGTH = 19


class TestClientRDP(TestL7ClientBase):
    def test_error_send_timeout_error(self):
        with mock.patch.object(L7ClientTlsBase, '_init_connection', side_effect=TimeoutError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('rdp', 'localhost', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @live_server
    @mock.patch.object(ParsableBase, 'parse_exact_size', side_effect=InvalidType)
    def test_error_parse_invalid_type(self, _):
        _, result = self.get_result('rdp', 'badssl.com', 443, L4TransferSocketParams(timeout=10))
        self.assertEqual(result.versions, [])

    @live_server
    @mock.patch.object(ParsableBase, 'parse_exact_size', side_effect=InvalidValue('x', int))
    def test_error_parse_invalid_value(self, _):
        _, result = self.get_result('rdp', 'badssl.com', 443, L4TransferSocketParams(timeout=10))
        self.assertEqual(result.versions, [])

    @live_server
    @mock.patch.object(
        L4ClientTCP, '_receive_bytes',
        return_value=TPKT(
            3, COTPConnectionConfirm(
                src_ref=1, dst_ref=1, user_data=RDPNegotiationResponse([], []).compose()
            ).compose()
        ).compose()
    )
    def test_error_no_ssl_support(self, _):
        _, result = self.get_result('rdp', 'badssl.com', 443, L4TransferSocketParams(timeout=10))
        self.assertEqual(result.versions, [])


class TestClientLDAP(TestL7ClientBase):
    def test_error_send_timeout_error(self):
        with mock.patch.object(L7ClientTlsBase, '_init_connection', side_effect=TimeoutError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('ldap', 'localhost', None)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @live_server
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

    @live_server
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

    def test_nntps_client_port(self):
        client = L7ClientTlsBase.from_scheme('nntps', 'localhost')
        self.assertEqual(client.port, 563)


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

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(MySQLRecord(0, MySQLHandshakeV10(
        protocol_version=MySQLVersion.MYSQL_9,
        server_version='version',
        connection_id=1,
        auth_plugin_data=b'\x00\x00\x00\x00\x00\x00\x00\x00',
        capabilities=set([MySQLCapability.CLIENT_SSL, MySQLCapability.CLIENT_PROTOCOL_41]),
        character_set=MySQLCharacterSet.UTF8,
        states=set(),
    ).compose()).compose(),))
    def test_client_protocol_41(self, _):
        _, result = self._get_mock_server_response('mysql')
        self.assertEqual(result.versions, [])

    def test_default_port(self):
        l7_client = L7ClientTlsBase.from_scheme('mysql', 'localhost')
        self.assertEqual(l7_client.port, 3306)


class TestClientPostgreSQL(TestL7ClientBase):
    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'X', ))
    def test_error_starttls_error(self, _):
        _, result = self._get_mock_server_response('postgresql')
        self.assertEqual(result.versions, [])

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=(b'S', ))
    def test_starttls_acknowledged_then_tls_fails(self, _):
        _, result = self._get_mock_server_response('postgresql')
        self.assertEqual(result.versions, [])

    def test_default_port(self):
        l7_client = L7ClientTlsBase.from_scheme('postgresql', 'localhost')
        self.assertEqual(l7_client.port, 5432)


class TestClientSieve(TestL7ClientBase):
    def test_error_send_timeout_error(self):
        with mock.patch.object(L7ClientTlsBase, '_init_connection', side_effect=TimeoutError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('sieve', 'localhost', None)
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

    @live_server
    def test_sieve_client(self):
        _, result = self.get_result('sieve', 'mail.aa.net.uk', None, analyzer=AnalyzerDHParams())
        self.assertEqual(result.dhparam.well_known, DHParamWellKnown.RFC3526_4096_BIT_MODP_GROUP)


class TestClientXMPP(TestL7ClientBase):
    @staticmethod
    def _start_xmpp_server(l7_server_class):
        threaded_server = L7ServerTlsTest(
            l7_server_class('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        return threaded_server

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

    def test_error_no_tls_feature(self):
        threaded_server = self._start_xmpp_server(L7ServerTlsXMPPNoStartTLS)
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
        )
        self.assertEqual(result.versions, [])

    def test_error_starttls_error(self):
        threaded_server = self._start_xmpp_server(L7ServerTlsXMPPStartTLSBad)
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
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

    def test_xmpp_client(self):
        threaded_server = self._start_xmpp_server(L7ServerTlsXMPP)
        _, result = self.get_result(
            'xmppclient', 'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10),
        )
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)

        threaded_server = self._start_xmpp_server(L7ServerTlsXMPP)
        port = threaded_server.l7_server.l4_transfer.bind_port
        analyzer = AnalyzerVersions()
        handler = ProtocolHandlerBase.from_protocol('tls')
        result = handler.analyze(
            analyzer, urllib3.util.parse_url(f'xmppclient://localhost:{port}/?stream_to=localhost')
        )
        self.assertIn(TlsProtocolVersion(TlsVersion.TLS1_2), result.versions)

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

    def test_xmppclient_client_port(self):
        client = L7ClientTlsBase.from_scheme('xmppclient', 'localhost')
        self.assertEqual(client.port, 5222)

    def test_xmppserver_client_port(self):
        client = L7ClientTlsBase.from_scheme('xmppserver', 'localhost')
        self.assertEqual(client.port, 5269)

    def test_xmpp_server_port(self):
        self.assertEqual(L7ServerTlsXMPPBase.get_default_port(), 5222)


class TestClientDoH(TestL7ClientBase):
    @live_server
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

    @live_server
    @mock.patch.object(L7TransferBase, 'receive', side_effect=NotEnoughData)
    @mock.patch.object(L4TransferBase, 'buffer', mock.PropertyMock(return_value=b'\x00'))
    def test_error_no_response(self, _):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS)
        l7_client.session_id = 0xfffffffffffffffe
        with self.assertRaises(NetworkError) as context_manager:
            l7_client.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @live_server
    @mock.patch.object(
        L4ClientUDP, '_receive_bytes',
        return_value=OpenVpnPacketHardResetServerV2(1, 0xffffffffffffffff, [0], 1).compose()
    )
    @mock.patch.object(
        L4ClientTCP, 'send', return_value=None
    )
    def test_error_not_enough_packet_byte_udp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    @live_server
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
        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    @live_server
    @mock.patch.object(ClientOpenVpnBase, '_reset_session', return_value=None)
    @mock.patch.object(
        ClientOpenVpnBase, '_receive_packets',
        return_value=[OpenVpnPacketHardResetClientV2(0xffffffffffffffff, 1), ]
    )
    def test_error_invalid_op_code_udp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(InvalidType):
            l7_client.receive(1)
        l7_client.l4_transfer.close()

    @live_server
    @mock.patch.object(ClientOpenVpnBase, '_reset_session', return_value=None)
    @mock.patch.object(
        ClientOpenVpnBase, '_receive_packets',
        return_value=[OpenVpnPacketHardResetClientV2(0xffffffffffffffff, 1), ]
    )
    def test_error_invalid_op_code_tcp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(InvalidType):
            l7_client.receive(1)
        l7_client.l4_transfer.close()

    @live_server
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
        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    @live_server
    def test_openvpn_tcp_client(self):
        _, result = self.get_result(
            'openvpntcp', 'gr1.vpnjantit.com', 992,
            L4TransferSocketParams(timeout=10), analyzer=AnalyzerDHParams()
        )
        self.assertEqual(result.dhparam.well_known, DHParamWellKnown.RFC2539_1024_BIT_MODP_GROUP)

        l7_client = L7ClientTlsBase.from_scheme('openvpntcp', 'localhost')
        self.assertEqual(l7_client.port, L7ClientHTTPS.get_default_port())

    @live_server
    @mock.patch.object(
        L4ClientUDP, '_receive_bytes',
        return_value=OpenVpnPacketHardResetServerV2(1, 0xffffffffffffffff, [0], 1).compose()
    )
    @mock.patch.object(
        L4ClientUDP, 'send', return_value=None
    )
    def test_error_receive_unexpected_server_reset_udp(self, _, __):
        l7_client = L7ClientTlsBase.from_scheme('openvpn', 'badssl.com', 1194, BADSSL_COM_L4_SOCKET_PARAMS)
        l7_client.session_id = 0xfffffffffffffffe
        l7_client.init_connection()
        with self.assertRaises(NotEnoughData) as context_manager:
            l7_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)
        l7_client.l4_transfer.close()

    @live_server
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

    @mock.patch.object(TlsServerMockResponse, '_get_mock_responses', return_value=[
        TlsRecord(
            TlsHandshakeServerHello(cipher_suite=TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_MD5).compose(),
            content_type=TlsContentType.HANDSHAKE,
        ).compose()
    ])
    @mock.patch.object(
        TlsRecord, 'parse_immutable', return_value=(
            TlsRecord(
                TlsChangeCipherSpecMessage().compose(),
                content_type=TlsContentType.CHANGE_CIPHER_SPEC,
            ),
            1,
        )
    )
    def test_error_non_handshake_message(self, _, __):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsMockResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.wait_for_server_listen()
        l7_client = L7ClientTlsBase.from_scheme('tls', 'localhost', threaded_server.l7_server.l4_transfer.bind_port)
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([TlsProtocolVersion(TlsVersion.TLS1_2), ], 'localhost')
        with self.assertRaises(TlsAlert) as context_manager:
            l7_client.do_tls_handshake(client_hello)
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
            L7ClientTls('badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS).do_ssl_handshake(
                SslHandshakeClientHello(list(SslCipherKind)))
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CIPHER_ERROR)

    @mock.patch.object(
        SslRecord, 'parse_exact_size',
        return_value=SslRecord(SslHandshakeServerHello(
            certificate=b'',
            cipher_kinds=[],
            connection_id=b'',
        ))
    )
    def test_server_hello_completes_handshake(self, _):
        result = L7ClientTls('badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS).do_ssl_handshake(
            SslHandshakeClientHello(list(SslCipherKind)),
        )
        self.assertIn(SslMessageType.SERVER_HELLO, result)

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
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.wait_for_server_listen()
        with self.assertRaises(SecurityError) as context_manager:
            L7ClientTls('localhost', threaded_server.l7_server.l4_transfer.bind_port).do_ssl_handshake(
                SslHandshakeClientHello(list(SslCipherKind)))
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
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.wait_for_server_listen()
        with self.assertRaises(SecurityError) as context_manager:
            L7ClientTls('localhost', threaded_server.l7_server.l4_transfer.bind_port).do_ssl_handshake(
                SslHandshakeClientHello(list(SslCipherKind)))
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
            L7ClientTls('badssl.com', 443, BADSSL_COM_L4_SOCKET_PARAMS).do_ssl_handshake(
                SslHandshakeClientHello(list(SslCipherKind)))
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(L4ClientTCP, 'receive', return_value=b'')
    @mock.patch.object(
        SslRecord, 'parse_exact_size', side_effect=[
            SslRecord(SslHandshakeServerHello(b'', SslCipherKind)),
            SslRecord(SslErrorMessage(SslErrorType.NO_CERTIFICATE_ERROR)),
        ]
    )
    def test_multiple_messages(self, _, __):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.wait_for_server_listen()
        with self.assertRaises(SslError) as context_manager:
            L7ClientTls('localhost', threaded_server.l7_server.l4_transfer.bind_port).do_ssl_handshake(
                SslHandshakeClientHello(list(SslCipherKind)),
                SslMessageType.ERROR
            )
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CERTIFICATE_ERROR)
