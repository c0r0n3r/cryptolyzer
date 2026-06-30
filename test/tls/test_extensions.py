# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from unittest import mock

import datetime

from test.common.classes import OFFLINE_L4_SOCKET_PARAMS, TestLoggerBase, TestMainBase
from test.common.markers import live_server

from cryptodatahub.tls.algorithm import TlsECPointFormat, TlsNextProtocolName, TlsProtocolName
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import (
    TlsECPointFormatVector,
    TlsExtensionApplicationLayerProtocolNegotiation,
    TlsExtensionRecordSizeLimit,
)
from cryptoparser.tls.subprotocol import (
    TlsCompressionMethod,
    TlsHandshakeHelloRandom,
    TlsHandshakeHelloRandomBytes,
    TlsHandshakeServerHello,
    TlsHandshakeType,
)
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.client import L7ClientTlsBase, TlsAlert, TlsAlertDescription
from cryptolyzer.tls.extensions import AnalyzerExtensions
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration

from cryptolyzer.__main__ import main

from .classes import L7ServerTlsTest


class TestTlsExtensions(TestLoggerBase, TestMainBase):  # pylint: disable=too-many-public-methods
    @classmethod
    def _get_main_func(cls):
        return main

    @staticmethod
    def get_result(
            host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=L4TransferSocketParams(), ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerExtensions()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    def test_next_protocols(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.next_protocols, [])

    def test_next_protocols_offered(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                next_protocols=[TlsNextProtocolName.HTTP_1_1],
                application_layer_protocols=[TlsProtocolName.HTTP_1_1],
            ),
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(set(result.next_protocols), set([TlsNextProtocolName.HTTP_1_1, ]))
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers application layer protocol "http/1.1"', log_lines)
        self.assertIn('Server offers next protocol(s) "http/1.1"', log_lines)

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
        result = self.get_result('localhost', 0)
        self.assertEqual(
            set(result.application_layer_protocols),
            set([TlsProtocolName.HTTP_1_1, ])
        )

    def test_application_layer_protocols(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.application_layer_protocols, [])

    def test_application_layer_protocols_offered(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                next_protocols=[TlsNextProtocolName.HTTP_1_1],
                application_layer_protocols=[TlsProtocolName.HTTP_1_1],
            ),
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(set(result.application_layer_protocols), set([TlsProtocolName.HTTP_1_1]))
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers application layer protocol "http/1.1"', log_lines)
        self.assertIn('Server offers next protocol(s) "http/1.1"', log_lines)

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
        l7_client = L7ClientTlsBase.from_scheme('tls', 'localhost', 0)
        compression_methods = analyzer._analyze_compression_methods(  # pylint: disable=protected-access
            l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
        )

        self.assertEqual(
            set(compression_methods),
            set([TlsCompressionMethod.NULL, TlsCompressionMethod.DEFLATE, TlsCompressionMethod.LZS])
        )

    def test_compression_method(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertEqual(
            set(result.compression_methods),
            set([TlsCompressionMethod.NULL, ])
        )
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers compression method(s) "NULL"', log_lines)

        analyzer = AnalyzerExtensions()
        threaded_server_tls13 = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256],
            )
        ))
        threaded_server_tls13.wait_for_server_listen()
        l7_client = L7ClientTlsBase.from_scheme(
            'tls', 'localhost', threaded_server_tls13.l7_server.l4_transfer.bind_port
        )
        compression_methods = analyzer._analyze_compression_methods(  # pylint: disable=protected-access
            l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        self.assertEqual(set(compression_methods), set())

    def test_ec_point_formats(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.ec_point_formats,
            [TlsECPointFormat.UNCOMPRESSED, ]
        )
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers point format(s) "UNCOMPRESSED"', log_lines)

    @live_server
    def test_ec_point_formats_offered(self):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(
            result.ec_point_formats,
            TlsECPointFormatVector([TlsECPointFormat.UNCOMPRESSED, ])
        )
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers point format(s) "UNCOMPRESSED"', log_lines)

    def test_encrypt_then_mac(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result(
            'localhost', threaded_server.l7_server.l4_transfer.bind_port,
            TlsProtocolVersion(TlsVersion.TLS1),
        )
        self.assertFalse(result.encrypt_then_mac_supported)
        log_lines = self.pop_log_lines()
        self.assertNotIn('Server does not offer encrypt then MAC', log_lines)
        self.assertNotIn('Server offers encrypt then MAC', log_lines)

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.encrypt_then_mac_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server does not offer encrypt then MAC', log_lines)

    def test_encrypt_then_mac_supported(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                encrypt_then_mac_supported=True,
            ),
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.encrypt_then_mac_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers encrypt then MAC', log_lines)

        threaded_server_gcm = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256],
            ),
        ))
        threaded_server_gcm.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server_gcm.l7_server.l4_transfer.bind_port)
        self.assertIsNone(result.encrypt_then_mac_supported)
        log_lines = self.pop_log_lines()
        self.assertNotIn('Server does not offer encrypt then MAC', log_lines)
        self.assertNotIn('Server offers encrypt then MAC', log_lines)

    def test_extended_master_secret(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.extended_master_secret_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server does not offer extended master secret', log_lines)

    def test_extended_master_secret_supported(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                extended_master_secret_supported=True,
            ),
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.extended_master_secret_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers extended master secret', log_lines)

    def test_clock_is_accurate(self):
        with mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            return_value={
                TlsHandshakeType.SERVER_HELLO: TlsHandshakeServerHello(
                    cipher_suite=TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                    random=TlsHandshakeHelloRandom(
                        time=datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
                        random=TlsHandshakeHelloRandomBytes(bytearray(28)),
                    ),
                )
            }
        ):
            result = self.get_result('localhost', 0)
            self.assertFalse(result.clock_is_accurate)
            log_lines = self.pop_log_lines()
            self.assertIn('Server does not offer accurate clock', log_lines)

        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.clock_is_accurate)
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers accurate clock', log_lines)

        analyzer = AnalyzerExtensions()
        threaded_server_tls13 = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256],
            )
        ))
        threaded_server_tls13.wait_for_server_listen()
        l7_client = L7ClientTlsBase.from_scheme(
            'tls', 'localhost', threaded_server_tls13.l7_server.l4_transfer.bind_port
        )
        clock_is_accurate = analyzer._analyze_clock_skew(  # pylint: disable=protected-access
            l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        self.assertIsNone(clock_is_accurate)

    def test_record_size_limit(self):
        analyzer = AnalyzerExtensions()
        l7_client = L7ClientTlsBase.from_scheme('tls', 'localhost', 0)

        with mock.patch.object(L7ClientTlsBase, 'do_tls_handshake',
                               side_effect=NetworkError(NetworkErrorType.NO_CONNECTION)):
            handled, limit_server = analyzer._analyze_record_size_limit(  # pylint: disable=protected-access
                l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
            )
            self.assertFalse(handled)
            self.assertEqual(limit_server, None)

        with mock.patch.object(L7ClientTlsBase, 'do_tls_handshake',
                               side_effect=TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)):
            handled, limit_server = analyzer._analyze_record_size_limit(  # pylint: disable=protected-access
                l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
            )
            self.assertFalse(handled)
            self.assertEqual(limit_server, None)

        with mock.patch.object(L7ClientTlsBase, 'do_tls_handshake', side_effect=[
                    TlsAlert(TlsAlertDescription.RECORD_OVERFLOW),
                    TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)
                ]):
            handled, limit_server = analyzer._analyze_record_size_limit(  # pylint: disable=protected-access
                l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
            )
            self.assertTrue(handled)
            self.assertEqual(limit_server, None)

        server_hello_message = TlsHandshakeServerHello(
            cipher_suite=TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
            compression_method=TlsCompressionMethod.NULL,
            extensions=[]
        )
        with mock.patch.object(L7ClientTlsBase, 'do_tls_handshake', side_effect=[
                    TlsAlert(TlsAlertDescription.RECORD_OVERFLOW),
                    {TlsHandshakeType.SERVER_HELLO: server_hello_message},
                ]):
            handled, limit_server = analyzer._analyze_record_size_limit(  # pylint: disable=protected-access
                l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
            )
            self.assertTrue(handled)
            self.assertEqual(limit_server, None)

        server_hello_message.extensions.append(TlsExtensionRecordSizeLimit(1024))
        with mock.patch.object(L7ClientTlsBase, 'do_tls_handshake', side_effect=[
                    TlsAlert(TlsAlertDescription.RECORD_OVERFLOW),
                    {TlsHandshakeType.SERVER_HELLO: server_hello_message},
                ]):
            handled, limit_server = analyzer._analyze_record_size_limit(  # pylint: disable=protected-access
                l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
            )
            self.assertTrue(handled)
            self.assertEqual(limit_server, 1024)

    def test_renegotiation_info(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.renegotiation_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server does not offer renegotiation', log_lines)

    def test_renegotiation_info_supported(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                renegotiation_supported=True,
            ),
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.renegotiation_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers renegotiation', log_lines)

    def test_session_cache(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.session_cache_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server does not offer session cache', log_lines)

        analyzer = AnalyzerExtensions()
        threaded_server_tls13 = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_3),
                cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256],
            )
        ))
        threaded_server_tls13.wait_for_server_listen()
        l7_client = L7ClientTlsBase.from_scheme(
            'tls', 'localhost', threaded_server_tls13.l7_server.l4_transfer.bind_port
        )
        session_cache_supported = analyzer._analyze_session_cache(  # pylint: disable=protected-access
            l7_client, TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        self.assertFalse(session_cache_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server does not offer session cache', log_lines)

    def test_session_cache_supported(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                session_cache_supported=True,
            ),
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.session_cache_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers session cache', log_lines)

    def test_session_ticket(self):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, OFFLINE_L4_SOCKET_PARAMS))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.session_ticket_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server does not offer session ticket', log_lines)

    def test_session_ticket_supported(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                session_ticket_supported=True,
            ),
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.session_ticket_supported)
        log_lines = self.pop_log_lines()
        self.assertIn('Server offers session ticket', log_lines)

    def test_output(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            '127.0.0.1', 0,
            OFFLINE_L4_SOCKET_PARAMS,
        ))
        threaded_server.wait_for_server_listen()
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'extensions', '127.0.0.1',
            threaded_server.l7_server.l4_transfer.bind_port, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
