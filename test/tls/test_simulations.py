# SPDX-License-Identifier: MPL-2.0

from unittest import mock

from test.common.classes import (
    OFFLINE_CLIENT_L4_SOCKET_PARAMS,
    OFFLINE_L4_SOCKET_PARAMS,
    TestLoggerBase,
    TestMainBase,
    TestThreadedServerHttps,
)

from cryptodatahub.common.algorithm import Authentication, KeyExchange
from cryptodatahub.common.key import PublicKeySize
from cryptodatahub.common.parameter import DHParameterNumbers
from cryptodatahub.tls.algorithm import TlsNextProtocolName, TlsProtocolName
from cryptodatahub.tls.client import TlsClient

from cryptoparser.common.x509 import PublicKeyX509
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsNamedCurve
from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.__main__ import main
from cryptolyzer.common.dhparam import DHParamWellKnown
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration
from cryptolyzer.tls.simulations import (
    AnalyzerSimulations,
    AnalyzerResultSimulationsTlsBase,
    AnalyzerResultSimulationsTlsPfs,
    AnalyzerResultSimulationsTlsPfsDhWellKnown,
    AnalyzerResultSimulationsTlsPfsNamedGroup,
)

from .classes import L7ServerTlsTest


class TestTlsSimulations(TestLoggerBase, TestMainBase):
    SNAKEOIL_CERT_DER = PublicKeyX509.from_pem(TestThreadedServerHttps.CERT_FILE_PATH.read_text()).der

    @classmethod
    def _get_main_func(cls):
        return main

    @staticmethod
    def get_result(
            host, port, protocol_version=None, l4_socket_params=OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=None, scheme='https'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerSimulations()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    )
    def test_error_tls_alert_protocol_version(self, _):
        result = self.get_result('127.0.0.1', 443)
        self.assertEqual(len(result.succeeded_clients), 0)
        self.assertEqual(len(result.failed_clients), len(set(tls_client.value.meta.client for tls_client in TlsClient)))

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)
    )
    def test_error_tls_alert_handshake_failure(self, _):
        result = self.get_result('127.0.0.1', 443)
        self.assertEqual(len(result.succeeded_clients), 0)
        self.assertEqual(len(result.failed_clients), len(set(tls_client.value.meta.client for tls_client in TlsClient)))

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
    )
    def test_error_tls_alert_unknown_error(self, _):
        result = self.get_result('127.0.0.1', 443)
        self.assertEqual(len(result.succeeded_clients), 0)
        self.assertEqual(len(result.failed_clients), len(set(tls_client.value.meta.client for tls_client in TlsClient)))

    def test_failed_clients(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA],
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.succeeded_clients), 2)
        self.assertEqual(len(result.failed_clients), 4)
        self.assertTrue(result)

    def test_non_pfs(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(all(
            type(analyzer_result) is AnalyzerResultSimulationsTlsBase  # pylint: disable=unidiomatic-typecheck
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.cipher_suite.value.authentication == Authentication.RSA
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(result)

    def test_application_layer_protocol(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
                application_layer_protocols=[TlsProtocolName.HTTP_1_1],
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(all(
            analyzer_result.application_layer_protocol == TlsProtocolName.HTTP_1_1
            for analyzer_result in result.succeeded_clients.values()
        ))

        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
                next_protocols=[TlsNextProtocolName.HTTP_1_1],
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(all(
            analyzer_result.application_layer_protocol == TlsNextProtocolName.HTTP_1_1
            for analyzer_result in result.succeeded_clients.values()
        ))

    def test_pfs_dh_custom(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
                dh_param=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(all(
            isinstance(analyzer_result, AnalyzerResultSimulationsTlsPfs)
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.cipher_suite.value.key_exchange == KeyExchange.DHE
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.key_size == PublicKeySize(KeyExchange.DHE, 2048)
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertEqual(len(result.failed_clients), 4)
        self.assertTrue(result)

    def test_pfs_dh_custom_prime(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
                dh_param=DHParameterNumbers((1 << 2047) + 3, 2),
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(all(
            type(analyzer_result) is AnalyzerResultSimulationsTlsPfs  # pylint: disable=unidiomatic-typecheck
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.cipher_suite.value.key_exchange == KeyExchange.DHE
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.key_size == PublicKeySize(KeyExchange.DHE, 2048)
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertEqual(len(result.failed_clients), 4)
        self.assertTrue(result)

    def test_dh_well_known(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
                dh_param=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(all(
            type(analyzer_result) is AnalyzerResultSimulationsTlsPfsDhWellKnown  # pylint: disable=unidiomatic-typecheck
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.well_known == DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(result)

    def test_pfs_named_group(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA],
                curves=[TlsNamedCurve.SECP256R1],
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(all(
            type(analyzer_result) is AnalyzerResultSimulationsTlsPfsNamedGroup  # pylint: disable=unidiomatic-typecheck
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.cipher_suite.value.key_exchange == KeyExchange.ECDHE
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.key_size == PublicKeySize(KeyExchange.ECDHE, 256)
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(result)

    def test_output(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            '127.0.0.1', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
                curves=[TlsNamedCurve.X25519, TlsNamedCurve.SECP256R1],
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        func_arguments, cli_arguments = self._get_arguments(
            'tls', 'simulations', '127.0.0.1', threaded_server.l7_server.l4_transfer.bind_port, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')

    def test_version_1_3(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256],
                curves=[TlsNamedCurve.X25519, TlsNamedCurve.SECP256R1],
                certificates=[self.SNAKEOIL_CERT_DER],
            )
        ))
        threaded_server.wait_for_server_listen()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        tls_1_3_results = [
            analyzer_result
            for analyzer_result in result.succeeded_clients.values()
            if analyzer_result.version > TlsProtocolVersion(TlsVersion.TLS1_2)
        ]
        self.assertTrue(tls_1_3_results)
        self.assertTrue(all(
            type(analyzer_result) is AnalyzerResultSimulationsTlsPfsNamedGroup  # pylint: disable=unidiomatic-typecheck
            for analyzer_result in tls_1_3_results
        ))
        self.assertTrue(all(
            analyzer_result.key_size in [PublicKeySize(KeyExchange.ECDHE, 256), PublicKeySize(KeyExchange.ECDHE, 1120)]
            for analyzer_result in tls_1_3_results
        ))
        self.assertTrue(result)
