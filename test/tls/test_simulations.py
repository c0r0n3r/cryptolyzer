# -*- coding: utf-8 -*-

from unittest import mock

from test.common.classes import TestLoggerBase

from cryptodatahub.common.algorithm import Authentication, KeyExchange
from cryptodatahub.common.key import PublicKeySize
from cryptodatahub.tls.client import TlsClient

from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.dhparam import DHParamWellKnown
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.simulations import (
    AnalyzerSimulations,
    AnalyzerResultSimulationsTlsBase,
    AnalyzerResultSimulationsTlsPfs,
    AnalyzerResultSimulationsTlsPfsNamedGroup,
)


class TestTlsSimulations(TestLoggerBase):
    @staticmethod
    def get_result(
            host, port, protocol_version=None, l4_socket_params=L4TransferSocketParams(), ip=None, scheme='https'
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
        result = self.get_result('badssl.com', 443)
        self.assertEqual(len(result.succeeded_clients), 0)
        self.assertEqual(len(result.failed_clients), len(set(tls_client.value.meta.client for tls_client in TlsClient)))

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)
    )
    def test_error_tls_alert_handshake_failure(self, _):
        result = self.get_result('badssl.com', 443)
        self.assertEqual(len(result.succeeded_clients), 0)
        self.assertEqual(len(result.failed_clients), len(set(tls_client.value.meta.client for tls_client in TlsClient)))

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
    )
    def test_error_tls_alert_unknown_error(self, _):
        result = self.get_result('badssl.com', 443)
        self.assertEqual(len(result.succeeded_clients), 0)
        self.assertEqual(len(result.failed_clients), len(set(tls_client.value.meta.client for tls_client in TlsClient)))

    def test_failed_clients(self):
        result = self.get_result('rc4.badssl.com', 443)
        self.assertEqual(len(result.succeeded_clients), 3)
        self.assertEqual(len(result.failed_clients), 4)
        self.assertTrue(result)

    def test_non_pfs(self):
        result = self.get_result('static-rsa.badssl.com', 443)
        self.assertTrue(all(
            type(analyzer_result) is AnalyzerResultSimulationsTlsBase  # pylint: disable=unidiomatic-typecheck
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.cipher_suite.value.authentication == Authentication.RSA
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(result)

    def test_pfs_dh_custom(self):
        result = self.get_result('dh2048.badssl.com', 443)
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
        result = self.get_result('kaspersky.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertTrue(all(
            analyzer_result.cipher_suite.value.key_exchange in [KeyExchange.DHE, KeyExchange.ECDHE]
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.well_known == DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP
            for analyzer_result in result.succeeded_clients.values()
            if analyzer_result.cipher_suite.value.key_exchange == KeyExchange.DHE
        ))

        self.assertEqual(len(result.failed_clients), 3)
        self.assertTrue(result)

    def test_pfs_named_group(self):
        result = self.get_result('ecc256.badssl.com', 443)
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
        self.assertEqual(len(result.failed_clients), 1)
        self.assertTrue(result)

    def test_version_1_3(self):
        result = self.get_result('cloudflare.com', 443)
        self.assertTrue(all(
            type(analyzer_result) is AnalyzerResultSimulationsTlsPfsNamedGroup  # pylint: disable=unidiomatic-typecheck
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(any(
            analyzer_result.version > TlsProtocolVersion(TlsVersion.TLS1_2)
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertTrue(all(
            analyzer_result.key_size in [PublicKeySize(KeyExchange.ECDHE, 256), PublicKeySize(KeyExchange.ECDHE, 1120)]
            for analyzer_result in result.succeeded_clients.values()
        ))
        self.assertEqual(len(result.failed_clients), 1)
        self.assertTrue(result)
