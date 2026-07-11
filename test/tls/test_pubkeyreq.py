# SPDX-License-Identifier: MPL-2.0

from unittest import mock

from collections import OrderedDict

from test.common.classes import (
    OFFLINE_CLIENT_L4_SOCKET_PARAMS,
    OFFLINE_L4_SOCKET_PARAMS,
    TestMainBase,
)

import asn1crypto.x509

from cryptodatahub.tls.algorithm import TlsSignatureAndHashAlgorithm

from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsCipherSuite, TlsClientCertificateType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.pubkeyreq import AnalyzerPublicKeyRequest
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration

from cryptolyzer.__main__ import main

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsPublicKeyRequest(TestTlsCases.TestTlsBase, TestMainBase):
    DISTINGUISHED_NAME = OrderedDict([
        ('country_name', 'US'),
        ('state_or_province_name', 'California'),
        ('locality_name', 'San Francisco'),
        ('organization_name', 'BadSSL'),
        ('common_name', 'BadSSL Client Root Certificate Authority'),
    ])

    @classmethod
    def _get_main_func(cls):
        return main

    @classmethod
    def _get_certificate_request_configuration(cls):
        return TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
            certificates=[b'fake certificate'],
            certificate_authorities=[asn1crypto.x509.Name.build(cls.DISTINGUISHED_NAME).dump()],
        )

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME),
    )
    def test_error_tls_alert_unrecognized_name(self, _):
        result = self.get_result('localhost', 0)

        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)
    )
    def test_error_tls_alert_handshake_failure(self, _):
        result = self.get_result('localhost', 0)

        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)

    @mock.patch.object(
        asn1crypto.x509.Name, 'load',
        side_effect=ValueError
    )
    def test_error_distinguished_name_cannot_be_loaded(self, _):
        threaded_server = self.create_server(self._get_certificate_request_configuration())
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.distinguished_names, [])

    @staticmethod
    def get_result(
            host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerPublicKeyRequest()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        analyzer_result = analyzer.analyze(l7_client, protocol_version)

        return analyzer_result

    def test_no_certificate_request(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
            certificates=[b'fake certificate'],
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)

    def test_certificate_request(self):
        threaded_server = self.create_server(self._get_certificate_request_configuration())
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.certificate_types,
            [
                TlsClientCertificateType.RSA_SIGN,
                TlsClientCertificateType.DSS_SIGN,
                TlsClientCertificateType.ECDSA_SIGN,
            ]
        )
        self.assertEqual(result.supported_signature_algorithms, list(TlsSignatureAndHashAlgorithm))
        self.assertEqual(result.distinguished_names, [self.DISTINGUISHED_NAME])
        self.assertEqual(
            self.log_stream.getvalue(),
            'Server requests X.509 for client authentication\n'
        )

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, OFFLINE_L4_SOCKET_PARAMS),
        )
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)

    def test_output(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            '127.0.0.1', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=self._get_certificate_request_configuration(),
        ))
        threaded_server.wait_for_server_listen()
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'pubkeyreq', '127.0.0.1',
            threaded_server.l7_server.l4_transfer.bind_port, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
