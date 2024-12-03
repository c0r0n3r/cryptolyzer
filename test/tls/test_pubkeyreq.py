# -*- coding: utf-8 -*-

from unittest import mock

from collections import OrderedDict

import asn1crypto.x509

from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.pubkeyreq import AnalyzerPublicKeyRequest

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsPublicKeyRequest(TestTlsCases.TestTlsBase):
    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME),
    )
    def test_error_tls_alert_unrecognized_name(self, _):
        result = self.get_result('badssl.com', 443)

        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)
    )
    def test_error_tls_alert_handshake_failure(self, _):
        result = self.get_result('badssl.com', 443)

        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)

    @mock.patch.object(
        asn1crypto.x509.Name, 'load',
        side_effect=ValueError
    )
    def test_error_distinguished_name_cannot_be_loaded(self, _):
        result = self.get_result('client.badssl.com', 443)
        self.assertEqual(result.distinguished_names, [])

    @staticmethod
    def get_result(
            host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=L4TransferSocketParams(), ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerPublicKeyRequest()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port)
        analyzer_result = analyzer.analyze(l7_client, protocol_version)

        return analyzer_result

    def test_real_server(self):
        result = self.get_result('badssl.com', 443)
        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)

        result = self.get_result('client.badssl.com', 443)
        self.assertEqual(
            result.distinguished_names,
            [
                OrderedDict([
                    ('country_name', 'US'),
                    ('state_or_province_name', 'California'),
                    ('locality_name', 'San Francisco'),
                    ('organization_name', 'BadSSL'),
                    ('common_name', 'BadSSL Client Root Certificate Authority')
                ])
            ]
        )
        self.assertEqual(
            self.log_stream.getvalue(),
            'Server requests X.509 for client authentication\n'
        )

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.certificate_types, None)
        self.assertEqual(result.supported_signature_algorithms, None)
        self.assertEqual(result.distinguished_names, None)
