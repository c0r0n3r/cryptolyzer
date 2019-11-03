#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.extension import TlsSignatureAndHashAlgorithm

from cryptolyzer.tls.client import L7ClientTlsBase, TlsAlert
from cryptolyzer.common.exception import ResponseError, ResponseErrorType
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos

from .classes import TestTlsCases


class TestTlsSigAlgos(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2), timeout=None):
        analyzer = AnalyzerSigAlgos()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    )
    def test_error_tls_alert_protocol_version(self, _):
        result = self.get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.sig_algos, [])

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=[
            mock.DEFAULT,
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
            ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE),
        ]
    )
    def test_error_response_error_no_response(self, _):
        result = self.get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.sig_algos, [
            TlsSignatureAndHashAlgorithm.DSA_NONE,
        ])

    def test_sigalgos(self):
        result = self.get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.sig_algos, [
            TlsSignatureAndHashAlgorithm.ECDSA_SHA1,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA224,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA384,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA512,
        ])

    def test_plain_text_response(self):
        protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        self.assertEqual(self.get_result('ptt.cc', 443, protocol_version).sig_algos, [])
        self.assertEqual(self.get_result('cplusplus.com', 443, protocol_version).sig_algos, [])

    def test_json(self):
        result = self.get_result('ecc256.badssl.com', 443)
        self.assertTrue(result)
