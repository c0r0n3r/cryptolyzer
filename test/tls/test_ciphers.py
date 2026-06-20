# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import unittest
from unittest import mock

from test.common.classes import TestMainBase

from cryptodatahub.common.algorithm import Authentication, BlockCipher

from cryptoparser.tls.subprotocol import TlsAlertDescription

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration

from cryptolyzer.__main__ import main

from .classes import (
    L7ServerTlsLongCipherSuiteListIntolerance,
    L7ServerTlsPlainTextResponse,
    L7ServerTlsTest,
    TestTlsCases,
)


class TestSslCiphers(unittest.TestCase):
    def setUp(self):
        self.threaded_server = self.create_server()

    @staticmethod
    def create_server():
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0,
            L4TransferSocketParams(timeout=0.5),
            configuration=TlsServerConfiguration(fallback_to_ssl=True)
        ))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @staticmethod
    def get_result(
            host,
            port,
            protocol_version=TlsProtocolVersion(TlsVersion.SSL2),
            l4_socket_params=L4TransferSocketParams(),
            ip=None,
            scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerCipherSuites()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    def test_ciphers(self):
        result = self.get_result('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)

        self.assertEqual(result.cipher_suite_preference, True)
        self.assertEqual(result.cipher_suites, list(SslCipherKind))

    def test_json(self):
        result = self.get_result('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result)


ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES = (  # pylint: disable=protected-access
    AnalyzerCipherSuites._next_accepted_cipher_suites  # pylint: disable=protected-access
)


class _ProtocolVersionMidScanWrapper:
    def __init__(self):
        self._should_raise = False

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __call__(self, l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
                 named_curves=None, key_share_curves=None):
        if self._should_raise:
            raise TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
        self._should_raise = True
        return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
            l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
            named_curves=named_curves, key_share_curves=key_share_curves,
        )


class _InternalErrorOnceWrapper:
    def __init__(self):
        self._state = None

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __call__(self, l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
                 named_curves=None, key_share_curves=None):
        if self._state is None:
            self._state = True
        elif self._state is True:
            self._state = False
            raise TlsAlert(TlsAlertDescription.INTERNAL_ERROR)
        return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
            l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
            named_curves=named_curves, key_share_curves=key_share_curves,
        )


class _InternalErrorMultipleWrapper:
    def __init__(self):
        self._should_raise = False

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __call__(self, l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
                 named_curves=None, key_share_curves=None):
        if not self._should_raise:
            self._should_raise = True
        else:
            raise TlsAlert(TlsAlertDescription.INTERNAL_ERROR)
        return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
            l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
            named_curves=named_curves, key_share_curves=key_share_curves,
        )


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _wrapped_next_accepted_cipher_suites_response_error(
        l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
        named_curves=None, key_share_curves=None):
    if len(accepted_cipher_suites) == 1:
        raise SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)

    return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
        l7_client,
        protocol_version,
        remaining_cipher_suites,
        accepted_cipher_suites,
        named_curves=named_curves,
        key_share_curves=key_share_curves,
    )


class TestTlsCiphers(TestTlsCases.TestTlsBase, TestMainBase):  # pylint: disable=too-many-public-methods
    @classmethod
    def _get_main_func(cls):
        return main

    @staticmethod
    def get_result(
            host,
            port,
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            l4_socket_params=L4TransferSocketParams(),
            ip=None,
            scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerCipherSuites()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.DECODE_ERROR),
    )
    @mock.patch.object(
        AnalyzerCipherSuites, '_get_accepted_cipher_suites_fallback',
        return_value=[]
    )
    def test_error_decode_error(self, mocked_next_accepted_cipher_suites, _):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 1)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME),
    )
    @mock.patch.object(
        AnalyzerCipherSuites, '_get_accepted_cipher_suites_fallback',
        return_value=[]
    )
    def test_error_unrecognized_name(self, mocked_fallback, _):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_fallback.call_count, 0)

    def test_error_protocol_version_mid_scan(self):
        threaded_server = self.create_server()
        with mock.patch.object(AnalyzerCipherSuites, '_next_accepted_cipher_suites',
                               wraps=_ProtocolVersionMidScanWrapper()):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.cipher_suites), 1)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.INTERNAL_ERROR)
    )
    def test_error_internal_error(self, mocked_next_accepted_cipher_suites):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 6)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.INSUFFICIENT_SECURITY)
    )
    def test_error_insufficient_security(self, mocked_next_accepted_cipher_suites):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 6)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.ILLEGAL_PARAMETER)
    )
    def test_error_illegal_parameter(self, mocked_next_accepted_cipher_suites):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 6)

    @mock.patch('time.sleep', return_value=None)
    def test_error_internal_error_once(self, _):
        threaded_server = self.create_server()
        with mock.patch.object(AnalyzerCipherSuites, '_next_accepted_cipher_suites',
                               wraps=_InternalErrorOnceWrapper()):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.cipher_suites, [TlsCipherSuite.TLS_RSA_WITH_RC2_CBC_MD5])

    @mock.patch('time.sleep', return_value=None)
    def test_error_internal_error_multiple(self, _):
        threaded_server = self.create_server()
        with mock.patch.object(AnalyzerCipherSuites, '_next_accepted_cipher_suites',
                               wraps=_InternalErrorMultipleWrapper()):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.cipher_suites, [])

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        wraps=_wrapped_next_accepted_cipher_suites_response_error
    )
    def test_error_response_error_no_response_last_time(self, _):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.cipher_suites), 1)

    def test_long_cipher_suite_list_intolerance(self):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.long_cipher_suite_list_intolerance)

        threaded_server = L7ServerTlsTest(
            L7ServerTlsLongCipherSuiteListIntolerance('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.long_cipher_suite_list_intolerance)

    def test_cbc(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertEqual(result.cipher_suite_preference, True)
        self.assertEqual(
            result.cipher_suites,
            [
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            ]
        )
        self.assertEqual(
            self.get_log_lines(), [
                'Server offers cipher suite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (TLS 1.0)',
                'Server offers cipher suite TLS_DHE_RSA_WITH_AES_256_CBC_SHA (TLS 1.0)',
                'Server offers cipher suite TLS_RSA_WITH_AES_256_CBC_SHA (TLS 1.0)',
                'Server offers cipher suite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (TLS 1.0)',
                'Server offers cipher suite TLS_DHE_RSA_WITH_AES_128_CBC_SHA (TLS 1.0)',
                'Server offers cipher suite TLS_RSA_WITH_AES_128_CBC_SHA (TLS 1.0)',
            ]
        )

    def test_rc4(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[
                TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        rc4_block_ciphers = [
            BlockCipher.RC4_40,
            BlockCipher.RC4_128,
        ]

        self.assertTrue(all(
            cipher_suite.value.bulk_cipher in rc4_block_ciphers
            for cipher_suite in result.cipher_suites
        ))

    def test_rc4_md5(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertEqual(result.cipher_suite_preference, None)
        self.assertEqual(result.cipher_suites, [TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5])

    def test_triple_des(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[
                TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        triple_des_block_ciphers = [
            BlockCipher.TRIPLE_DES_168,
            BlockCipher.TRIPLE_DES_EDE,
        ]

        self.assertTrue(all(
            cipher_suite.value.bulk_cipher in triple_des_block_ciphers
            for cipher_suite in result.cipher_suites
        ))

    def test_anon(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[
                TlsCipherSuite.TLS_NULL_WITH_NULL_NULL,
                TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertTrue(all(
            'NULL' in cipher_suite.name or 'anon' in cipher_suite.name
            for cipher_suite in result.cipher_suites
        ))

    def test_rsa(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[
                TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5,
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertTrue(all(
            cipher_suite.value.authentication == Authentication.RSA
            for cipher_suite in result.cipher_suites
        ))

    def test_tls_1_3(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[
                TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            ]
        ))
        self.assertEqual(
            self.get_result(
                'localhost', threaded_server.l7_server.l4_transfer.bind_port,
                TlsProtocolVersion(TlsVersion.TLS1_3)
            ).cipher_suites,
            [
                TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            ]
        )

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()
        self.assertEqual(
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).cipher_suites, []
        )

    def test_json(self):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result)

    def test_output(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            '127.0.0.1', 0,
            L4TransferSocketParams(timeout=5.0),
            configuration=TlsServerConfiguration(cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5])
        ))
        threaded_server.wait_for_server_listen()
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1), 'ciphers', '127.0.0.1',
            threaded_server.l7_server.l4_transfer.bind_port, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
