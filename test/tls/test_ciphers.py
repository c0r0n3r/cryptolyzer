# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import unittest
from unittest import mock

from test.common.classes import TestMainBase
from test.common.markers import live_server

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

INTERNAL_ERROR_SHOULD_BE_RAISED_ONCE = None


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _wrapped_next_accepted_cipher_suites_internal_error_once(
        l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
        named_curves=None, key_share_curves=None):
    if globals()['INTERNAL_ERROR_SHOULD_BE_RAISED_ONCE'] is None:
        globals()['INTERNAL_ERROR_SHOULD_BE_RAISED_ONCE'] = True
    elif globals()['INTERNAL_ERROR_SHOULD_BE_RAISED_ONCE'] is True:
        globals()['INTERNAL_ERROR_SHOULD_BE_RAISED_ONCE'] = False
        raise TlsAlert(TlsAlertDescription.INTERNAL_ERROR)

    return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
        l7_client,
        protocol_version,
        remaining_cipher_suites,
        accepted_cipher_suites,
        named_curves=named_curves,
        key_share_curves=key_share_curves,
    )


INTERNAL_ERROR_SHOULD_BE_RAISED = False


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _wrapped_next_accepted_cipher_suites_internal_error_multiple(
        l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
        named_curves=None, key_share_curves=None):
    if not globals()['INTERNAL_ERROR_SHOULD_BE_RAISED']:
        globals()['INTERNAL_ERROR_SHOULD_BE_RAISED'] = True
    else:
        raise TlsAlert(TlsAlertDescription.INTERNAL_ERROR)

    return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
        l7_client,
        protocol_version,
        remaining_cipher_suites,
        accepted_cipher_suites,
        named_curves=named_curves,
        key_share_curves=key_share_curves,
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


PROTOCOL_VERSION_SHOULD_BE_RAISED = False


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _wrapped_next_accepted_cipher_suites_protocol_version_mid_scan(
        l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
        named_curves=None, key_share_curves=None):
    if globals()['PROTOCOL_VERSION_SHOULD_BE_RAISED']:
        raise TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    globals()['PROTOCOL_VERSION_SHOULD_BE_RAISED'] = True
    return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
        l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites,
        named_curves=named_curves, key_share_curves=key_share_curves,
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

    @live_server
    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        wraps=_wrapped_next_accepted_cipher_suites_protocol_version_mid_scan
    )
    def test_error_protocol_version_mid_scan(self, _):
        result = self.get_result('rc4.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
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

    @live_server
    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        wraps=_wrapped_next_accepted_cipher_suites_internal_error_once
    )
    @mock.patch('time.sleep', return_value=None)
    def test_error_internal_error_once(self, _, __):
        result = self.get_result('rc4.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(result.cipher_suites, [
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
            TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        ])

    @live_server
    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        wraps=_wrapped_next_accepted_cipher_suites_internal_error_multiple
    )
    @mock.patch('time.sleep', return_value=None)
    def test_error_internal_error_multiple(self, _, __):
        result = self.get_result('rc4.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(result.cipher_suites, [])

    @live_server
    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        wraps=_wrapped_next_accepted_cipher_suites_response_error
    )
    def test_error_response_error_no_response_last_time(self, _):
        result = self.get_result('rc4.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(len(result.cipher_suites), 1)

    @live_server
    def test_long_cipher_suite_list_intolerance(self):
        self.assertFalse(self.get_result('8.8.8.8', 443).long_cipher_suite_list_intolerance)

        threaded_server = L7ServerTlsTest(
            L7ServerTlsLongCipherSuiteListIntolerance('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.long_cipher_suite_list_intolerance)

    @live_server
    def test_cbc(self):
        result = self.get_result('cbc.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))

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

    @live_server
    def test_rc4(self):
        result = self.get_result('rc4.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))

        rc4_block_ciphers = [
            BlockCipher.RC4_40,
            BlockCipher.RC4_128,
        ]

        self.assertTrue(all(
            cipher_suite.value.bulk_cipher in rc4_block_ciphers
            for cipher_suite in result.cipher_suites
        ))

    @live_server
    def test_rc4_md5(self):
        result = self.get_result('rc4-md5.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))

        self.assertEqual(result.cipher_suite_preference, None)
        self.assertEqual(result.cipher_suites, [TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5, ])

    @live_server
    def test_triple_des(self):
        result = self.get_result('3des.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))

        triple_des_block_ciphers = [
            BlockCipher.TRIPLE_DES_168,
            BlockCipher.TRIPLE_DES_EDE,
        ]

        self.assertTrue(all(
            cipher_suite.value.bulk_cipher in triple_des_block_ciphers
            for cipher_suite in result.cipher_suites
        ))

    @live_server
    def test_anon(self):
        result = self.get_result('null.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))

        self.assertTrue(all(
            'NULL' in cipher_suite.name or 'anon' in cipher_suite.name
            for cipher_suite in result.cipher_suites
        ))

    @live_server
    def test_rsa(self):
        result = self.get_result('static-rsa.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))

        self.assertTrue(all(
            cipher_suite.value.authentication == Authentication.RSA
            for cipher_suite in result.cipher_suites
        ))

    @live_server
    def test_tls_1_3(self):
        self.assertEqual(
            self.get_result('www.cloudflare.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3)).cipher_suites,
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

    @live_server
    def test_json(self):
        result = self.get_result('mozill.old.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertTrue(result)

    @live_server
    def test_output(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1), 'ciphers', 'rc4-md5.badssl.com', 443, timeout=10, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
