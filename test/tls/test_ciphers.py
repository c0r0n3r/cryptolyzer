# -*- coding: utf-8 -*-

import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.common.algorithm import Authentication, BlockCipher
from cryptoparser.tls.subprotocol import TlsAlertDescription

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.common.exception import ResponseError, ResponseErrorType
from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
from cryptolyzer.tls.client import L7ClientTlsBase, TlsAlert

from .classes import TestTlsCases


class TestSslCiphers(unittest.TestCase):
    @staticmethod
    def get_result(host, port):
        analyzer = AnalyzerCipherSuites()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, SslProtocolVersion())
        return result

    def test_ciphers(self):
        result = self.get_result('164.100.148.73', 443)

        self.assertEqual(result.cipher_suite_preference, True)
        self.assertEqual(
            result.cipher_suites,
            [
                SslCipherKind.RC4_128_WITH_MD5,
                SslCipherKind.DES_192_EDE3_CBC_WITH_MD5,
            ]
        )

    def test_json(self):
        result = self.get_result('164.100.148.73', 443)
        self.assertTrue(result)


ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES = \
    AnalyzerCipherSuites._next_accepted_cipher_suites  # pylint: disable=protected-access

INTERNAL_ERROR_ALREADY_RAISED = False


def _wrapped_next_accepted_cipher_suites_internal_error_once(
        l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites):
    if not globals()['INTERNAL_ERROR_ALREADY_RAISED']:
        globals()['INTERNAL_ERROR_ALREADY_RAISED'] = True
        raise TlsAlert(TlsAlertDescription.INTERNAL_ERROR)

    return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
        l7_client,
        protocol_version,
        remaining_cipher_suites,
        accepted_cipher_suites
    )


def _wrapped_next_accepted_cipher_suites_response_error(
        l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites):
    if len(accepted_cipher_suites) == 1:
        raise ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE)

    return ORIGINAL_NEXT_ACCEPTED_CIPHER_SUITES(
        l7_client,
        protocol_version,
        remaining_cipher_suites,
        accepted_cipher_suites
    )


class TestTlsCiphers(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0), timeout=None):
        analyzer = AnalyzerCipherSuites()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    )
    @mock.patch.object(
        AnalyzerCipherSuites, '_get_accepted_cipher_suites_fallback',
        return_value=[]
    )
    def test_error_protocol_version(self, mocked_next_accepted_cipher_suites, _):
        result = self.get_result('rc4.badssl.com', 443)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 1)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.INTERNAL_ERROR)
    )
    def test_error_internal_error(self, mocked_next_accepted_cipher_suites):
        with self.assertRaises(TlsAlert) as context_manager:
            self.get_result('badssl.com', 443)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.INTERNAL_ERROR)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 2)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.INSUFFICIENT_SECURITY)
    )
    def test_error_insufficient_security(self, mocked_next_accepted_cipher_suites):
        result = self.get_result('rc4.badssl.com', 443)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 4)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        side_effect=TlsAlert(TlsAlertDescription.ILLEGAL_PARAMETER)
    )
    def test_error_illegal_parameter(self, mocked_next_accepted_cipher_suites):
        result = self.get_result('rc4.badssl.com', 443)
        self.assertEqual(len(result.cipher_suites), 0)
        self.assertEqual(mocked_next_accepted_cipher_suites.call_count, 4)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        wraps=_wrapped_next_accepted_cipher_suites_internal_error_once
    )
    @mock.patch('time.sleep', return_value=None)
    def test_error_internal_error_once(self, _, __):
        result = self.get_result('rc4.badssl.com', 443)
        self.assertEqual(len(result.cipher_suites), 2)

    @mock.patch.object(
        AnalyzerCipherSuites, '_next_accepted_cipher_suites',
        wraps=_wrapped_next_accepted_cipher_suites_response_error
    )
    def test_error_response_error_no_response_last_time(self, _):
        result = self.get_result('rc4.badssl.com', 443)
        self.assertEqual(len(result.cipher_suites), 1)

    @mock.patch.object(
        AnalyzerCipherSuites, '_get_accepted_cipher_suites_all',
        return_value=(TlsCipherSuite, TlsCipherSuite)
    )
    def test_long_cipher_suite_list_intolerance(self, _):
        result = self.get_result('rc4.badssl.com', 443)

        rc4_block_ciphers = [
            BlockCipher.RC4_40,
            BlockCipher.RC4_128,
        ]

        self.assertTrue(all([
            cipher_suite.value.bulk_cipher in rc4_block_ciphers
            for cipher_suite in result.cipher_suites
        ]))
        self.assertTrue(result.long_cipher_suite_list_intolerance)

    def test_cbc(self):
        result = self.get_result('cbc.badssl.com', 443)

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

    def test_rc4(self):
        result = self.get_result('rc4.badssl.com', 443)

        rc4_block_ciphers = [
            BlockCipher.RC4_40,
            BlockCipher.RC4_128,
        ]

        self.assertTrue(all([
            cipher_suite.value.bulk_cipher in rc4_block_ciphers
            for cipher_suite in result.cipher_suites
        ]))

    def test_rc4_md5(self):
        result = self.get_result('rc4-md5.badssl.com', 443)

        self.assertEqual(result.cipher_suite_preference, None)
        self.assertEqual(result.cipher_suites, [TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5, ])

    def test_triple_des(self):
        result = self.get_result('3des.badssl.com', 443)

        triple_des_block_ciphers = [
            BlockCipher.TRIPLE_DES,
            BlockCipher.TRIPLE_DES_EDE,
        ]

        self.assertTrue(all([
            cipher_suite.value.bulk_cipher in triple_des_block_ciphers
            for cipher_suite in result.cipher_suites
        ]))

    def test_anon(self):
        result = self.get_result('null.badssl.com', 443)

        self.assertTrue(all([
            'NULL' in cipher_suite.name or 'anon' in cipher_suite.name
            for cipher_suite in result.cipher_suites
        ]))

    def test_rsa(self):
        result = self.get_result('static-rsa.badssl.com', 443)

        self.assertTrue(all([
            cipher_suite.value.authentication == Authentication.RSA
            for cipher_suite in result.cipher_suites
        ]))

    def test_plain_text_response(self):
        self.assertEqual(self.get_result('ptt.cc', 443).cipher_suites, [])
        self.assertEqual(self.get_result('cplusplus.com', 443).cipher_suites, [])

    def test_json(self):
        result = self.get_result('mozill.old.badssl.com', 443)
        self.assertTrue(result)
