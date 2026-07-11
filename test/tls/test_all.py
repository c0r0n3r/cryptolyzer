# SPDX-License-Identifier: MPL-2.0

from unittest import mock

from collections import OrderedDict

from test.common.classes import OFFLINE_CLIENT_L4_SOCKET_PARAMS, OFFLINE_L4_SOCKET_PARAMS, TestMainBase

import test.tls.test_ciphers
from test.common.markers import live_server

from cryptodatahub.common.parameter import DHParamWellKnown

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsNamedCurve
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.result import AnalyzerTargetTls

from cryptolyzer.tls.all import AnalyzerAll
from cryptolyzer.tls.ciphers import AnalyzerResultCipherSuites
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration

from cryptolyzer.__main__ import main

from .classes import TestTlsCases, L7ServerTlsTest


class TestTlsAll(TestTlsCases.TestTlsBase, TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    @staticmethod
    def create_server(configuration=None):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0, OFFLINE_L4_SOCKET_PARAMS, configuration=configuration
        ))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @staticmethod
    def get_result(
            host,
            port,
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            l4_socket_params=OFFLINE_CLIENT_L4_SOCKET_PARAMS,
            ip=None,
            scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerAll()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    def test_is_ecdhe_supported(self):
        target = AnalyzerTargetTls('tls', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_ecdhe_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), None)

        self.assertEqual(AnalyzerAll.is_ecdhe_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
                ], False, False)
            ),
        ])), TlsProtocolVersion(TlsVersion.TLS1_2))

    def test_is_public_key_supported(self):
        target = AnalyzerTargetTls('tls', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_public_key_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), None)

        self.assertEqual(AnalyzerAll.is_public_key_supported(OrderedDict([
            (
                TlsProtocolVersion(TlsVersion.TLS1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_1),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
            (
                TlsProtocolVersion(TlsVersion.TLS1_2),
                AnalyzerResultCipherSuites(target, [
                    TlsCipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                ], False, False)
            ),
        ])), TlsProtocolVersion(TlsVersion.TLS1_1))

    def test_real(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
            dh_param=DHParamWellKnown.APPLICATION_SERVER_NGINX_VERSION_0_7_2_BIT_1024,
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.dhparams.groups, [])
        self.assertNotEqual(result.dhparams.dhparam, None)
        self.assertFalse(result.vulns.ciphers.null_encryption.value)
        self.assertFalse(result.vulns.ciphers.sweet32.value)
        self.assertTrue(result.vulns.dhparams.weak_dh.value)
        self.assertTrue(result.vulns.versions.early_tls_version.value)

        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_1),
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA],
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.vulns.ciphers.rc4.value)
        self.assertFalse(result.vulns.ciphers.null_encryption.value)
        self.assertFalse(result.vulns.ciphers.sweet32.value)
        self.assertFalse(result.vulns.dhparams.weak_dh.value)
        self.assertTrue(result.vulns.versions.early_tls_version.value)

    @live_server
    def test_real_live(self):
        result = self.get_result('documentfreedom.org', 443)
        self.assertEqual(result.dhparams.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ])
        self.assertIsNone(result.dhparams.dhparam)

        result = self.get_result('xenproject.org', 443)
        self.assertTrue(all(map(
            lambda version: version > TlsProtocolVersion(TlsVersion.TLS1_2), result.versions.versions
        )))
        self.assertEqual(set(result.ciphers[-1].cipher_suites), set([
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ]))
        self.assertEqual(result.dhparams.dhparam, None)
        self.assertEqual(result.dhparams.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192
        ])
        self.assertEqual(set(result.curves.curves), set([
            TlsNamedCurve.X25519,
            TlsNamedCurve.SECP256R1,
            TlsNamedCurve.X448,
            TlsNamedCurve.SECP521R1,
            TlsNamedCurve.SECP384R1,
        ]))

        result = self.get_result('pq.cloudflareresearch.com', 443)
        self.assertTrue(all(map(
            lambda version: version >= TlsProtocolVersion(TlsVersion.TLS1), result.versions.versions
        )))
        self.assertEqual(set(result.ciphers[-1].cipher_suites), set([
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ]))
        self.assertEqual(result.dhparams, None)
        curves = result.curves.curves
        # different instances run with different configuration, the following is the common subset
        self.assertIn(TlsNamedCurve.X25519_KYBER_768_R3, curves)
        self.assertIn(TlsNamedCurve.X25519, curves)
        self.assertIn(TlsNamedCurve.SECP256R1, curves)

    def test_markdown(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        markdown_result = result.as_markdown()

        target_index = markdown_result.find('Target')
        self.assertNotEqual(target_index, -1)
        target_index = markdown_result.find('Target', target_index + 1)
        self.assertEqual(target_index, -1)

    def test_missing_parts(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
        ))
        with mock.patch.object(AnalyzerAll, 'is_public_key_supported', return_value=None):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertEqual(result.curves, None)
        self.assertEqual(result.dhparams, None)
        self.assertEqual(result.pubkeys, None)
        self.assertNotEqual(result.ciphers, None)
        self.assertNotEqual(result.pubkeyreq, None)
        self.assertNotEqual(result.versions, None)

        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            max_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
            dh_param=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.sigalgos, None)
        self.assertNotEqual(result.ciphers, None)
        self.assertNotEqual(result.dhparams, None)
        self.assertNotEqual(result.pubkeys, None)
        self.assertNotEqual(result.pubkeyreq, None)
        self.assertNotEqual(result.versions, None)

    def test_output(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            '127.0.0.1', 0, OFFLINE_L4_SOCKET_PARAMS, configuration=TlsServerConfiguration(
                min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
                cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
            )
        ))
        threaded_server.wait_for_server_listen()
        port = threaded_server.l7_server.l4_transfer.bind_port
        func_arguments, cli_arguments = self._get_arguments(
            'tls', 'all', '127.0.0.1', port, timeout=30, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')

        ciphers_func_arguments, _ = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1), 'ciphers', '127.0.0.1', port, timeout=30, scheme='tls'
        )
        ciphers_result = test.tls.test_ciphers.TestTlsCiphers.get_result(**ciphers_func_arguments)
        ciphers_markdown = ciphers_result._as_markdown_without_target(  # pylint: disable=protected-access
            ciphers_result, 0
        )
        self.assertTrue(ciphers_markdown in result.as_markdown())
