# SPDX-License-Identifier: MPL-2.0

import unittest

from test.common.classes import OFFLINE_CLIENT_L4_SOCKET_PARAMS, OFFLINE_L4_SOCKET_PARAMS

from cryptodatahub.common.parameter import DHParamWellKnown
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration
from cryptolyzer.tls.vulnerabilities import AnalyzerResultVulnerabilityCiphers, AnalyzerVulnerabilities

from .classes import TestTlsCases, L7ServerTlsTest


class TestTlsVulnerabilityCiphers(unittest.TestCase):
    def test_freak_rsa_export(self):
        result = AnalyzerResultVulnerabilityCiphers.from_cipher_suites([
            TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
        ])
        self.assertTrue(result.freak.value)
        self.assertTrue(result.export_grade.value)

    def test_no_freak_rsa(self):
        result = AnalyzerResultVulnerabilityCiphers.from_cipher_suites([
            TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        ])
        self.assertFalse(result.freak.value)
        self.assertFalse(result.export_grade.value)

    def test_no_freak_dhe_export(self):
        result = AnalyzerResultVulnerabilityCiphers.from_cipher_suites([
            TlsCipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
        ])
        self.assertFalse(result.freak.value)
        self.assertTrue(result.export_grade.value)

    def test_logjam_dhe_export(self):
        result = AnalyzerResultVulnerabilityCiphers.from_cipher_suites([
            TlsCipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
        ])
        self.assertTrue(result.logjam.value)
        self.assertTrue(result.export_grade.value)

    def test_no_logjam_dhe(self):
        result = AnalyzerResultVulnerabilityCiphers.from_cipher_suites([
            TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        ])
        self.assertFalse(result.logjam.value)
        self.assertFalse(result.export_grade.value)

    def test_no_logjam_rsa_export(self):
        result = AnalyzerResultVulnerabilityCiphers.from_cipher_suites([
            TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
        ])
        self.assertFalse(result.logjam.value)
        self.assertTrue(result.freak.value)


class TestTlsVulnerabilities(TestTlsCases.TestTlsBase):
    def _check_cipher_suite_logs(self, cipher_suites, log_stream):
        for cipher_suite in cipher_suites:
            self.assertIn(f'Server offers cipher suite {cipher_suite.name}', log_stream)

    @staticmethod
    def get_result(
            host, port, protocol_version=None, l4_socket_params=OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerVulnerabilities()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        analyzer_result = analyzer.analyze(l7_client, None)

        return analyzer_result

    @staticmethod
    def create_server(configuration=None):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0, OFFLINE_L4_SOCKET_PARAMS, configuration=configuration
        ))
        threaded_server.wait_for_server_listen()
        return threaded_server

    def test_real_versions(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.SSL3),
            cipher_suites=[
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            ],
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.ciphers.lucky13.value)
        self.assertFalse(result.ciphers.sweet32.value)
        self.assertFalse(result.ciphers.freak.value)
        self.assertFalse(result.ciphers.anonymous_dh.value)
        self.assertFalse(result.ciphers.null_encryption.value)
        self.assertTrue(result.ciphers.rc4.value)
        self.assertTrue(result.ciphers.non_forward_secret.value)
        self.assertFalse(result.ciphers.export_grade.value)

        self.assertFalse(result.versions.drown.value)
        self.assertTrue(result.versions.early_tls_version.value)
        self.assertTrue(result.versions.ssl_version.value)

        self.assertFalse(result.dhparams.weak_dh.value)
        self.assertFalse(result.dhparams.dheat.value)

    def test_real_ciphers(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            cipher_suites=[
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
            ],
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.ciphers.lucky13.value)
        self.assertFalse(result.ciphers.sweet32.value)
        self.assertFalse(result.ciphers.freak.value)
        self.assertFalse(result.ciphers.anonymous_dh.value)
        self.assertFalse(result.ciphers.null_encryption.value)
        self.assertTrue(result.ciphers.rc4.value)
        self.assertTrue(result.ciphers.non_forward_secret.value)
        self.assertFalse(result.ciphers.export_grade.value)

        self.assertFalse(result.versions.drown.value)
        self.assertTrue(result.versions.early_tls_version.value)
        self.assertFalse(result.versions.ssl_version.value)

        self.assertFalse(result.dhparams.weak_dh.value)
        self.assertFalse(result.dhparams.dheat.value)

        log_stream = '\n'.join(self.pop_log_lines())
        self._check_cipher_suite_logs([
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
            TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        ], log_stream)
        self.assertNotIn('Server offers well-known DH public parameter', log_stream)

        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            cipher_suites=[
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            ],
            dh_param=DHParamWellKnown.APPLICATION_SERVER_NGINX_VERSION_0_7_2_BIT_1024,
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.ciphers.lucky13.value)
        self.assertTrue(result.ciphers.sweet32.value)
        self.assertFalse(result.ciphers.freak.value)
        self.assertFalse(result.ciphers.anonymous_dh.value)
        self.assertFalse(result.ciphers.null_encryption.value)
        self.assertFalse(result.ciphers.rc4.value)
        self.assertTrue(result.ciphers.non_forward_secret.value)
        self.assertFalse(result.ciphers.export_grade.value)

        self.assertFalse(result.versions.drown.value)
        self.assertTrue(result.versions.early_tls_version.value)
        self.assertFalse(result.versions.ssl_version.value)

        self.assertTrue(result.dhparams.weak_dh.value)
        self.assertFalse(result.dhparams.dheat.value)

        log_stream = '\n'.join(self.pop_log_lines())
        self._check_cipher_suite_logs([
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TlsCipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ], log_stream)
        self.assertIn('Server offers 1024-bit NGINX 0.7.2 builtin DH parameter', log_stream)

    def test_real_dhparams(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            min_protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            cipher_suites=[
                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            ],
            dh_param=DHParamWellKnown.RFC3526_8192_BIT_MODP_GROUP,
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.ciphers.lucky13.value)
        self.assertFalse(result.ciphers.sweet32.value)
        self.assertFalse(result.ciphers.freak.value)
        self.assertFalse(result.ciphers.anonymous_dh.value)
        self.assertFalse(result.ciphers.null_encryption.value)
        self.assertFalse(result.ciphers.rc4.value)
        self.assertFalse(result.ciphers.non_forward_secret.value)
        self.assertFalse(result.ciphers.export_grade.value)

        self.assertFalse(result.versions.drown.value)
        self.assertFalse(result.versions.early_tls_version.value)
        self.assertFalse(result.versions.ssl_version.value)

        self.assertFalse(result.dhparams.weak_dh.value)
        self.assertTrue(result.dhparams.dheat.value)
