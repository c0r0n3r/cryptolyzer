# -*- coding: utf-8 -*-

from cryptodatahub.tls.algorithm import TlsNamedCurve
from cryptoparser.tls.ciphersuite import TlsCipherSuite

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.vulnerabilities import AnalyzerVulnerabilities

from .classes import TestTlsCases


class TestTlsVulnerabilities(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(
            host, port, protocol_version=None, l4_socket_params=L4TransferSocketParams(), ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerVulnerabilities()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        analyzer_result = analyzer.analyze(l7_client, None)

        return analyzer_result

    def _check_cipher_suite_logs(self, cipher_suites, log_stream):
        for cipher_suite in cipher_suites:
            self.assertIn(f'Server offers cipher suite {cipher_suite.name}', log_stream)

    def _check_ffdhe_params(self, ffdhe_params, log_stream):
        for ffdhe_param in ffdhe_params:
            self.assertIn(
                f'Server offers FFDHE public parameter with size {ffdhe_param.value.named_group.value.size}-bit',
                log_stream
            )

    def test_real_versions(self):
        result = self.get_result('baidu.com', 443)
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
        result = self.get_result('rc4.badssl.com', 443, L4TransferSocketParams(timeout=10))
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

        result = self.get_result('3des.badssl.com', 443, L4TransferSocketParams(timeout=10))
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
        result = self.get_result('archive.org', 443)
        self.assertTrue(result.ciphers.lucky13.value)
        self.assertFalse(result.ciphers.sweet32.value)
        self.assertFalse(result.ciphers.freak.value)
        self.assertFalse(result.ciphers.anonymous_dh.value)
        self.assertFalse(result.ciphers.null_encryption.value)
        self.assertFalse(result.ciphers.rc4.value)
        self.assertTrue(result.ciphers.non_forward_secret.value)
        self.assertFalse(result.ciphers.export_grade.value)

        self.assertFalse(result.versions.drown.value)
        self.assertFalse(result.versions.early_tls_version.value)
        self.assertFalse(result.versions.ssl_version.value)

        self.assertFalse(result.dhparams.weak_dh.value)
        self.assertTrue(result.dhparams.dheat.value)

        log_stream = '\n'.join(self.pop_log_lines())
        self._check_cipher_suite_logs([
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ], log_stream)
        self._check_ffdhe_params([
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ], log_stream)
