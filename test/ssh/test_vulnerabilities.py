# -*- coding: utf-8 -*-

from cryptodatahub.ssh.algorithm import SshKexAlgorithm, SshEncryptionAlgorithm, SshMacAlgorithm

from cryptoparser.common.base import Serializable, SerializableTextEncoder

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.common.utils import SerializableTextEncoderHighlighted

from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.vulnerabilities import (
    AnalyzerResultVulnerabilities,
    AnalyzerResultVulnerabilityAlgorithms,
    AnalyzerResultVulnerabilityDHParams,
    AnalyzerResultVulnerabilityVersions,
    AnalyzerVulnerabilities,
)

from .classes import TestSshCases


class TestSshVulnerabilities(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, l4_socket_params=L4TransferSocketParams(), ip=None):
        analyzer = AnalyzerVulnerabilities()
        l7_client = L7ClientSsh.from_scheme('ssh', host, port, l4_socket_params, ip)
        analyzer_result = analyzer.analyze(l7_client)

        return analyzer_result

    def _check_kex_params(self, algorithms, log_stream):
        for algorithm in algorithms:
            self.assertIn(
                'Server offers well-known DH public parameter with size '
                f'{algorithm.value.key_size}-bit ({algorithm.value.code})',
                log_stream
            )

    def _check_gex_params(self, key_sizes, log_stream):
        for key_size in key_sizes:
            self.assertIn(f'Server offers custom DH public parameter with size {key_size}-bit', log_stream)

    def test_algorithms(self):
        # Vulnerable algorithms are aprotected by strict KEX

        algorithms_result = AnalyzerResultVulnerabilityAlgorithms.from_ssh_algorithms(
            kex_algorithms=[],
            strict_kex_enabled=True,
            encryption_algorithms=[SshEncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM],
            mac_algorithms=[],
        )
        self.assertFalse(algorithms_result.terrapin.value)

        algorithms_result = AnalyzerResultVulnerabilityAlgorithms.from_ssh_algorithms(
            kex_algorithms=[],
            strict_kex_enabled=True,
            encryption_algorithms=[SshEncryptionAlgorithm.AES256_CBC],
            mac_algorithms=[SshMacAlgorithm.HMAC_SHA2_256_ETM_OPENSSH_COM],
        )
        self.assertFalse(algorithms_result.terrapin.value)

        # Vulnerable algorithms can be exploited without strict KEX

        algorithms_result = AnalyzerResultVulnerabilityAlgorithms.from_ssh_algorithms(
            kex_algorithms=[],
            strict_kex_enabled=False,
            encryption_algorithms=[SshEncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM],
            mac_algorithms=[],
        )
        self.assertTrue(algorithms_result.terrapin.value)

        algorithms_result = AnalyzerResultVulnerabilityAlgorithms.from_ssh_algorithms(
            kex_algorithms=[],
            strict_kex_enabled=False,
            encryption_algorithms=[SshEncryptionAlgorithm.AES256_CBC],
            mac_algorithms=[SshMacAlgorithm.HMAC_SHA2_256_ETM_OPENSSH_COM],
        )
        self.assertTrue(algorithms_result.terrapin.value)

        # Not vulnerable algorithms cannot be exploited independently from strict KEX

        algorithms_result = AnalyzerResultVulnerabilityAlgorithms.from_ssh_algorithms(
            kex_algorithms=[],
            strict_kex_enabled=False,
            encryption_algorithms=[SshEncryptionAlgorithm.AES256_CTR],
            mac_algorithms=[SshMacAlgorithm.HMAC_SHA2_256_ETM_OPENSSH_COM],
        )
        self.assertFalse(algorithms_result.terrapin.value)

        algorithms_result = AnalyzerResultVulnerabilityAlgorithms.from_ssh_algorithms(
            kex_algorithms=[],
            strict_kex_enabled=False,
            encryption_algorithms=[SshEncryptionAlgorithm.AES256_CBC],
            mac_algorithms=[SshMacAlgorithm.HMAC_SHA2_256],
        )
        self.assertFalse(algorithms_result.terrapin.value)

    def test_output(self):
        result = AnalyzerResultVulnerabilities(
            target=None,
            algorithms=AnalyzerResultVulnerabilityAlgorithms(
                sweet32=True,
                anonymous_dh=True,
                rc4=True,
                non_forward_secret=True,
                null_encryption=True,
                terrapin=True,
            ),
            dhparams=AnalyzerResultVulnerabilityDHParams(
                dheat=True,
                weak_dh=True,
            ),
            versions=AnalyzerResultVulnerabilityVersions(
                early_ssh_version=True,
            ),
        )
        self.assertTrue(result.as_json())
        self.assertTrue(result.as_markdown())
        Serializable.post_text_encoder = SerializableTextEncoderHighlighted()
        self.assertTrue(result.as_markdown())
        Serializable.post_text_encoder = SerializableTextEncoder()

        result = AnalyzerResultVulnerabilities(
            target=None,
            algorithms=AnalyzerResultVulnerabilityAlgorithms(
                sweet32=False,
                anonymous_dh=False,
                rc4=False,
                non_forward_secret=False,
                null_encryption=False,
                terrapin=False,
            ),
            dhparams=AnalyzerResultVulnerabilityDHParams(
                dheat=False,
                weak_dh=False,
            ),
            versions=AnalyzerResultVulnerabilityVersions(
                early_ssh_version=False,
            ),
        )
        self.assertTrue(result.as_json())
        self.assertTrue(result.as_markdown())
        Serializable.post_text_encoder = SerializableTextEncoderHighlighted()
        self.assertTrue(result.as_markdown())
        Serializable.post_text_encoder = SerializableTextEncoder()

    def test_real(self):
        result = self.get_result('gitlab.com', 22)
        self.assertFalse(result.algorithms.sweet32.value)
        self.assertFalse(result.algorithms.anonymous_dh.value)
        self.assertFalse(result.algorithms.null_encryption.value)
        self.assertFalse(result.algorithms.rc4.value)
        self.assertFalse(result.algorithms.non_forward_secret.value)

        self.assertFalse(result.versions.early_ssh_version.value)

        self.assertFalse(result.dhparams.weak_dh.value)
        self.assertFalse(result.dhparams.dheat.value)

        log_stream = '\n'.join(self.pop_log_lines())
        self._check_kex_params([
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256,
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA1,
        ], log_stream)

        result = self.get_result('github.com', 22)
        self.assertFalse(result.algorithms.sweet32.value)
        self.assertFalse(result.algorithms.anonymous_dh.value)
        self.assertFalse(result.algorithms.null_encryption.value)
        self.assertFalse(result.algorithms.rc4.value)
        self.assertFalse(result.algorithms.non_forward_secret.value)

        self.assertFalse(result.versions.early_ssh_version.value)

        self.assertFalse(result.dhparams.weak_dh.value)
        self.assertTrue(result.dhparams.dheat.value)

        log_stream = '\n'.join(self.pop_log_lines())
        self._check_gex_params([2048, 3072, 4096, 6144, 8192], log_stream)
