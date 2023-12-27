# -*- coding: utf-8 -*-

import six

import attr

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, MACMode
from cryptodatahub.common.grade import Grade
from cryptodatahub.common.types import convert_value_to_object

from cryptodatahub.ssh.algorithm import SshEncryptionAlgorithm

from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.common.vulnerability import (
    AnalyzerResultVulnerabilityCiphersBase,
    AnalyzerResultVulnerabilityDHParamsBase,
    AnalyzerResultVulnerabilityVersionsBase,
    VulnerabilityResultNullEncryption,
    VulnerabilityResultGraded,
)

from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptolyzer.ssh.dhparams import AnalyzerDHParams
from cryptolyzer.ssh.versions import AnalyzerVersions


@attr.s
class VulnerabilityResultEarlySshVersion(VulnerabilityResultGraded):
    @property
    def _vulnerable_grade(self):
        return Grade.INSECURE

    @classmethod
    def get_name(cls):
        return 'Early SSH version'


@attr.s
class VulnerabilityResultTerrapin(VulnerabilityResultGraded):
    @property
    def _vulnerable_grade(self):
        return Grade.INSECURE

    @classmethod
    def get_name(cls):
        return 'Terrapin Attack'


@attr.s
class AnalyzerResultVulnerabilityAlgorithms(AnalyzerResultVulnerabilityCiphersBase):
    """
    :class: Vulnerabilities relate to cipher suite algorithms. Any attribute represents an vulnerability, which value is
        true if any of the negotiable cipher suite uses an algorithm affected by the vulnerability.
    """

    null_encryption = attr.ib(
        converter=convert_value_to_object(VulnerabilityResultNullEncryption),
        validator=attr.validators.instance_of(VulnerabilityResultNullEncryption),
        metadata={'human_readable_name': VulnerabilityResultNullEncryption.get_name()},
    )
    terrapin = attr.ib(
        converter=convert_value_to_object(VulnerabilityResultTerrapin),
        validator=attr.validators.instance_of(VulnerabilityResultTerrapin),
        metadata={'human_readable_name': VulnerabilityResultTerrapin.get_name()},
    )

    @classmethod
    def from_ssh_algorithms(cls, kex_algorithms, strict_kex_enabled, encryption_algorithms, mac_algorithms):
        bulk_cipher_algorithms = set(map(
            lambda encryption_algorithm: encryption_algorithm.value.cipher, encryption_algorithms
        ))
        key_exchange_algorithms = set(map(lambda kex_algorithm: kex_algorithm.value.kex, kex_algorithms))

        null_encryption = VulnerabilityResultNullEncryption(SshEncryptionAlgorithm.NONE in kex_algorithms)
        terrapin = False
        if not strict_kex_enabled:
            has_chacha20 = BlockCipher.CHACHA20 in bulk_cipher_algorithms
            if has_chacha20:
                terrapin = True
            else:
                has_cbc = any(map(
                    lambda encryption_algorithm: encryption_algorithm.value.mode == BlockCipherMode.CBC,
                    encryption_algorithms
                ))
                has_etm = any(map(
                    lambda mac_algorithm: mac_algorithm.value.mode == MACMode.ENCRYPT_THEN_MAC,
                    mac_algorithms
                ))
                terrapin = has_cbc and has_etm

        vulnerability_ciphers = AnalyzerResultVulnerabilityCiphersBase.from_algorithms(
            key_exchange_algorithms, bulk_cipher_algorithms
        )

        return AnalyzerResultVulnerabilityAlgorithms(
            sweet32=vulnerability_ciphers.sweet32,
            anonymous_dh=vulnerability_ciphers.anonymous_dh,
            rc4=vulnerability_ciphers.rc4,
            non_forward_secret=vulnerability_ciphers.non_forward_secret,
            null_encryption=null_encryption,
            terrapin=terrapin,
        )


@attr.s
class AnalyzerResultVulnerabilityVersions(AnalyzerResultVulnerabilityVersionsBase):
    """
    :class: Vulnerabilities relate to the protocol versions. Any attribute represents a vulnerability, which value is
        true if any of the negotiable protocol versions uses an algorithm affected by the vulnerability.

    :param early_ssh_version: -  `Early (1.x) protocol versions are supported.
    """

    early_ssh_version = attr.ib(
        converter=convert_value_to_object(VulnerabilityResultEarlySshVersion),
        validator=attr.validators.instance_of(VulnerabilityResultEarlySshVersion),
        metadata={'human_readable_name': VulnerabilityResultEarlySshVersion.get_name()},
    )

    @staticmethod
    def from_protocol_versions(protocol_versions):
        early_ssh_version = VulnerabilityResultEarlySshVersion(any(map(
            lambda protocol_version: (
                isinstance(protocol_version, SshProtocolVersion) and
                protocol_version < SshProtocolVersion(SshVersion.SSH2)
            ),
            protocol_versions
        )))

        return AnalyzerResultVulnerabilityVersions(
            early_ssh_version=early_ssh_version,
        )


@attr.s
class AnalyzerResultVulnerabilityDHParams(AnalyzerResultVulnerabilityDHParamsBase):
    """
    :class: Vulnerabilities relate to the protocol versions. Any attribute represents a vulnerability, which value is
        true if any of the negotiable protocol versions uses an algorithm affected by the vulnerability.
    """


@attr.s
class AnalyzerResultVulnerabilities(AnalyzerResultSsh):  # pylint: disable=too-few-public-methods
    """
    :class: Vulnerabilities relate to the server configuration.

    :param cipher: Cipher suite related vulnerabilities.
    :param dhparam: Diffie-Hellman parameter related vulnerabilities.
    :param versions: Protocol version related vulnerabilities.
    """

    algorithms = attr.ib(
        validator=attr.validators.instance_of(AnalyzerResultVulnerabilityAlgorithms),
        metadata={'human_readable_name': 'Algorithms'},
    )
    dhparams = attr.ib(
        validator=attr.validators.instance_of(AnalyzerResultVulnerabilityDHParams),
        metadata={'human_readable_name': 'Diffie-Hellman Parameters'}
    )
    versions = attr.ib(
        validator=attr.validators.instance_of(AnalyzerResultVulnerabilityVersions),
        metadata={'human_readable_name': 'Protocol Versions'}
    )


class AnalyzerVulnerabilities(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'vulns'

    @classmethod
    def get_help(cls):
        return 'Check which vulnerabilities affect the server(s)'

    @classmethod
    def _get_known_algorithms(cls, algorithms):
        return filter(lambda algorithm: not isinstance(algorithm, six.string_types), algorithms)

    def analyze(self, analyzable):
        LogSingleton().disabled = True
        analyzer_result_versions = AnalyzerVersions().analyze(analyzable)
        analyzer_result_ciphers = AnalyzerCiphers().analyze(analyzable)
        analyzer_result_dhparams = AnalyzerDHParams().analyze(analyzable)
        LogSingleton().disabled = False

        return AnalyzerResultVulnerabilities(
            target=AnalyzerTargetSsh.from_l7_client(analyzable, None),
            algorithms=AnalyzerResultVulnerabilityAlgorithms.from_ssh_algorithms(
                kex_algorithms=set(self._get_known_algorithms(analyzer_result_ciphers.kex_algorithms)),
                strict_kex_enabled='kex-strict-s-v00@openssh.com' in analyzer_result_ciphers.kex_algorithms,
                encryption_algorithms=set(
                    list(self._get_known_algorithms(analyzer_result_ciphers.encryption_algorithms_client_to_server)) +
                    list(self._get_known_algorithms(analyzer_result_ciphers.encryption_algorithms_server_to_client))
                ),
                mac_algorithms=set(
                    list(self._get_known_algorithms(analyzer_result_ciphers.mac_algorithms_client_to_server)) +
                    list(self._get_known_algorithms(analyzer_result_ciphers.mac_algorithms_server_to_client))
                ),
            ),
            dhparams=AnalyzerResultVulnerabilityDHParams.from_key_sizes(
                set(map(
                    lambda key_size: key_size.value,
                    analyzer_result_dhparams.group_exchange.key_sizes
                    if analyzer_result_dhparams.group_exchange else []
                )) | set(map(
                    lambda kex_algorithm: kex_algorithm.value.key_size,
                    analyzer_result_dhparams.key_exchange.kex_algorithms
                    if analyzer_result_dhparams.key_exchange else []
                ))
            ),
            versions=AnalyzerResultVulnerabilityVersions.from_protocol_versions(
                analyzer_result_versions.protocol_versions
            )
        )
