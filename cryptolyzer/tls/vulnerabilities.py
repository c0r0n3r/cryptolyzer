# -*- coding: utf-8 -*-

import itertools

import attr


from cryptodatahub.common.grade import AttackNamed, Grade

from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.common.vulnerability import (
    AnalyzerResultVulnerabilityCiphersBase,
    AnalyzerResultVulnerabilityDHParamsBase,
    AnalyzerResultVulnerabilityVersionsBase,
    VulnerabilityResultAnonymousDH,
    VulnerabilityResultNullEncryption,
    VulnerabilityResultRC4,
    VulnerabilityResultAttackNamed,
    VulnerabilityResultDheat,
    VulnerabilityResultGraded,
    VulnerabilityResultNonForwardSecret,
    VulnerabilityResultSweet32,
    VulnerabilityResultWeakDh,
)

from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloBlockCipherModeCBC,
    TlsHandshakeClientHelloBulkCipherBlockSize64,
    TlsHandshakeClientHelloBulkCipherNull,
    TlsHandshakeClientHelloKeyExchangeAnonymousDH,
    TlsHandshakeClientHelloStreamCipherRC4,
)
from cryptolyzer.tls.dhparams import AnalyzerDHParams
from cryptolyzer.tls.versions import AnalyzerVersions


@attr.s
class VulnerabilityResultEarlyTlsVersion(VulnerabilityResultGraded):
    @property
    def _vulnerable_grade(self):
        return Grade.DEPRECATED

    @classmethod
    def get_name(cls):
        return 'Early TLS version'


class VulnerabilityResultDrown(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.DROWN_ATTACK


class VulnerabilityResultExportGrade(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.EXPORT_GRADE


class VulnerabilityResultFreak(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.FREAK


class VulnerabilityResultLuckyThirteen(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.LUCKY13


@attr.s
class AnalyzerResultVulnerabilityCiphers(AnalyzerResultVulnerabilityCiphersBase):
    """
    :class: Vulnerabilities relate to cipher suite algorithms. Any attribute represents an vulnerability, which value is
        true if any of the negotiable cipher suite uses an algorithm affected by the vulnerability.

    :param lucky13: `Lucky Thirteen attack <https://en.wikipedia.org/wiki/Lucky_Thirteen_attack>`__.
    :param freak: `FREAK attack <https://en.wikipedia.org/wiki/FREAK>`__.
    :param export_grade: Cipher suite uses
        `export grade <https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States>`__ algorithms.
    """

    null_encryption = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultNullEncryption),
        metadata={'human_readable_name': VulnerabilityResultNullEncryption.get_name()},
    )
    lucky13 = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultLuckyThirteen),
        metadata={'human_readable_name': VulnerabilityResultLuckyThirteen.get_name()},
    )
    freak = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultFreak),
        metadata={'human_readable_name': VulnerabilityResultFreak.get_name()},
    )
    export_grade = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultExportGrade),
        metadata={'human_readable_name': VulnerabilityResultExportGrade.get_name()},
    )

    @staticmethod
    def from_cipher_suites(cipher_suites):
        rc4_cipher_suites = set(TlsHandshakeClientHelloStreamCipherRC4.CIPHER_SUITES)
        rc4 = VulnerabilityResultRC4(bool(rc4_cipher_suites & set(cipher_suites)))

        null_encryption_cipher_suites = set(TlsHandshakeClientHelloBulkCipherNull.CIPHER_SUITES)
        null_encryption = VulnerabilityResultNullEncryption(bool(null_encryption_cipher_suites & set(cipher_suites)))

        anonymous_dh_cipher_suites = set(TlsHandshakeClientHelloKeyExchangeAnonymousDH.CIPHER_SUITES)
        anonymous_dh = VulnerabilityResultAnonymousDH(bool(anonymous_dh_cipher_suites & set(cipher_suites)))

        export_rsa_cipher_suites = set(TlsHandshakeClientHelloKeyExchangeAnonymousDH.CIPHER_SUITES)
        freak = VulnerabilityResultFreak(bool(export_rsa_cipher_suites & set(cipher_suites)))

        sweet32_cipher_suites = set(TlsHandshakeClientHelloBulkCipherBlockSize64.CIPHER_SUITES)
        sweet32 = VulnerabilityResultSweet32(bool(sweet32_cipher_suites & set(cipher_suites)))

        lucky13_cipher_suites = set(TlsHandshakeClientHelloBlockCipherModeCBC.CIPHER_SUITES)
        lucky13 = VulnerabilityResultLuckyThirteen(bool(lucky13_cipher_suites & set(cipher_suites)))

        non_forward_secret = VulnerabilityResultNonForwardSecret(any(map(
            lambda cipher_suite: (
                cipher_suite.value.key_exchange is not None and
                cipher_suite.value.key_exchange.value.forward_secret
            ), cipher_suites
        )))

        export_grade = VulnerabilityResultExportGrade(any(map(
            lambda cipher_suite: cipher_suite.value.export_grade, cipher_suites
        )))

        return AnalyzerResultVulnerabilityCiphers(
            rc4=rc4,
            null_encryption=null_encryption,
            anonymous_dh=anonymous_dh,
            freak=freak,
            sweet32=sweet32,
            lucky13=lucky13,
            non_forward_secret=non_forward_secret,
            export_grade=export_grade,
        )


@attr.s
class AnalyzerResultVulnerabilityVersions(AnalyzerResultVulnerabilityVersionsBase):
    """
    :class: Vulnerabilities relate to the protocol versions. Any attribute represents a vulnerability, which value is
        true if any of the negotiable protocol versions uses an algorithm affected by the vulnerability.

    :param drown: `DROWN attack <https://drownattack.com/>`__.
    :param early_tls_version: -  `Early protocol versions <https://www.rfc-editor.org/rfc/rfc8996>`__ are supported.
    """

    drown = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultDrown),
        metadata={'human_readable_name': VulnerabilityResultDrown.get_name()},
    )
    early_tls_version = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultEarlyTlsVersion),
        metadata={'human_readable_name': VulnerabilityResultEarlyTlsVersion.get_name()},
    )

    @staticmethod
    def from_protocol_versions(protocol_versions):
        drown = VulnerabilityResultDrown(bool(TlsProtocolVersion(TlsVersion.SSL2) in protocol_versions))

        early_tls_version = VulnerabilityResultEarlyTlsVersion(any(map(
            lambda protocol_version: (
                isinstance(protocol_version, TlsProtocolVersion) and
                protocol_version < TlsProtocolVersion(TlsVersion.TLS1_2)
            ),
            protocol_versions
        )))

        return AnalyzerResultVulnerabilityVersions(
            drown=drown,
            early_tls_version=early_tls_version,
        )


@attr.s
class AnalyzerResultVulnerabilityDHParams(AnalyzerResultVulnerabilityDHParamsBase):
    """
    :class: Vulnerabilities relate to the protocol versions. Any attribute represents a vulnerability, which value is
        true if any of the negotiable protocol versions uses an algorithm affected by the vulnerability.

    :param weak_dh: `Weak DH vulnerability <https://weakdh.org/>`__.
    """

    weak_dh = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultWeakDh),
        metadata={'human_readable_name': VulnerabilityResultWeakDh.get_name()},
    )

    @staticmethod
    def from_dhparam(dhparam, groups):
        weak_dh = VulnerabilityResultWeakDh(dhparam is not None and dhparam.key_size.value <= 1024)
        dheat = VulnerabilityResultDheat(
            (dhparam is not None and dhparam.key_size.value > 4096) or
            (max([group.value.named_group.value.size for group in groups] + [0]) > 4096)
        )

        return AnalyzerResultVulnerabilityDHParams(
            weak_dh=weak_dh,
            dheat=dheat,
        )


@attr.s
class AnalyzerResultVulnerabilities(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    """
    :class: Vulnerabilities relate to the server configuration.

    :param cipher: Cipher suite related vulnerabilities.
    :param dhparam: Diffie-Hellman parameter related vulnerabilities.
    :param versions: Protocol version related vulnerabilities.
    """

    ciphers = attr.ib(
        validator=attr.validators.instance_of(AnalyzerResultVulnerabilityCiphers),
        metadata={'human_readable_name': 'Cipher Suites'},
    )
    dhparams = attr.ib(
        validator=attr.validators.instance_of(AnalyzerResultVulnerabilityDHParams),
        metadata={'human_readable_name': 'Diffie-Hellman Parameters'}
    )
    versions = attr.ib(
        validator=attr.validators.instance_of(AnalyzerResultVulnerabilityVersions),
        metadata={'human_readable_name': 'Protocol Versions'}
    )

    @staticmethod
    def from_results(target, protocol_versions, cipher_suites, dhparam, groups):
        return AnalyzerResultVulnerabilities(
            target=target,
            ciphers=AnalyzerResultVulnerabilityCiphers.from_cipher_suites(cipher_suites),
            dhparams=AnalyzerResultVulnerabilityDHParams.from_dhparam(dhparam, groups),
            versions=AnalyzerResultVulnerabilityVersions.from_protocol_versions(protocol_versions),
        )


class AnalyzerVulnerabilities(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'vulns'

    @classmethod
    def get_help(cls):
        return 'Check which vulnerabilities affect the server(s)'

    def analyze(self, analyzable, protocol_version):
        LogSingleton().disabled = True
        analyzer_result_versions = AnalyzerVersions().analyze(analyzable, None)
        cipher_suites = set(itertools.chain.from_iterable(map(
            lambda supported_protocol_version: AnalyzerCipherSuites().analyze(
                analyzable, supported_protocol_version
            ).cipher_suites,
            analyzer_result_versions.versions
        )))
        for supported_protocol_version in analyzer_result_versions.versions:
            if (isinstance(supported_protocol_version, TlsProtocolVersion) and
                    supported_protocol_version <= TlsProtocolVersion(TlsVersion.TLS1_2)):
                result = AnalyzerDHParams().analyze(analyzable, supported_protocol_version)
                dhparam = result.dhparam
                groups = result.groups
                break
        else:
            dhparam = None
            groups = []
        tls_protocol_version_1_3 = TlsProtocolVersion(TlsVersion.TLS1_3)
        if not groups and tls_protocol_version_1_3 in analyzer_result_versions.versions:
            result = AnalyzerDHParams().analyze(analyzable, tls_protocol_version_1_3)
            groups = result.groups
        LogSingleton().disabled = False

        return AnalyzerResultVulnerabilities(
            target=AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            ciphers=AnalyzerResultVulnerabilityCiphers.from_cipher_suites(cipher_suites),
            dhparams=AnalyzerResultVulnerabilityDHParams.from_dhparam(dhparam, groups),
            versions=AnalyzerResultVulnerabilityVersions.from_protocol_versions(analyzer_result_versions.versions)
        )
