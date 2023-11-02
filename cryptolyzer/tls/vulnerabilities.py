# -*- coding: utf-8 -*-

import abc
import itertools

import attr


from cryptodatahub.common.grade import AttackNamed, Grade, GradeableSimple

from cryptoparser.common.base import Serializable
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton

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
class VulnerabilityResult(Serializable, GradeableSimple):
    value = attr.ib(validator=attr.validators.instance_of(bool))

    @property
    @abc.abstractmethod
    def grade(self):
        raise NotImplementedError()

    def __str__(self):
        return self._markdown_result(self.value)[1]

    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()


@attr.s
class VulnerabilityResultGraded(VulnerabilityResult):
    @property
    def grade(self):
        return self._vulnerable_grade if self.value else Grade.SECURE

    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _vulnerable_grade(self):
        raise NotImplementedError()


@attr.s
class VulnerabilityResultAnonymousDH(VulnerabilityResultGraded):
    @property
    def _vulnerable_grade(self):
        return Grade.INSECURE

    @classmethod
    def get_name(cls):
        return 'Anonymous Diffie-Hellman'


@attr.s
class VulnerabilityResultEarlyTlsVersion(VulnerabilityResultGraded):
    @property
    def _vulnerable_grade(self):
        return Grade.DEPRECATED

    @classmethod
    def get_name(cls):
        return 'Early TLS version'


@attr.s
class VulnerabilityResultNullEncryption(VulnerabilityResultGraded):
    @property
    def _vulnerable_grade(self):
        return Grade.INSECURE

    @classmethod
    def get_name(cls):
        return 'NULL encryption'


@attr.s
class VulnerabilityResultRC4(VulnerabilityResultGraded):
    @property
    def _vulnerable_grade(self):
        return Grade.INSECURE

    @classmethod
    def get_name(cls):
        return 'RC4'


class VulnerabilityResultAttackNamed(VulnerabilityResult):
    @property
    def grade(self):
        return self.get_attack_named().value.grade if self.value else Grade.SECURE

    @classmethod
    def get_name(cls):
        return cls.get_attack_named().value.name

    @classmethod
    @abc.abstractmethod
    def get_attack_named(cls):
        raise NotImplementedError()


class VulnerabilityResultDheat(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.DHEAT_ATTACK


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


class VulnerabilityResultNonForwardSecret(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.NOFS


class VulnerabilityResultSweet32(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.SWEET32


class VulnerabilityResultWeakDh(VulnerabilityResultAttackNamed):
    @classmethod
    def get_attack_named(cls):
        return AttackNamed.WEAK_DH


@attr.s
class AnalyzerResultVulnerabilityCiphers(object):  # pylint: disable=too-many-instance-attributes
    """
    :class: Vulnerabilities relate to cipher suite algorithms. Any attribute represents an vulnerability, which value is
        true if any of the negotiable cipher suite uses an algorithm affected by the vulnerability.

    :param lucky13: `Lucky Thirteen attack <https://en.wikipedia.org/wiki/Lucky_Thirteen_attack>`__.
    :param sweet32: `Sweet32 attack <https://sweet32.info/>`__.
    :param freak: `FREAK attack <https://en.wikipedia.org/wiki/FREAK>`__.
    :param anonymous_dh:
        `Anonymous Diffie-Hellman <https://en.wikipedia.org/wiki/Key-agreement_protocol#Exponential_key_exchange>`__ key
        exchange algorithm.
    :param null_encryption: Cipher suite does use `no/null null <https://en.wikipedia.org/wiki/Null_encryption>`__
        encryption
    :param rc4: Cipher suite uses `RC4 stream ciphers <https://en.wikipedia.org/wiki/RC4#Security>`__.
    :param non_forward_secret: Cipher suite uses key exchange algorithm which does not provide
        `forward secrecy <https://en.wikipedia.org/wiki/Forward_secrecy>`__
    :param export_grade: Cipher suite uses
        `export grade <https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States>`__ algorithms.
    """

    lucky13 = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultLuckyThirteen),
        metadata={'human_readable_name': VulnerabilityResultLuckyThirteen.get_name()},
    )
    sweet32 = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultSweet32),
        metadata={'human_readable_name': VulnerabilityResultSweet32.get_name()},
    )
    freak = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultFreak),
        metadata={'human_readable_name': VulnerabilityResultFreak.get_name()},
    )
    anonymous_dh = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultAnonymousDH),
        metadata={'human_readable_name': VulnerabilityResultAnonymousDH.get_name()},
    )
    null_encryption = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultNullEncryption),
        metadata={'human_readable_name': VulnerabilityResultNullEncryption.get_name()},
    )
    rc4 = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultRC4),
        metadata={'human_readable_name': VulnerabilityResultRC4.get_name()},
    )
    non_forward_secret = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultNonForwardSecret),
        metadata={'human_readable_name': VulnerabilityResultNonForwardSecret.get_name()},
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
class AnalyzerResultVulnerabilityVersions(object):  # pylint: disable=too-few-public-methods
    """
    :class: Vulnerabilities relate to the protocol versions. Any attribute represents a vulnerability, which value is
        true if any of the negotiable protocol versions uses an algorithm affected by the vulnerability.

    :param drown: `DROWN attack <https://drownattack.com/>`__.
    :param early_tls_version: -  `Early protocol versions <https://www.rfc-editor.org/rfc/rfc8996>`__ is supported.
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
class AnalyzerResultVulnerabilityDHParams(object):
    """
    :class: Vulnerabilities relate to the protocol versions. Any attribute represents a vulnerability, which value is
        true if any of the negotiable protocol versions uses an algorithm affected by the vulnerability.

    :param weak_dh: `Weak DH vulnerability <https://weakdh.org/>`__.
    :param early_tls_version: `D(HE)at attack <https://dheatattack.com/>`__.
    """

    weak_dh = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultWeakDh),
        metadata={'human_readable_name': VulnerabilityResultWeakDh.get_name()},
    )
    dheat = attr.ib(
        validator=attr.validators.instance_of(VulnerabilityResultDheat),
        metadata={'human_readable_name': VulnerabilityResultDheat.get_name()},
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
