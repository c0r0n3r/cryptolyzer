# -*- coding: utf-8 -*-

import itertools

import attr


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
class AnalyzerResultVulnerabilityCiphers(object):  # pylint: disable=too-many-instance-attributes
    lucky13 = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Lucky Thirteen attack'},
    )
    sweet32 = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Sweet32 attack'},
    )
    freak = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'FREAK attack'},
    )
    anonymous_dh = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Anonymous Diffie-Hellman'},
    )
    null_encryption = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'NULL encryption'},
    )
    rc4 = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'RC4'},
    )
    non_forward_secret = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Non-Forward-Secret'},
    )
    export_grade = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Export grade ciphers'},
    )

    @staticmethod
    def from_cipher_suites(cipher_suites):
        rc4_cipher_suites = set(TlsHandshakeClientHelloStreamCipherRC4.CIPHER_SUITES)
        rc4 = bool(rc4_cipher_suites & set(cipher_suites))

        null_encryption_cipher_suites = set(TlsHandshakeClientHelloBulkCipherNull.CIPHER_SUITES)
        null_encryption = bool(null_encryption_cipher_suites & set(cipher_suites))

        anonymous_dh_cipher_suites = set(TlsHandshakeClientHelloKeyExchangeAnonymousDH.CIPHER_SUITES)
        anonymous_dh = bool(anonymous_dh_cipher_suites & set(cipher_suites))

        export_rsa_cipher_suites = set(TlsHandshakeClientHelloKeyExchangeAnonymousDH.CIPHER_SUITES)
        freak = bool(export_rsa_cipher_suites & set(cipher_suites))

        sweet32_cipher_suites = set(TlsHandshakeClientHelloBulkCipherBlockSize64.CIPHER_SUITES)
        sweet32 = bool(sweet32_cipher_suites & set(cipher_suites))

        lucky13_cipher_suites = set(TlsHandshakeClientHelloBlockCipherModeCBC.CIPHER_SUITES)
        lucky13 = bool(lucky13_cipher_suites & set(cipher_suites))

        non_forward_secret = any(map(
            lambda cipher_suite: (
                cipher_suite.value.key_exchange is not None and
                cipher_suite.value.key_exchange.value.forward_secret
            ), cipher_suites
        ))

        export_grade = any(map(lambda cipher_suite: cipher_suite.value.export_grade, cipher_suites))

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
    drown = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'DROWN attack'},
    )
    early_tls_version = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Early TLS version'},
    )

    @staticmethod
    def from_protocol_versions(protocol_versions):
        drown = TlsProtocolVersion(TlsVersion.SSL2) in protocol_versions

        early_tls_version = any(map(
            lambda protocol_version: (
                isinstance(protocol_version, TlsProtocolVersion) and
                protocol_version < TlsProtocolVersion(TlsVersion.TLS1_2)
            ),
            protocol_versions
        ))

        return AnalyzerResultVulnerabilityVersions(
            drown=drown,
            early_tls_version=early_tls_version,
        )


@attr.s
class AnalyzerResultVulnerabilityDHParams(object):
    logjam = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Logjam attack'},
    )
    dheat = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'DHEat attack'},
    )

    @staticmethod
    def from_dhparam(dhparam, groups):
        logjam = dhparam is not None and dhparam.key_size <= 1024
        dheat = ((dhparam is not None and dhparam.key_size > 4096) or
                 (max([group.value.named_group.value.size for group in groups] + [0]) > 4096))

        return AnalyzerResultVulnerabilityDHParams(
            logjam=logjam,
            dheat=dheat,
        )


@attr.s
class AnalyzerResultVulnerabilities(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
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
