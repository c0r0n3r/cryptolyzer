# -*- coding: utf-8 -*-

import attr

from cryptodatahub.common.algorithm import KeyExchange

from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.result import AnalyzerResultAllBase, AnalyzerTargetSsh

from cryptolyzer.ssh.ciphers import AnalyzerCiphers, AnalyzerResultCiphers
from cryptolyzer.ssh.dhparams import AnalyzerDHParams, AnalyzerResultDHParams
from cryptolyzer.ssh.pubkeys import AnalyzerPublicKeys, AnalyzerResultPublicKeys
from cryptolyzer.ssh.versions import AnalyzerVersions, AnalyzerResultVersions


@attr.s  # pylint: disable=too-few-public-methods,too-many-instance-attributes
class AnalyzerResultAll(AnalyzerResultAllBase):
    versions = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultVersions)),
        metadata={'human_readable_name': 'Supported Protocol Versions'}
    )
    ciphers = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultCiphers)),
        metadata={'human_readable_name': 'Supported Algorithms'}
    )
    dhparams = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultDHParams)),
        metadata={'human_readable_name': 'Supported Diffie-Hellman Algorithms and Key Sizes'}
    )
    pubkeys = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultPublicKeys)),
        metadata={'human_readable_name': 'Supported Host Key Types'}
    )


class AnalyzerAll(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'all'

    @classmethod
    def get_help(cls):
        return 'Check SSH settings of the server(s)'

    @staticmethod
    def _get_result(analyzer_class, analyzable, protocol_version):
        analyzer_name = analyzer_class.get_name()
        if protocol_version is None:
            return {analyzer_name: None}

        return {analyzer_name: analyzer_class().analyze(analyzable)}

    @staticmethod
    def get_versions_result(analyzable):
        analyzer_class = AnalyzerVersions
        analyzer_name = analyzer_class.get_name()

        return {analyzer_name: analyzer_class().analyze(analyzable)}

    @staticmethod
    def _is_key_exchange_supported(ciphers_result, key_exchange):
        if any(map(lambda kex_algorithm: kex_algorithm.value.kex == key_exchange, ciphers_result.kex_algorithms)):
            return SshProtocolVersion(SshVersion.SSH2)

        return None

    @staticmethod
    def is_dhe_supported(cipher_suite_results):
        return AnalyzerAll._is_key_exchange_supported(cipher_suite_results, KeyExchange.DHE)

    @staticmethod
    def get_dhparams_result(analyzable, cipher_suite_results):
        protocol_version = AnalyzerAll.is_dhe_supported(cipher_suite_results)
        return AnalyzerAll._get_result(AnalyzerDHParams, analyzable, protocol_version)

    def analyze(self, analyzable):
        results = {
            'target': AnalyzerTargetSsh.from_l7_client(analyzable),
        }

        results.update(self.get_versions_result(analyzable))

        ciphers_result = AnalyzerCiphers().analyze(analyzable)
        results.update({AnalyzerCiphers.get_name(): ciphers_result})
        results.update(self.get_dhparams_result(analyzable, ciphers_result))
        results.update({AnalyzerPublicKeys.get_name(): AnalyzerPublicKeys().analyze(analyzable)})

        return AnalyzerResultAll(**results)
