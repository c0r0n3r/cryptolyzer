# -*- coding: utf-8 -*-

from collections import OrderedDict

import attr

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls

from cryptolyzer.tls.ciphers import AnalyzerCipherSuites, AnalyzerResultCipherSuites
from cryptolyzer.tls.curves import AnalyzerCurves, AnalyzerResultCurves
from cryptolyzer.tls.dhparams import AnalyzerDHParams, AnalyzerResultDHParams
from cryptolyzer.tls.pubkeyreq import AnalyzerPublicKeyRequest, AnalyzerResultPublicKeyRequest
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys, AnalyzerResultPublicKeys
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos, AnalyzerResultSigAlgos
from cryptolyzer.tls.versions import AnalyzerVersions, AnalyzerResultVersions


@attr.s
class AnalyzerResultAll(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    versions = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultVersions)),
        metadata={'human_readable_name': 'Supported Protocol Versions'}
    )
    ciphers = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultCipherSuites))
        )),
        metadata={'human_readable_name': 'Supported Cipher Suites'}
    )
    curves = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultCurves)),
        metadata={'human_readable_name': 'Supported Elliptic Curves'}
    )
    dhparams = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultDHParams)),
        metadata={'human_readable_name': 'Used Diffie-Hellman parameters'}
    )
    pubkeyreq = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultPublicKeyRequest)),
        metadata={'human_readable_name': 'Requested Public Keys'}
    )
    pubkeys = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultPublicKeys)),
        metadata={'human_readable_name': 'Used Public Keys'}
    )
    sigalgos = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultSigAlgos)),
        metadata={'human_readable_name': 'Supported Signature Algorithms'}
    )

    def _as_markdown(self, level):
        result = ''

        dict_value = self._asdict()
        name_dict = self._markdown_human_readable_names(self, dict_value)
        for attr_name, value in dict_value.items():
            result += '{} {}\n\n'.format((level + 1) * '#', name_dict[attr_name])
            if value is None or isinstance(value, (AnalyzerResultTls, AnalyzerTargetTls)):
                result += self._as_markdown_without_target(value, level)
            else:
                for index, cipher_result in enumerate(value):
                    if index:
                        result += '\n'

                    result += '{} {}\n\n'.format((level + 2) * '#', cipher_result.target.proto_version)
                    result += self._as_markdown_without_target(cipher_result, level)
            result += '\n'

        return True, result


class AnalyzerAll(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'all'

    @classmethod
    def get_help(cls):
        return 'Check TLS settings of the server(s) all'

    @staticmethod
    def _is_key_exchange_supported(cipher_suite_results, key_exchange):
        for protocol_version, cipher_suite_result in cipher_suite_results.items():
            for cipher_suite in cipher_suite_result.cipher_suites:
                if cipher_suite.value.key_exchange == key_exchange:
                    return protocol_version

        return None

    @staticmethod
    def is_dhe_supported(cipher_suite_results):
        return AnalyzerAll._is_key_exchange_supported(cipher_suite_results, KeyExchange.DHE)

    @staticmethod
    def is_ecdhe_supported(cipher_suite_results):
        return AnalyzerAll._is_key_exchange_supported(cipher_suite_results, KeyExchange.ECDHE)

    @staticmethod
    def is_publc_key_supported(cipher_suite_results):
        for protocol_version, cipher_suite_result in cipher_suite_results.items():
            for cipher_suite in cipher_suite_result.cipher_suites:
                if cipher_suite.value.authentication != Authentication.anon:
                    return protocol_version

        return None

    def analyze(self, analyzable, protocol_version):
        results = {
            'target': AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            'versions': None,
        }

        results['versions'] = AnalyzerVersions().analyze(analyzable, protocol_version)
        versions = results['versions'].versions

        cipher_suite_results = OrderedDict([
            (protocol_version, AnalyzerCipherSuites().analyze(analyzable, protocol_version))
            for protocol_version in versions
        ])

        if versions:
            results['pubkeyreq'] = AnalyzerPublicKeyRequest().analyze(analyzable, versions[-1])
        protocol_version = self.is_publc_key_supported(cipher_suite_results)
        if protocol_version is None:
            results['pubkeys'] = None
        else:
            results['pubkeys'] = AnalyzerPublicKeys().analyze(analyzable, protocol_version)

        protocol_version = self.is_dhe_supported(cipher_suite_results)
        if protocol_version is None:
            results['dhparams'] = None
        else:
            results['dhparams'] = AnalyzerDHParams().analyze(analyzable, protocol_version)
        protocol_version = self.is_ecdhe_supported(cipher_suite_results)
        if protocol_version is None:
            results['curves'] = None
        else:
            results['curves'] = AnalyzerCurves().analyze(analyzable, protocol_version)
        if TlsProtocolVersionFinal(TlsVersion.TLS1_2) in versions:
            results['sigalgos'] = AnalyzerSigAlgos().analyze(analyzable, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        else:
            results['sigalgos'] = None

        results['ciphers'] = list(cipher_suite_results.values())
        return AnalyzerResultAll(**results)
