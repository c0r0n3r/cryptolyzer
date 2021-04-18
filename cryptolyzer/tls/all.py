# -*- coding: utf-8 -*-

from collections import OrderedDict

import attr

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase, ProtocolHandlerTlsExactVersion
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
    def _get_result(analyzer_class, analyzable, protocol_version):
        for protocol_handler_class in get_leaf_classes(ProtocolHandlerTlsExactVersion):
            if (analyzer_class in protocol_handler_class.get_analyzers() and
                    protocol_handler_class.get_protocol_version() == protocol_version):
                break
        else:
            protocol_version = None

        analyzer_name = analyzer_class.get_name()
        if protocol_version is None:
            return {analyzer_name: None}

        return {analyzer_name: analyzer_class().analyze(analyzable, protocol_version)}

    @staticmethod
    def get_versions_result(analyzable):
        analyzer_class = AnalyzerVersions
        analyzer_name = analyzer_class.get_name()

        return {analyzer_name: analyzer_class().analyze(analyzable, None)}

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
    def get_dhparams_result(analyzable, cipher_suite_results):
        protocol_version = AnalyzerAll.is_dhe_supported(cipher_suite_results)
        return AnalyzerAll._get_result(AnalyzerDHParams, analyzable, protocol_version)

    @staticmethod
    def get_curves_result(analyzable, cipher_suite_results):
        protocol_version = AnalyzerAll.is_ecdhe_supported(cipher_suite_results)
        return AnalyzerAll._get_result(AnalyzerCurves, analyzable, protocol_version)

    @staticmethod
    def get_pubkeyreq_result(analyzable, protocol_versions):
        if protocol_versions:
            protocol_version = protocol_versions[-1]
        else:
            protocol_version = None

        return AnalyzerAll._get_result(AnalyzerPublicKeyRequest, analyzable, protocol_version)

    @staticmethod
    def is_publc_key_supported(cipher_suite_results):
        for protocol_version, cipher_suite_result in cipher_suite_results.items():
            for cipher_suite in cipher_suite_result.cipher_suites:
                if cipher_suite.value.authentication != Authentication.anon:
                    return protocol_version

        return None

    @staticmethod
    def get_pubkeys_result(analyzable, cipher_suite_results):
        protocol_version = AnalyzerAll.is_publc_key_supported(cipher_suite_results)
        return AnalyzerAll._get_result(AnalyzerPublicKeys, analyzable, protocol_version)

    @staticmethod
    def get_sigalgos_result(analyzable, versions):
        protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        if protocol_version not in versions:
            protocol_version = None

        return AnalyzerAll._get_result(AnalyzerSigAlgos, analyzable, protocol_version)

    def analyze(self, analyzable, protocol_version):
        results = {
            'target': AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
        }

        results.update(self.get_versions_result(analyzable))
        versions = results[AnalyzerVersions.get_name()].versions

        cipher_suite_results = OrderedDict([
            (protocol_version, AnalyzerCipherSuites().analyze(analyzable, protocol_version))
            for protocol_version in versions
        ])

        results.update(self.get_pubkeyreq_result(analyzable, versions))
        results.update(self.get_pubkeys_result(analyzable, cipher_suite_results))
        results.update(self.get_dhparams_result(analyzable, cipher_suite_results))
        results.update(self.get_curves_result(analyzable, cipher_suite_results))
        results.update(self.get_sigalgos_result(analyzable, versions))
        results.update({AnalyzerCipherSuites.get_name(): list(cipher_suite_results.values())})

        return AnalyzerResultAll(**results)
