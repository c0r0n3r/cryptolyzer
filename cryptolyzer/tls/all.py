# -*- coding: utf-8 -*-

from collections import OrderedDict

import attr

from cryptodatahub.common.algorithm import Authentication, KeyExchange

from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase, ProtocolHandlerBase
from cryptolyzer.common.result import AnalyzerResultAllBase, AnalyzerTargetTls

from cryptolyzer.tls.ciphers import AnalyzerCipherSuites, AnalyzerResultCipherSuites
from cryptolyzer.tls.curves import AnalyzerCurves, AnalyzerResultCurves
from cryptolyzer.tls.dhparams import AnalyzerDHParams, AnalyzerResultDHParams
from cryptolyzer.tls.extensions import AnalyzerExtensions, AnalyzerResultExtensions
from cryptolyzer.tls.pubkeyreq import AnalyzerPublicKeyRequest, AnalyzerResultPublicKeyRequest
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys, AnalyzerResultPublicKeys
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos, AnalyzerResultSigAlgos
from cryptolyzer.tls.simulations import AnalyzerSimulations, AnalyzerResultSimulations
from cryptolyzer.tls.versions import AnalyzerVersions, AnalyzerResultVersions
from cryptolyzer.tls.vulnerabilities import AnalyzerVulnerabilities, AnalyzerResultVulnerabilities


@attr.s
class AnalyzerResultAll(AnalyzerResultAllBase):  # pylint: disable=too-few-public-methods,too-many-instance-attributes
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
    simulations = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultSimulations)),
        metadata={'human_readable_name': 'Simulated Clients'}
    )
    extensions = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultExtensions)),
        metadata={'human_readable_name': 'Supported Extensions'}
    )
    vulns = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultVulnerabilities)),
        metadata={'human_readable_name': 'Vulnerabilities'}
    )


class AnalyzerAll(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'all'

    @classmethod
    def get_help(cls):
        return 'Check TLS settings of the server(s)'

    @staticmethod
    def _get_result(analyzer_class, analyzable, protocol_version):
        analyzer_name = analyzer_class.get_name()
        if protocol_version is not None:
            protocol_handler = ProtocolHandlerBase.from_protocol(protocol_version.identifier)
            if not (analyzer_class in protocol_handler.get_analyzers() and
                    protocol_handler.get_protocol_version() == protocol_version):
                protocol_version = None

        if protocol_version is None:
            return {analyzer_name: None}

        return {analyzer_name: analyzer_class().analyze(analyzable, protocol_version)}

    @staticmethod
    def get_versions_result(analyzable):
        analyzer_class = AnalyzerVersions
        analyzer_name = analyzer_class.get_name()

        return {analyzer_name: analyzer_class().analyze(analyzable, None)}

    @staticmethod
    def _is_key_exchange_supported(cipher_suites, key_exchange):
        return any(map(
            lambda cipher_suite: (
                cipher_suite.value.key_exchange is None or
                cipher_suite.value.key_exchange == key_exchange
            ),
            cipher_suites
        ))

    @staticmethod
    def _max_tls_version_supported(cipher_suite_results, key_exchange):
        protocol_versions = sorted(filter(
            lambda protocol_version: not protocol_version.is_draft and not protocol_version.is_google_experimental,
            cipher_suite_results
        ), reverse=True)
        for protocol_version in protocol_versions:
            cipher_suite_result = cipher_suite_results[protocol_version]
            if AnalyzerAll._is_key_exchange_supported(cipher_suite_result.cipher_suites, key_exchange):
                return protocol_version

        return None

    @staticmethod
    def is_dhe_supported(cipher_suite_results):
        protocol_versions = [
            protocol_version
            for protocol_version, cipher_suite_result in cipher_suite_results.items()
            if AnalyzerAll._is_key_exchange_supported(cipher_suite_result.cipher_suites, KeyExchange.DHE)
        ]

        protocol_version_tls1_2 = TlsProtocolVersion(TlsVersion.TLS1_2)
        if protocol_version_tls1_2 in cipher_suite_results.keys() and protocol_version_tls1_2 not in protocol_versions:
            protocol_versions.append(protocol_version_tls1_2)

        return protocol_versions

    @staticmethod
    def is_ecdhe_supported(cipher_suite_results):
        return AnalyzerAll._max_tls_version_supported(cipher_suite_results, KeyExchange.ECDHE)

    @staticmethod
    def get_dhparams_result(analyzable, cipher_suite_results):
        analyzer_name = AnalyzerDHParams.get_name()
        result = {analyzer_name: None}
        protocol_versions = AnalyzerAll.is_dhe_supported(cipher_suite_results)
        if not protocol_versions:
            return result

        protocol_version_min = min(protocol_versions)
        if protocol_version_min < TlsProtocolVersion(TlsVersion.TLS1_2):
            result = AnalyzerAll._get_result(AnalyzerDHParams, analyzable, protocol_version_min)

        protocol_version_tls1_2 = TlsProtocolVersion(TlsVersion.TLS1_2)
        if protocol_version_tls1_2 in protocol_versions:
            result_tls1_2 = AnalyzerAll._get_result(AnalyzerDHParams, analyzable, protocol_version_tls1_2)
            if result_tls1_2[analyzer_name]:
                if result[analyzer_name]:
                    result[analyzer_name].groups = result_tls1_2[analyzer_name].groups
                else:
                    result = result_tls1_2

        protocol_version_max = max(protocol_versions)
        if (protocol_version_max > protocol_version_tls1_2 and
                (result[analyzer_name] is None or not result[analyzer_name].groups)):
            result_tls1_3 = AnalyzerAll._get_result(AnalyzerDHParams, analyzable, protocol_version_max)
            if result_tls1_3[analyzer_name]:
                if result[analyzer_name]:
                    result[analyzer_name].groups = result_tls1_3[analyzer_name].groups
                else:
                    result = result_tls1_3

        if (result[analyzer_name] is not None and (result[analyzer_name].groups or result[analyzer_name].dhparam)):
            return result

        return {analyzer_name: None}

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
    def is_public_key_supported(cipher_suite_results):
        for protocol_version, cipher_suite_result in cipher_suite_results.items():
            for cipher_suite in cipher_suite_result.cipher_suites:
                if cipher_suite.value.authentication not in (None, Authentication.ANONYMOUS):
                    return protocol_version

        return None

    @staticmethod
    def get_pubkeys_result(analyzable, cipher_suite_results):
        protocol_version = AnalyzerAll.is_public_key_supported(cipher_suite_results)
        return AnalyzerAll._get_result(AnalyzerPublicKeys, analyzable, protocol_version)

    @staticmethod
    def get_sigalgos_result(analyzable, versions):
        protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        if protocol_version not in versions:
            protocol_version = None

        return AnalyzerAll._get_result(AnalyzerSigAlgos, analyzable, protocol_version)

    @staticmethod
    def get_simulations_result(analyzable):
        analyzer_class = AnalyzerSimulations
        analyzer_name = analyzer_class.get_name()

        return {analyzer_name: analyzer_class().analyze(analyzable, None)}

    @staticmethod
    def get_extensions_result(analyzable, versions):
        for version in reversed(versions):
            if version <= TlsProtocolVersion(TlsVersion.TLS1_2):
                protocol_version = version
                break
        else:
            protocol_version = None

        return AnalyzerAll._get_result(AnalyzerExtensions, analyzable, protocol_version)

    def analyze(self, analyzable, protocol_version):
        results = {
            'target': AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
        }

        results.update(self.get_versions_result(analyzable))
        versions = results[AnalyzerVersions.get_name()]
        protocol_versions = versions.versions

        cipher_suite_results = OrderedDict([
            (protocol_version, AnalyzerCipherSuites().analyze(analyzable, protocol_version))
            for protocol_version in protocol_versions
        ])

        dhparams_result = self.get_dhparams_result(analyzable, cipher_suite_results)
        dhparams = dhparams_result[AnalyzerDHParams.get_name()]
        results.update(dhparams_result)

        results.update(self.get_pubkeyreq_result(analyzable, protocol_versions))
        results.update(self.get_pubkeys_result(analyzable, cipher_suite_results))
        results.update(self.get_curves_result(analyzable, cipher_suite_results))
        results.update(self.get_sigalgos_result(analyzable, protocol_versions))
        results.update(self.get_simulations_result(analyzable))
        results.update(self.get_extensions_result(analyzable, protocol_versions))
        results.update({
            AnalyzerVulnerabilities.get_name():
            AnalyzerResultVulnerabilities.from_results(
                target=analyzable,
                versions=versions,
                ciphers=cipher_suite_results.values(),
                dhparams=dhparams,
            )
        })
        results.update({AnalyzerCipherSuites.get_name(): list(cipher_suite_results.values())})

        return AnalyzerResultAll(**results)
