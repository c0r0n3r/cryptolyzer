# -*- coding: utf-8 -*-

import abc
from collections import OrderedDict

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.tls.version import TlsProtocolVersionFinal
from cryptoparser.tls.version import TlsVersion
from cryptoparser.tls.version import SslProtocolVersion

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.result import AnalyzerResultTls
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys
from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
from cryptolyzer.tls.curves import AnalyzerCurves
from cryptolyzer.tls.dhparams import AnalyzerDHParams
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos
from cryptolyzer.tls.versions import AnalyzerVersions


class ProtocolHandlerTlsBase(ProtocolHandlerBase):
    @classmethod
    def get_clients(cls):
        return list(get_leaf_classes(L7ClientTlsBase))

    @classmethod
    @abc.abstractmethod
    def _get_protocol_version(cls):
        raise NotImplementedError()

    @classmethod
    def get_protocol(cls):
        return repr(cls._get_protocol_version())

    @classmethod
    def get_default_scheme(cls):
        return 'tls'

    @classmethod
    def _get_analyzer_args(cls):
        return ([], {'protocol_version': cls._get_protocol_version()})


class ProtocolHandlerTlsExactVersion(ProtocolHandlerTlsBase):
    @classmethod
    @abc.abstractmethod
    def _get_protocol_version(cls):
        raise NotImplementedError()


class ProtocolHandlerSsl2(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return [
            AnalyzerPublicKeys,
            AnalyzerCipherSuites,
        ]

    @classmethod
    def _get_protocol_version(cls):
        return SslProtocolVersion()


class ProtocolHandlerSsl3(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerSsl2.get_analyzers()

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.SSL3)


class ProtocolHandlerTls10(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerSsl3.get_analyzers() + [
            AnalyzerCurves,
            AnalyzerDHParams,
        ]

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_0)


class ProtocolHandlerTls11(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerTls10.get_analyzers()

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_1)


class ProtocolHandlerTls12(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerTls11.get_analyzers() + [
            AnalyzerSigAlgos,
        ]

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_2)


class AnalyzerResultTlsAllSupportedVersions(AnalyzerResultTls):
    def __init__(self, target, results):
        super(AnalyzerResultTlsAllSupportedVersions, self).__init__(target)

        self.results = results

    def _asdict(self):
        results = []
        for protocol_version, result in iter(self.results.items()):
            result_as_dict = result._asdict()
            del result_as_dict['target']

            results.append((repr(protocol_version), result_as_dict))

        return OrderedDict([('target', self.target)] + results)


class ProtocolHandlerTlsAllSupportedVersions(ProtocolHandlerTlsBase):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerTls12.get_analyzers() + [
            AnalyzerVersions,
        ]

    @classmethod
    def get_protocol(cls):
        return 'tls'

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_2)

    def analyze(self, analyzer, uri):
        base_analyze = super(ProtocolHandlerTlsAllSupportedVersions, self).analyze
        analyzer_result = base_analyze(AnalyzerVersions.get_name(), uri)
        if analyzer == AnalyzerVersions.get_name():
            return analyzer_result

        results = []
        target = None
        for protocol_handler_class in get_leaf_classes(ProtocolHandlerTlsExactVersion):
            if analyzer in [analyzer_class.get_name() for analyzer_class in protocol_handler_class.get_analyzers()]:
                result = protocol_handler_class().analyze(analyzer, uri)
                target = result.target

                results.append(
                    (protocol_handler_class._get_protocol_version(), result)  # pylint: disable=protected-access
                )

        return AnalyzerResultTlsAllSupportedVersions(target, OrderedDict(results))
