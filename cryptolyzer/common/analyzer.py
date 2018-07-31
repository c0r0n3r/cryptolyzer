#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json

from cryptoparser.common.base import JSONSerializable
from cryptoparser.common.utils import get_leaf_classes

class ProtocolHandlerBase(object):
    @classmethod
    def from_protocol(cls, protocol):
        for handler_class in get_leaf_classes(cls):
            if handler_class.get_protocol() == protocol:
                return handler_class()
        else:
            raise KeyError()

    @classmethod
    @abc.abstractmethod
    def get_protocol(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_analyzers(cls):
        raise NotImplementedError()

    def _get_analyzer_args(cls):
        return ([], {})

    def _l7_client_from_uri(self, uri):
        kwargs = {'scheme': uri.scheme, 'host': uri.host}

        if uri.port:
            kwargs['port'] = int(uri.port)

        return L7Client.from_scheme(**kwargs)

    def analyze(self, analyzer, uri):
        analyzer = self._analyzer_from_name(analyzer)
        l7_client = self._l7_client_from_uri(uri)
        args, kwargs = self._get_analyzer_args()
        return analyzer.analyze(l7_client, *args, **kwargs)

    @classmethod
    def _analyzer_from_name(cls, name):
        analyzer_list = [
            analyzer_class
            for analyzer_class in cls.get_analyzers()
            if analyzer_class.get_name() == name
        ]
        if len(analyzer_list) != 1:
            raise ValueError

        return analyzer_list[0]()


class AnalyzerBase(object):
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def analyze(self, l7_client):
        raise NotImplementedError()


class AnalyzerResultBase(JSONSerializable):
    @staticmethod
    def _bytes_to_colon_separated_hex(byte_array):
        return ':'.join(['{:02X}'.format(x) for x in byte_array])


class AnalyzerTlsBase(object):
    @abc.abstractmethod
    def analyze(self, l7_client, protocol_version):
        raise NotImplementedError()


from cryptolyzer.tls import ciphers, pubkeys, curves, sigalgos, versions
from cryptoparser.tls.client import L7Client

from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion, SslProtocolVersion


class ProtocolHandlerTlsBase(ProtocolHandlerBase):
    @classmethod
    def get_clients(cls):
        return [client_class for client_class in get_leaf_classes(L7Client)]

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

    def _get_analyzer_args(self):
        return ([], {'protocol_version': self._get_protocol_version()})


class ProtocolHandlerTlsExactVersion(ProtocolHandlerTlsBase):
    pass


class ProtocolHandlerSsl2(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return [
            certificates.AnalyzerCertificates,
            ciphers.AnalyzerCipherSuites,
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
            curves.AnalyzerCurves,
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
            sigalgos.AnalyzerSigAlgos,
        ]

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_2)


class AnalyzerResultTls(AnalyzerResultBase):
    def __init__(self, analyzer, results):
        self.analyzer = analyzer
        self.results = results

    def as_json(self):
        return json.dumps({repr(protocol_version): result.__dict__ for protocol_version, result in self.results.items()})


class ProtocolHandlerTlsSupportedVersions(ProtocolHandlerTlsBase):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerTls12.get_analyzers() + [
            versions.AnalyzerVersions,
        ]

    @classmethod
    def get_protocol(cls):
        return 'tls'

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_2)

    def analyze(self, analyzer, uri):
        base_analyze = super(ProtocolHandlerTlsSupportedVersions, self).analyze
        analyzer_result = base_analyze(versions.AnalyzerVersions.get_name(), uri)
        if analyzer == versions.AnalyzerVersions.get_name():
            return analyzer_result


        results = {
            protocol_handler_class._get_protocol_version(): protocol_handler_class().analyze(analyzer, uri)
            for protocol_handler_class in get_leaf_classes(ProtocolHandlerTlsExactVersion)
            if analyzer in [analyzer_class.get_name() for analyzer_class in protocol_handler_class.get_analyzers()]
            #protocol_version: base_analyze(analyzer, uri)
            #for protocol_version in analyzer_result.versions
            #if type(analyzer) in self._analyzer_from_name(analyzer).get_analyzers()
        }
        return AnalyzerResultTls(analyzer, results)
