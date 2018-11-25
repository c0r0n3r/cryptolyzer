#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.tls.version import TlsProtocolVersionFinal
from cryptoparser.tls.version import TlsVersion
from cryptoparser.tls.version import SslProtocolVersion

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.tls.client import L7ClientTls
from cryptolyzer.tls.versions import AnalyzerVersions


class ProtocolHandlerTlsBase(ProtocolHandlerBase):
    @classmethod
    def get_clients(cls):
        return [client_class for client_class in get_leaf_classes(L7ClientTls)]

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
        ]

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_2)


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
        return analyzer_result
