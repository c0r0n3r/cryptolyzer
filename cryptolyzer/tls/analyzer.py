# -*- coding: utf-8 -*-

import abc

from cryptoparser.tls.version import TlsProtocolVersionFinal
from cryptoparser.tls.version import TlsVersion
from cryptoparser.tls.version import SslProtocolVersion

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys
from cryptolyzer.tls.pubkeyreq import AnalyzerPublicKeyRequest
from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
from cryptolyzer.tls.curves import AnalyzerCurves
from cryptolyzer.tls.dhparams import AnalyzerDHParams
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos
from cryptolyzer.tls.versions import AnalyzerVersions
from cryptolyzer.tls.all import AnalyzerAll


class ProtocolHandlerTlsBase(ProtocolHandlerBase):
    @classmethod
    @abc.abstractmethod
    def _get_protocol_version(cls):
        raise NotImplementedError()

    @classmethod
    def get_protocol(cls):
        return cls._get_protocol_version().identifier

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
        return (
            AnalyzerPublicKeys,
            AnalyzerCipherSuites,
        )

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
        return ProtocolHandlerSsl3.get_analyzers() + (
            AnalyzerPublicKeyRequest,
            AnalyzerCurves,
            AnalyzerDHParams,
        )

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
        return ProtocolHandlerTls11.get_analyzers() + (
            AnalyzerSigAlgos,
        )

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_2)


class ProtocolHandlerTlsVersionIndependent(ProtocolHandlerTlsBase):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerVersions,
            AnalyzerAll,
        )

    @classmethod
    def get_protocol(cls):
        return 'tls'

    @classmethod
    def _get_protocol_version(cls):
        return None
