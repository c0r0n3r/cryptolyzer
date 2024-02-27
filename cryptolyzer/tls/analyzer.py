# -*- coding: utf-8 -*-

from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.analyzer import ProtocolHandlerTlsBase, ProtocolHandlerTlsExactVersion
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys
from cryptolyzer.tls.pubkeyreq import AnalyzerPublicKeyRequest
from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
from cryptolyzer.tls.curves import AnalyzerCurves
from cryptolyzer.tls.dhparams import AnalyzerDHParams
from cryptolyzer.tls.extensions import AnalyzerExtensions
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos
from cryptolyzer.tls.simulations import AnalyzerSimulations
from cryptolyzer.tls.versions import AnalyzerVersions
from cryptolyzer.tls.vulnerabilities import AnalyzerVulnerabilities
from cryptolyzer.tls.all import AnalyzerAll


class ProtocolHandlerSsl2(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerPublicKeys,
            AnalyzerCipherSuites,
        )

    @classmethod
    def get_protocol_version(cls):
        return TlsProtocolVersion(TlsVersion.SSL2)


class ProtocolHandlerSsl3(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerSsl2.get_analyzers() + (
            AnalyzerPublicKeyRequest,
            AnalyzerDHParams,
        )

    @classmethod
    def get_protocol_version(cls):
        return TlsProtocolVersion(TlsVersion.SSL3)


class ProtocolHandlerTls10(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerSsl3.get_analyzers() + (
            AnalyzerCurves,
        )

    @classmethod
    def get_protocol_version(cls):
        return TlsProtocolVersion(TlsVersion.TLS1)


class ProtocolHandlerTls11(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerTls10.get_analyzers()

    @classmethod
    def get_protocol_version(cls):
        return TlsProtocolVersion(TlsVersion.TLS1_1)


class ProtocolHandlerTls12(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerTls11.get_analyzers() + (
            AnalyzerSigAlgos,
            AnalyzerExtensions,
        )

    @classmethod
    def get_protocol_version(cls):
        return TlsProtocolVersion(TlsVersion.TLS1_2)


class ProtocolHandlerTls13(ProtocolHandlerTlsExactVersion):
    @classmethod
    def get_analyzers(cls):
        analyzers = ProtocolHandlerTls12.get_analyzers()

        # Temporarily remove analyzers need encrypted packets
        return tuple(filter(
            lambda analyzer: analyzer not in [AnalyzerPublicKeys, AnalyzerPublicKeyRequest, ],
            analyzers
        ))

    @classmethod
    def get_protocol_version(cls):
        return TlsProtocolVersion(TlsVersion.TLS1_3)


class ProtocolHandlerTlsVersionIndependent(ProtocolHandlerTlsBase):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerVersions,
            AnalyzerAll,
            AnalyzerSimulations,
            AnalyzerVulnerabilities,
        )

    @classmethod
    def get_protocol(cls):
        return 'tls'

    @classmethod
    def get_protocol_version(cls):
        return None
