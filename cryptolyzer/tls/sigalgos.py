#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.algorithm import Authentication

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionServerName, TlsNamedCurve, TlsExtensionEllipticCurves
from cryptoparser.tls.extension import TlsSignatureAndHashAlgorithm, TlsExtensionSignatureAlgorithms, TlsExtensionSignatureAlgorithmsCert
from cryptoparser.tls.extension import TlsECPointFormat, TlsExtensionECPointFormats
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase, AnalyzerResultBase
from cryptolyzer.common.exception import NetworkError
from cryptolyzer.tls.client import TlsHandshakeClientHello, TlsAlert

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.extension import TlsExtensionSupportedVersions, TlsExtensionKeyShareReserved, TlsExtensionKeyShare

class AnalyzerResultSigAlgos(AnalyzerResultBase):  # pylint: disable=too-few-public-methods
    def __init__(self, sig_algos):
        self.sig_algos = [sig_algo.name for sig_algo in sig_algos]


class AnalyzerSigAlgos(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'sigalgos'

    @classmethod
    def get_help(cls):
        return 'Check which signature and hash algorithm combinations supported by the server(s)'

    def analyze(self, l7_client, protocol_version):
        supported_algorithms = []
        for authentication in [Authentication.DSS, Authentication.RSA, Authentication.ECDSA, Authentication.EDDSA]:
            cipher_suites = TlsCipherSuiteVector([
                cipher_suite
                for cipher_suite in TlsCipherSuite
                if cipher_suite.value.min_version > TlsProtocolVersionFinal(TlsVersion.TLS1_2)
                #(cipher_suite.value.key_exchange and cipher_suite.value.key_exchange.value.pfs and
                #    cipher_suite.value.authentication and cipher_suite.value.authentication == authentication)
            ])

            for algorithm in TlsSignatureAndHashAlgorithm:
                if algorithm.value.signature_algorithm != authentication:
                    continue

                client_hello = TlsHandshakeClientHello(
                    cipher_suites=cipher_suites,
                    extensions=[
                        TlsExtensionServerName(l7_client.host),
                        TlsExtensionECPointFormats(list(TlsECPointFormat)),
                        TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                        TlsExtensionSignatureAlgorithms([algorithm, ]),
                        TlsExtensionSignatureAlgorithmsCert(list(TlsSignatureAndHashAlgorithm)),
                        TlsExtensionSupportedVersions([TlsProtocolVersionFinal(TlsVersion.TLS1_3), ]),
                        TlsExtensionKeyShareReserved([]),
                        TlsExtensionKeyShare([]),
                    ]
                )

                try:
                    l7_client.do_tls_handshake(client_hello, client_hello.protocol_version)
                except TlsAlert as e:
                    acceptable_alerts = [TlsAlertDescription.HANDSHAKE_FAILURE, TlsAlertDescription.ILLEGAL_PARAMETER]
                    if e.description not in acceptable_alerts:
                        raise e
                except NetworkError:
                    pass
                else:
                    supported_algorithms.append(algorithm)
                finally:
                    del client_hello.extensions[-1]

        return AnalyzerResultSigAlgos(supported_algorithms)
