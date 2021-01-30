# -*- coding: utf-8 -*-

import attr

from cryptoparser.common.algorithm import Authentication

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensions
from cryptoparser.tls.extension import (
    TlsECPointFormatVector,
    TlsExtensionEllipticCurves,
    TlsExtensionServerName,
    TlsNamedCurve,
)
from cryptoparser.tls.extension import (
    TlsExtensionSignatureAlgorithms,
    TlsSignatureAndHashAlgorithm,
    TlsSignatureAndHashAlgorithmVector,
)
from cryptoparser.tls.extension import TlsECPointFormat, TlsExtensionECPointFormats, TlsEllipticCurveVector
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsAlertDescription, TlsHandshakeClientHello

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultSigAlgos(AnalyzerResultTls):
    sig_algos = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsSignatureAndHashAlgorithm)),
        metadata={'human_readable_name': 'Signature Algorithms'}
    )


class AnalyzerSigAlgos(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'sigalgos'

    @classmethod
    def get_help(cls):
        return 'Check which signature and hash algorithm combinations supported by the server(s)'

    @staticmethod
    def _analyze_algorithms(l7_client, protocol_version, cipher_suites, matching_algorithms):
        supported_algorithms = []
        for algorithm in matching_algorithms:
            client_hello = TlsHandshakeClientHello(
                protocol_version=protocol_version,
                cipher_suites=cipher_suites,
                extensions=TlsExtensions([
                    TlsExtensionServerName(l7_client.address),
                    TlsExtensionECPointFormats(TlsECPointFormatVector(list(TlsECPointFormat))),
                    TlsExtensionEllipticCurves(TlsEllipticCurveVector(list(TlsNamedCurve))),
                    TlsExtensionSignatureAlgorithms(TlsSignatureAndHashAlgorithmVector([algorithm, ])),
                ])
            )

            try:
                l7_client.do_tls_handshake(client_hello)
            except TlsAlert as e:
                if (algorithm == matching_algorithms[0] and
                        e.description in [TlsAlertDescription.PROTOCOL_VERSION, TlsAlertDescription.UNRECOGNIZED_NAME]):
                    break

                if e.description not in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            except SecurityError:
                if algorithm == matching_algorithms[0]:
                    break

                continue
            else:
                supported_algorithms.append(algorithm)
            finally:
                del client_hello.extensions[-1]

        return supported_algorithms

    def analyze(self, analyzable, protocol_version):
        supported_algorithms = []
        for authentication in [Authentication.DSS, Authentication.RSA, Authentication.ECDSA]:
            cipher_suites = TlsCipherSuiteVector([
                cipher_suite
                for cipher_suite in TlsCipherSuite
                if (cipher_suite.value.key_exchange and cipher_suite.value.key_exchange.value.forward_secret and
                    cipher_suite.value.authentication and cipher_suite.value.authentication == authentication)
            ])

            matching_algorithms = [
                algorithm
                for algorithm in TlsSignatureAndHashAlgorithm
                if algorithm.value.signature_algorithm == authentication
            ]
            supported_algorithms.extend(
                self._analyze_algorithms(analyzable, protocol_version, cipher_suites, matching_algorithms)
            )

        return AnalyzerResultSigAlgos(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            supported_algorithms
        )
