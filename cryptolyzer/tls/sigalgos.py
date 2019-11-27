# -*- coding: utf-8 -*-

from cryptoparser.common.algorithm import Authentication

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionServerName, TlsNamedCurve, TlsExtensionEllipticCurves
from cryptoparser.tls.extension import TlsSignatureAndHashAlgorithm, TlsExtensionSignatureAlgorithms
from cryptoparser.tls.extension import TlsECPointFormat, TlsExtensionECPointFormats
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsAlertDescription, TlsHandshakeClientHello

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, ResponseError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsAlert


class AnalyzerResultSigAlgos(AnalyzerResultTls):
    def __init__(self, target, sig_algos):
        super(AnalyzerResultSigAlgos, self).__init__(target)

        self.sig_algos = sig_algos


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
                extensions=[
                    TlsExtensionServerName(l7_client.address),
                    TlsExtensionECPointFormats(list(TlsECPointFormat)),
                    TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                    TlsExtensionSignatureAlgorithms([algorithm, ]),
                ]
            )

            try:
                l7_client.do_tls_handshake(client_hello)
            except TlsAlert as e:
                if (algorithm == matching_algorithms[0] and
                        e.description in [TlsAlertDescription.PROTOCOL_VERSION, TlsAlertDescription.UNRECOGNIZED_NAME]):
                    break

                acceptable_alerts = [
                    TlsAlertDescription.HANDSHAKE_FAILURE,
                    TlsAlertDescription.ILLEGAL_PARAMETER,
                    TlsAlertDescription.INTERNAL_ERROR
                ]
                if e.description not in acceptable_alerts:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            except ResponseError:
                if algorithm == matching_algorithms[0]:
                    break

                continue
            else:
                supported_algorithms.append(algorithm)
            finally:
                del client_hello.extensions[-1]

        return supported_algorithms

    def analyze(self, l7_client, protocol_version):
        supported_algorithms = []
        for authentication in [Authentication.DSS, Authentication.RSA, Authentication.ECDSA]:
            cipher_suites = TlsCipherSuiteVector([
                cipher_suite
                for cipher_suite in TlsCipherSuite
                if (cipher_suite.value.key_exchange and cipher_suite.value.key_exchange.value.fs and
                    cipher_suite.value.authentication and cipher_suite.value.authentication == authentication)
            ])

            matching_algorithms = [
                algorithm
                for algorithm in TlsSignatureAndHashAlgorithm
                if algorithm.value.signature_algorithm == authentication
            ]
            supported_algorithms.extend(
                self._analyze_algorithms(l7_client, protocol_version, cipher_suites, matching_algorithms)
            )

        return AnalyzerResultSigAlgos(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            supported_algorithms
        )
