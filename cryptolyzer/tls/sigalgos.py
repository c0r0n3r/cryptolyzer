# -*- coding: utf-8 -*-

import six

import attr

from cryptodatahub.tls.algorithm import TlsSignatureAndHashAlgorithm

from cryptoparser.tls.extension import TlsExtensionSignatureAlgorithms, TlsSignatureAndHashAlgorithmVector
from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAuthenticationDSS,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationGOST,
    TlsHandshakeClientHelloAuthenticationRSA,
)
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultSigAlgos(AnalyzerResultTls):
    """
    :class: Analyzer result relates to the signature algorithms

    :param certificate_types: supported signature algorithms (can be negotiated using signature algorithms extension)
    """

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
    def _analyze_algorithms(l7_client, client_hello):
        supported_algorithms = []
        extension = client_hello.extensions.get_item_by_type(
            TlsExtensionSignatureAlgorithms.get_extension_type()
        )
        for algorithm in extension.hash_and_signature_algorithms:
            extension.hash_and_signature_algorithms = TlsSignatureAndHashAlgorithmVector([algorithm, ])
            try:
                l7_client.do_tls_handshake(
                    client_hello, last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
                )
            except TlsAlert as e:
                if algorithm == extension.hash_and_signature_algorithms[0]:
                    if e.description in [TlsAlertDescription.PROTOCOL_VERSION, TlsAlertDescription.UNRECOGNIZED_NAME]:
                        break

                acceptable_alerts = AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                    TlsAlertDescription.DECODE_ERROR,
                    TlsAlertDescription.INTERNAL_ERROR,
                ]
                if e.description not in acceptable_alerts:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            except SecurityError:
                break
            else:
                LogSingleton().log(level=60, msg=six.u('Server offers signature algorithm %s') % (algorithm.name, ))
                supported_algorithms.append(algorithm)

        return supported_algorithms

    def analyze(self, analyzable, protocol_version):
        supported_algorithms = []
        for client_hello_class in [
                    TlsHandshakeClientHelloAuthenticationRSA,
                    TlsHandshakeClientHelloAuthenticationECDSA,
                    TlsHandshakeClientHelloAuthenticationDSS,
                    TlsHandshakeClientHelloAuthenticationGOST,
                ]:
            client_hello = client_hello_class(
                protocol_version=protocol_version,
                hostname=analyzable.address,
            )
            supported_algorithms.extend(
                self._analyze_algorithms(analyzable, client_hello)
            )

        return AnalyzerResultSigAlgos(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            supported_algorithms
        )
