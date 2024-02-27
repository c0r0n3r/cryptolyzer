# -*- coding: utf-8 -*-

from collections import OrderedDict

import six

import attr

import asn1crypto.x509

from cryptodatahub.tls.algorithm import TlsSignatureAndHashAlgorithm
from cryptoparser.tls.subprotocol import (
    TlsAlertDescription,
    TlsClientCertificateType,
    TlsHandshakeType,
)

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationDeprecated,
)
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultPublicKeyRequest(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to the client authentication (cerificate-based)

    :param certificate_types: types of certificate accepted for authentication
    :param signature_algorithms: signature algorithms accepted for authentication
    :param distinguished_names: distinguished names (DN) of certificates accepted for authentication
    """

    certificate_types = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.in_(TlsClientCertificateType)
        ))
    )
    supported_signature_algorithms = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.in_(TlsSignatureAndHashAlgorithm)
        ))
    )
    distinguished_names = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(OrderedDict)
        ))
    )


class AnalyzerPublicKeyRequest(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'pubkeyreq'

    @classmethod
    def get_help(cls):
        return 'Check whether client public key is required by the server(s)'

    @staticmethod
    def _analyze_requierd_certificates(analyzable, protocol_version):
        client_hello_messsages_in_order_of_probability = (
            TlsHandshakeClientHelloAuthenticationRSA(protocol_version, analyzable.address),
            TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, analyzable.address),
            TlsHandshakeClientHelloAuthenticationDeprecated(protocol_version, analyzable.address),
        )
        for client_hello in client_hello_messsages_in_order_of_probability:
            try:
                server_messages = analyzable.do_tls_handshake(
                    hello_message=client_hello,
                    last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
                )
            except TlsAlert as e:
                if e.description == TlsAlertDescription.UNRECOGNIZED_NAME:
                    break
                if e.description in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS:
                    break

                raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            except SecurityError:
                break
            else:
                if TlsHandshakeType.CERTIFICATE_REQUEST in server_messages:
                    distinguished_names = None

                    certificate_request = server_messages[TlsHandshakeType.CERTIFICATE_REQUEST]
                    if certificate_request.certificate_authorities:
                        distinguished_names = []
                        for certificate_authority in certificate_request.certificate_authorities:
                            try:
                                distinguished_names.append(
                                    asn1crypto.x509.Name.load(bytes(bytearray(certificate_authority))).native
                                )
                            except ValueError:
                                pass

                    LogSingleton().log(level=60, msg=six.u('Server requests X.509 for client authentication'))
                    return (
                        list(certificate_request.certificate_types),
                        list(certificate_request.supported_signature_algorithms),
                        distinguished_names,
                    )

                break

        return None, None, None

    def analyze(self, analyzable, protocol_version):
        certificate_types, supported_signature_algorithms, distinguished_names = \
            self._analyze_requierd_certificates(analyzable, protocol_version)

        return AnalyzerResultPublicKeyRequest(
            target=AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            certificate_types=certificate_types,
            supported_signature_algorithms=supported_signature_algorithms,
            distinguished_names=distinguished_names,
        )
