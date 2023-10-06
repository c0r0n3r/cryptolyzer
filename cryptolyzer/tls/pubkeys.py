# -*- coding: utf-8 -*-

import attr

import six

import asn1crypto.ocsp

from cryptoparser.common.base import Serializable
from cryptoparser.common.x509 import SignedCertificateTimestampList
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.extension import (
    TlsExtensionCertificateStatusRequestClient,
    TlsExtensionSignedCertificateTimestampClient,
    TlsExtensionType,
    TlsCertificateStatusType,
)

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.common.x509 import (
    CertificateChainX509,
    CertificateChainX509Validator,
    CertificateStatus,
    PublicKeyX509,
)
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAuthenticationDSS,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationGOST,
)
from cryptolyzer.tls.exception import TlsAlert

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls


@attr.s
class CertificateChainTls(Serializable):
    """
    :class: Analyzer result relates to a certificate chain

    :param sni_sent: whether server name indication (SNI) extension is used by the client when the server sent the
        chain.
    :param subject_matches: whether the subject (common name) of the leaf certificate in the chain mathes the analyzed
        server's fully qualified domain name.
    :param certificate_chain: the list of X.509 certificates sent in the chain.
    :param certificate_status: certificate status (OCSP staple) relate to the leaf certificate in the chain.
    :param scts: list of signed certificate timestamp (SCT) relate to the certificate in the chain.
    """

    sni_sent = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Server Name Indication (SNI)'}
    )
    subject_matches = attr.ib(validator=attr.validators.instance_of(bool))
    certificate_chain = attr.ib(
        validator=attr.validators.instance_of(CertificateChainX509),
    )
    certificate_status = attr.ib(
        default=None, eq=False,
        validator=attr.validators.optional(attr.validators.instance_of(CertificateStatus))
    )
    scts = attr.ib(
        default=None, eq=False,
        validator=attr.validators.optional(attr.validators.instance_of(SignedCertificateTimestampList)),
        metadata={'human_readable_name': 'Signed Certificate Timestamps'}
    )


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to the signature algorithms.

    :param pubkeys: list of the certificate chains sent by the server.
    """

    pubkeys = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(CertificateChainTls)),
        metadata={'human_readable_name': 'TLS Certificates'},
    )


class AnalyzerPublicKeys(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which certificate used by the server(s)'

    @classmethod
    def _get_certificate_status(cls, server_messages):
        if TlsHandshakeType.CERTIFICATE_STATUS in server_messages:
            status_message = server_messages[TlsHandshakeType.CERTIFICATE_STATUS]
            if status_message.status_type == TlsCertificateStatusType.OCSP:
                ocsp_response = asn1crypto.ocsp.OCSPResponse.load(bytes(status_message.status))
                if ocsp_response['response_status'].native == 'successful':
                    return CertificateStatus(
                        asn1crypto.ocsp.OCSPResponse.load(bytes(status_message.status))
                    )

        # Server may send the same certificate chain independently that client hello conatins SNI exetension, however
        # OCSP staple not necessarily sent in both cases. New status values stored only if no one had # already stored.
        raise KeyError()

    @classmethod
    def _get_signed_certificate_timestamps(cls, server_messages):
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        sct_extension = server_hello.extensions.get_item_by_type(TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP)

        return sct_extension.scts

    @classmethod
    def _add_tls_public_key_to_results(cls, analyzable, sni_sent, server_messages, results):
        if TlsHandshakeType.CERTIFICATE not in server_messages:
            return

        x509_public_keys = [
            PublicKeyX509.from_der(public_key_bytes.certificate)
            for public_key_bytes in server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain
        ]

        try:
            certificate_status = cls._get_certificate_status(server_messages)
        except KeyError:
            certificate_status = None

        certificate_chain = CertificateChainX509Validator()(
            items=x509_public_keys,
            certificate_status_list=[] if certificate_status is None else [certificate_status]
        )

        leaf_certificate = certificate_chain.items[0]
        subject_matches = leaf_certificate.is_subject_matches(six.ensure_str(analyzable.address))
        if sni_sent or subject_matches:
            for result in results:
                if certificate_chain == result.certificate_chain:
                    tls_public_key = result
                    break
            else:
                tls_public_key = CertificateChainTls(
                    sni_sent=sni_sent,
                    subject_matches=subject_matches,
                    certificate_chain=certificate_chain,
                )
                LogSingleton().log(level=60, msg=six.u('Server offers %s X.509 public key (with%s SNI)') % (
                    tls_public_key.certificate_chain.items[-1].key_type.name,
                    '' if tls_public_key.sni_sent else 'out',
                ))
                results.append(tls_public_key)

            tls_public_key.certificate_status = certificate_status

            try:
                tls_public_key.scts = cls._get_signed_certificate_timestamps(server_messages)
            except KeyError:
                pass

    @staticmethod
    def _get_server_messages(l7_client, client_hello, sni_sent, client_hello_messages):
        server_messages = []

        try:
            server_messages = l7_client.do_tls_handshake(
                client_hello,
                last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
            )
        except TlsAlert as e:
            if e.description == TlsAlertDescription.UNRECOGNIZED_NAME:
                if sni_sent:
                    six.raise_from(StopIteration, e)
            elif e.description not in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                    TlsAlertDescription.INTERNAL_ERROR,
                    TlsAlertDescription.DECODE_ERROR,
            ]:
                raise e
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e
        except SecurityError as e:
            if e.error != SecurityErrorType.UNPARSABLE_MESSAGE and client_hello == client_hello_messages[0]:
                six.raise_from(StopIteration, e)

        return server_messages

    def analyze(self, analyzable, protocol_version):
        results = []

        for hostname in [None, analyzable.address]:
            client_hello_messages = [
                TlsHandshakeClientHelloAuthenticationDSS(protocol_version, hostname),
                TlsHandshakeClientHelloAuthenticationRSA(protocol_version, hostname),
                TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, hostname),
                TlsHandshakeClientHelloAuthenticationGOST(protocol_version, hostname),
            ]
            for client_hello in client_hello_messages:
                sni_sent = hostname is not None
                client_hello.extensions.extend([
                    TlsExtensionCertificateStatusRequestClient(),
                    TlsExtensionSignedCertificateTimestampClient(),
                ])
                try:
                    server_messages = self._get_server_messages(
                        analyzable, client_hello, sni_sent, client_hello_messages
                    )
                except StopIteration:
                    break

                if not server_messages:
                    continue

                self._add_tls_public_key_to_results(analyzable, sni_sent, server_messages, results)

        return AnalyzerResultPublicKeys(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            results
        )
