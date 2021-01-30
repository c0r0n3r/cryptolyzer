# -*- coding: utf-8 -*-

import attr

import six

import asn1crypto.x509
import certvalidator

from cryptoparser.common.base import Serializable
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloBasic,
    TlsHandshakeClientHelloAuthenticationDSS,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationGOST,
)
from cryptolyzer.tls.exception import TlsAlert

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
import cryptolyzer.common.x509


@attr.s
class TlsCertificateChain(Serializable):  # pylint: disable=too-few-public-methods
    items = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(cryptolyzer.common.x509.PublicKeyX509)),
        metadata={'human_readable_name': 'Certificates in Chain'},
    )
    ordered = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )
    verified = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )
    contains_anchor = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )

    def __attrs_post_init__(self):
        cert_validator = certvalidator.CertificateValidator(
            self.items[0].certificate,
            [item.certificate for item in self.items[1:]]
        )
        try:
            build_path = cert_validator.validate_usage(set())
        except certvalidator.errors.PathBuildingError:
            pass
        except (certvalidator.errors.InvalidCertificateError, certvalidator.errors.PathValidationError):
            if self.items[-1].is_self_signed:
                self.contains_anchor = True
        else:
            self.verified = True
            validated_items = [cryptolyzer.common.x509.PublicKeyX509(item) for item in reversed(build_path)]
            self.ordered = validated_items[:len(self.items)] == self.items
            self.contains_anchor = len(self.items) == len(validated_items)


@attr.s
class TlsPublicKey(Serializable):
    sni_sent = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Server Name Indication (SNI)'}
    )
    subject_matches = attr.ib(validator=attr.validators.instance_of(bool))
    tls_certificate_chain = attr.ib(
        validator=attr.validators.instance_of(TlsCertificateChain),
        metadata={'human_readable_name': 'Certificate Chain'}
    )


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    pubkeys = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsPublicKey)),
        metadata={'human_readable_name': 'TLS Certificates'},
    )


class AnalyzerPublicKeys(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which certificate used by the server(s)'

    @staticmethod
    def _get_tls_certificate_chain(server_messages):
        certificate_chain = []

        for tls_certificate in server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain:
            certificate = asn1crypto.x509.Certificate.load(tls_certificate.certificate)
            certificate_chain.append(cryptolyzer.common.x509.PublicKeyX509(certificate))

        return TlsCertificateChain(items=certificate_chain)

    @staticmethod
    def _get_server_messages(l7_client, client_hello, sni_sent, client_hello_messages):
        server_messages = []

        try:
            server_messages = l7_client.do_tls_handshake(
                client_hello,
                last_handshake_message_type=TlsHandshakeType.CERTIFICATE
            )
        except TlsAlert as e:
            if e.description == TlsAlertDescription.UNRECOGNIZED_NAME:
                if sni_sent:
                    six.raise_from(StopIteration, e)
            elif e.description not in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                    TlsAlertDescription.INTERNAL_ERROR
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
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(protocol_version),
            TlsHandshakeClientHelloAuthenticationDSS(protocol_version, analyzable.address),
            TlsHandshakeClientHelloAuthenticationRSA(protocol_version, analyzable.address),
            TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, analyzable.address),
            TlsHandshakeClientHelloAuthenticationGOST(protocol_version, analyzable.address),
        ]

        for client_hello in client_hello_messages:
            sni_sent = not isinstance(client_hello, TlsHandshakeClientHelloBasic)
            try:
                server_messages = self._get_server_messages(analyzable, client_hello, sni_sent, client_hello_messages)
            except StopIteration:
                break

            if not server_messages:
                continue

            try:
                certificate_chain = self._get_tls_certificate_chain(server_messages)
            except ValueError:
                continue
            else:
                leaf_certificate = certificate_chain.items[0]
                subject_matches = leaf_certificate.is_subject_matches(six.u(analyzable.address))
                if ((sni_sent or subject_matches) and
                        certificate_chain not in [result.tls_certificate_chain for result in results]):
                    results.append(TlsPublicKey(sni_sent, subject_matches, certificate_chain))

        return AnalyzerResultPublicKeys(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            results
        )
