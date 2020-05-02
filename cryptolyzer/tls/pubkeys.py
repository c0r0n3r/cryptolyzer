# -*- coding: utf-8 -*-

import copy
from collections import OrderedDict
import attr

import cryptography.x509 as cryptography_x509

from cryptography.hazmat.backends import default_backend as cryptography_default_backend

from cryptoparser.common.base import Serializable
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloBasic,
    TlsHandshakeClientHelloAuthenticationDSS,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationECDSA
)
from cryptolyzer.tls.exception import TlsAlert

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
import cryptolyzer.common.x509


@attr.s(hash=False, eq=False)
class TlsCertificateChain(Serializable):  # pylint: disable=too-few-public-methods
    certificate_bytes = attr.ib()
    items = attr.ib()
    ordered = attr.ib(init=False, default=None, validator=attr.validators.optional(attr.validators.instance_of(bool)))
    verified = attr.ib(init=False, default=None, validator=attr.validators.optional(attr.validators.instance_of(bool)))

    def __attrs_post_init__(self):
        self.verified = None

        original_certificate_chain = copy.copy(self.items)
        ordered_certificate_chain = [cert for cert in original_certificate_chain if not cert.is_ca]

        while original_certificate_chain:
            try:
                issuer_certificate = self._get_issuer(original_certificate_chain, ordered_certificate_chain[-1])
                ordered_certificate_chain.append(issuer_certificate)
                original_certificate_chain.remove(issuer_certificate)
            except (StopIteration, IndexError):
                break

        if len(ordered_certificate_chain) > 1:
            self.ordered = self.items == ordered_certificate_chain
            self.items = ordered_certificate_chain

            for chain_index in range(len(self.items) - 1):
                issuer_public_key = self.items[chain_index + 1]
                cert_to_check = self.items[chain_index]

                if not issuer_public_key.verify(cert_to_check):
                    break
            else:
                self.verified = True
        else:
            self.ordered = None
            self.verified = None

    @staticmethod
    def _get_issuer(certificates, certificate):
        issuer_certificates = [
            issuer_certificate
            for issuer_certificate in certificates
            if issuer_certificate.is_ca and issuer_certificate.subject == certificate.issuer
        ]
        if len(issuer_certificates) == 1:
            return issuer_certificates[0]

        raise StopIteration()

    @property
    def contains_anchor(self):
        return any([cert.is_self_signed for cert in self.items])

    def __hash__(self):
        return hash(tuple([bytes(certificate_byte) for certificate_byte in self.certificate_bytes]))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def _asdict(self):
        return OrderedDict([
            ('items_chain', self.items),
            ('ordered', self.ordered),
            ('verified', self.verified),
            ('contains_anchor', self.contains_anchor),
        ])


@attr.s
class TlsPublicKey(Serializable):
    sni_sent = attr.ib(validator=attr.validators.instance_of(bool))
    subject_matches = attr.ib(validator=attr.validators.instance_of(bool))
    tls_certificate_chain = attr.ib(validator=attr.validators.instance_of(TlsCertificateChain))


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    pubkeys = attr.ib()


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
        certificate_bytes = []

        for tls_certificate in server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain:
            certificate = cryptography_x509.load_der_x509_certificate(
                bytes(tls_certificate.certificate),
                cryptography_default_backend()
            )
            certificate_bytes.append(tls_certificate.certificate)
            certificate_chain.append(cryptolyzer.common.x509.PublicKeyX509(certificate))

        return TlsCertificateChain(
            certificate_bytes=certificate_bytes,
            items=certificate_chain,
        )

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
                    raise StopIteration
            elif e.description not in [
                    TlsAlertDescription.HANDSHAKE_FAILURE,
                    TlsAlertDescription.INTERNAL_ERROR,
                    TlsAlertDescription.ILLEGAL_PARAMETER,
                    TlsAlertDescription.INSUFFICIENT_SECURITY
            ]:
                raise e
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e
        except SecurityError:
            if client_hello == client_hello_messages[0]:
                raise StopIteration

        return server_messages

    def analyze(self, analyzable, protocol_version):
        results = []
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(protocol_version),
            TlsHandshakeClientHelloAuthenticationDSS(protocol_version, analyzable.address),
            TlsHandshakeClientHelloAuthenticationRSA(protocol_version, analyzable.address),
            TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, analyzable.address),
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
                subject_matches = cryptolyzer.common.x509.is_subject_matches(
                    leaf_certificate.common_names,
                    leaf_certificate.subject_alternative_names,
                    analyzable.address
                )
                if ((sni_sent or subject_matches) and
                        certificate_chain not in [result.tls_certificate_chain for result in results]):
                    results.append(TlsPublicKey(sni_sent, subject_matches, certificate_chain))

        return AnalyzerResultPublicKeys(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            results
        )
