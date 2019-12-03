# -*- coding: utf-8 -*-

import copy

from collections import OrderedDict

import cryptography.x509 as cryptography_x509

from cryptography.hazmat.backends import default_backend as cryptography_default_backend

from cryptoparser.common.base import Serializable
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.tls.client import TlsAlert, \
    TlsHandshakeClientHelloBasic, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, ResponseError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
import cryptolyzer.common.x509


class TlsCertificateChain(Serializable):  # pylint: disable=too-few-public-methods
    def __init__(self, certificate_bytes, certificate_chain):
        self._certificate_bytes = certificate_bytes
        self.items = certificate_chain
        self.verified = None

        original_certificate_chain = copy.copy(certificate_chain)
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
        return hash(tuple([bytes(certificate_byte) for certificate_byte in self._certificate_bytes]))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def _asdict(self):
        return OrderedDict([
            ('items_chain', self.items),
            ('ordered', self.ordered),
            ('verified', self.verified),
            ('contains_anchor', self.contains_anchor),
        ])


class TlsPublicKey(Serializable):
    def __init__(self, sni_sent, subject_matches, tls_certificate_chain):
        self.sni_sent = sni_sent
        self.subject_matches = subject_matches
        self.certificate_chain = tls_certificate_chain


class AnalyzerResultPublicKeys(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, target, tls_public_keys):
        super(AnalyzerResultPublicKeys, self).__init__(target)

        self.pubkeys = tls_public_keys


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
            certificate_chain=certificate_chain,
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
        except ResponseError:
            if client_hello == client_hello_messages[0]:
                raise StopIteration

        return server_messages

    def analyze(self, l7_client, protocol_version):
        results = []
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(protocol_version),
            TlsHandshakeClientHelloAuthenticationDSS(protocol_version, l7_client.address),
            TlsHandshakeClientHelloAuthenticationRSA(protocol_version, l7_client.address),
            TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, l7_client.address),
        ]

        for client_hello in client_hello_messages:
            sni_sent = not isinstance(client_hello, TlsHandshakeClientHelloBasic)
            try:
                server_messages = self._get_server_messages(l7_client, client_hello, sni_sent, client_hello_messages)
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
                    l7_client.address
                )
                if ((sni_sent or subject_matches) and
                        certificate_chain not in [result.certificate_chain for result in results]):
                    results.append(TlsPublicKey(sni_sent, subject_matches, certificate_chain))

        return AnalyzerResultPublicKeys(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            results
        )
