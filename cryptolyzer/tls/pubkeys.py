#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

import cryptography
import cryptography.x509 as cryptography_x509
import cryptography.x509.ocsp as cryptography_ocsp
import cryptography.hazmat.primitives.asymmetric.rsa as cryptography_rsa
import cryptography.hazmat.primitives.asymmetric.ec as cryptography_ec

from cryptography.hazmat.backends import default_backend as cryptography_default_backend
from cryptography.hazmat.primitives.asymmetric import padding as cryptography_padding

from cryptoparser.common.base import JSONSerializable
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.tls.client import TlsAlert, \
    TlsHandshakeClientHelloBasic, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
import cryptolyzer.common.x509


class TlsCertificateChain(JSONSerializable):  # pylint: disable=too-few-public-methods
    def __init__(self, certificate_bytes, certificate_chain):
        self._certificate_bytes = certificate_bytes
        self.items = certificate_chain
        self.verified = None

        ordered_certificate_chain = [cert for cert in certificate_chain if not cert.is_ca]
        self.complete = len(ordered_certificate_chain) == 1

        while len(ordered_certificate_chain) <= len(self.items):
            try:
                next_certificate = self.next_issuer(ordered_certificate_chain[-1].issuer)
                ordered_certificate_chain.append(next_certificate)
            except StopIteration:
                break

        if self.complete:
            self.ordered = self.items == ordered_certificate_chain
            self.items = ordered_certificate_chain

            self.verified = False
            for chain_index in range(len(self.items) - 1):
                issuer_public_key = self.items[chain_index + 1].public_key()
                cert_to_check = self.items[chain_index]

                if not self._is_signed_verifiable(issuer_public_key, cert_to_check):
                    break
            else:
                self.verified = True

    @staticmethod
    def _is_signed_verifiable(issuer_public_key, cert_to_check):
        verify_args = {
            'signature': cert_to_check.signature,
            'data': cert_to_check.tbs_certificate_bytes,
        }
        if isinstance(issuer_public_key, cryptography_rsa.RSAPublicKey):
            verify_args['padding'] = cryptography_padding.PKCS1v15()
        if isinstance(issuer_public_key, cryptography_ec.EllipticCurvePublicKey):
            verify_args['signature_algorithm'] = cryptography_ec.ECDSA(
                    cert_to_check._certificate.signature_hash_algorithm
            )
        else:
            verify_args['algorithm'] = cert_to_check._certificate.signature_hash_algorithm

        try:
            issuer_public_key.verify(**verify_args)
        except cryptography.exceptions.InvalidSignature:
             return False

        return True

    def next_issuer(self, issuer):
        next_certificates = [
            certificate
            for certificate in self.items
            if certificate.is_ca and certificate.subject == issuer
        ]
        if len(next_certificates) == 1:
            return next_certificates[0]

        raise StopIteration()

    def __hash__(self):
        return hash(tuple([bytes(certificate_byte) for certificate_byte in self._certificate_bytes]))

    def __eq__(self, other):
        return hash(self) == hash(other)

    @property
    def contains_anchor(self):
        return any([cert.is_self_signed for cert in self.items])

    def as_json(self):
        return OrderedDict([
            ('items_chain', self.items),
            ('complete', self.complete),
            ('ordered', self.ordered),
            ('verified', self.verified),
            ('contains_anchor', self.contains_anchor),
        ])


class TlsPublicKey(JSONSerializable):
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
            try:
                certificate = cryptography_x509.load_der_x509_certificate(
                    bytes(tls_certificate.certificate),
                    cryptography_default_backend()
                )
            except ValueError:
                pass
            else:
                certificate_bytes.append(tls_certificate.certificate)
                certificate_chain.append(cryptolyzer.common.x509.PublicKeyX509(certificate))

        return TlsCertificateChain(
            certificate_bytes=certificate_bytes,
            certificate_chain=certificate_chain,
        )

    def analyze(self, l7_client, protocol_version):
        results = []
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(),
            TlsHandshakeClientHelloAuthenticationDSS(l7_client.address),
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.address),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.address),
        ]

        for client_hello in client_hello_messages:
            try:
                client_hello.protocol_version = protocol_version
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    client_hello.protocol_version,
                    TlsHandshakeType.CERTIFICATE
                )
            except TlsAlert as e:
                if (e.description != TlsAlertDescription.HANDSHAKE_FAILURE and
                        e.description != TlsAlertDescription.PROTOCOL_VERSION):
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                sni_sent = not isinstance(client_hello, TlsHandshakeClientHelloBasic)
                certificate_chain = self._get_tls_certificate_chain(server_messages)
                leaf_certificate = certificate_chain.items[0]
                subject_matches = cryptolyzer.common.x509.is_subject_matches(
                    leaf_certificate.common_names,
                    leaf_certificate.subject_alternative_names,
                    l7_client.address
                )
                if ((not sni_sent and not subject_matches) or
                        certificate_chain in [result.certificate_chain for result in results]):
                    continue

                results.append(TlsPublicKey(sni_sent, subject_matches, certificate_chain))

        return AnalyzerResultPublicKeys(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            results
        )
