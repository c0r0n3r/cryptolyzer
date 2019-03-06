#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

import cryptography.x509 as cryptography_x509
from cryptography.hazmat.backends import default_backend as cryptography_default_backend

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

    def __hash__(self):
        return hash(tuple([bytes(certificate_byte) for certificate_byte in self._certificate_bytes]))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def as_json(self):
        return OrderedDict([
            ('items_chain', self.items),
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
                leaf_certificate = [cert for cert in certificate_chain.items if not cert.is_ca][0]
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
