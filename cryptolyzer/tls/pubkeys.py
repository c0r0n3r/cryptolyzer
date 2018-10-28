#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

import cryptography.x509 as cryptography_x509
from cryptography.hazmat.backends import default_backend as cryptography_default_backend

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.tls.client import TlsAlert, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls
import cryptolyzer.common.x509 as x509


class TlsPublicKey(object):  # pylint: disable=too-few-public-methods
    def __init__(self, certificate_bytes, certificate_chain):
        self._certificate_bytes = certificate_bytes
        self.certificate_chain = certificate_chain

    def __hash__(self):
        return hash(tuple([bytes(certificate_byte) for certificate_byte in self._certificate_bytes]))

    def __eq__(self, other):
        return hash(self) == hash(other)


class AnalyzerResultPublicKeys(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, pubkeys, host_name):
        self.host_name = host_name
        self.pubkeys = pubkeys


class AnalyzerPublicKeys(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which certificate used by the server(s)'

    @staticmethod
    def _get_tls_public_key(server_messages):
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
                certificate_chain.append(x509.PublicKeyX509(certificate))

        return TlsPublicKey(
            certificate_bytes=certificate_bytes,
            certificate_chain=certificate_chain,
        )

    def analyze(self, l7_client, protocol_version):
        results = []
        client_hello_messages = [
            TlsHandshakeClientHelloAuthenticationDSS(l7_client.host),
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.host),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.host),
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
                tls_public_key = self._get_tls_public_key(server_messages)
                results.append(OrderedDict([
                    ('pubkey', tls_public_key),
                ]))

        return AnalyzerResultPublicKeys(results, l7_client.host)
