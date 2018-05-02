#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime

from collections import OrderedDict

from cryptoparser.common.exception import NetworkError, NetworkErrorType
from cryptoparser.tls.client import TlsAlert, \
    TlsHandshakeClientHelloBasic, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerBase, AnalyzerResultBase


class AnalyzerResultCertificates(AnalyzerResultBase):
    def __init__(self, certificate_chains):
        now = datetime.datetime.now()
        self.certificate_chains = \
            [
                [
                    OrderedDict([
                        ('serial_number', str(certificate._certificate.serial_number)),
                        ('subject', OrderedDict(
                            [
                                (str(attribute.oid._name), attribute.value)
                                for attribute in certificate._certificate.subject
                            ]
                        )),
                        ('issuer', OrderedDict(
                            [
                                (str(attribute.oid._name), attribute.value)
                                for attribute in certificate._certificate.issuer
                            ]
                        )),
                        ('key_size', certificate._certificate.public_key().key_size),
                        ('signature_algorithm', certificate._certificate.signature_algorithm_oid._name),
                        ('validity', OrderedDict([
                            ('not_before', str(certificate._certificate.not_valid_before)),
                            ('not_after', str(certificate._certificate.not_valid_after)),
                            ('period', str(
                                certificate._certificate.not_valid_after -
                                certificate._certificate.not_valid_before
                            )),
                            ('remaining', str(
                                certificate._certificate.not_valid_after - now
                                if now < certificate._certificate.not_valid_after
                                else None
                            )),

                        ])),
                        ('version', str(certificate._certificate.version.name)),
                    ])
                    for certificate in certificate_chains
                ]
                for certificate_chain in certificate_chains
            ]


class AnalyzerCertificates(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'certificates'

    @classmethod
    def get_help(cls):
        return 'Check which certificate used by the server(s)'

    def analyze(self, l7_client):
        certificate_chains = set()
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(),
            TlsHandshakeClientHelloAuthenticationDSS(l7_client.host),
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.host),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.host),
        ]

        for client_hello in client_hello_messages:
            try:
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    client_hello.protocol_version,
                    TlsHandshakeType.CERTIFICATE
                )
            except TlsAlert as e:
                if e.description != TlsAlertDescription.HANDSHAKE_FAILURE:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                certificate_chains.add(server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain[0])

        return AnalyzerResultCertificates(certificate_chains)
