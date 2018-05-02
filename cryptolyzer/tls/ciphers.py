#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from cryptoparser.common.exception import NetworkError, NetworkErrorType

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.version import TlsProtocolVersionFinal

from cryptolyzer.common.analyzer import AnalyzerBase, AnalyzerResultBase
from cryptolyzer.tls.versions import AnalyzerVersions


class AnalyzerResultCipherSuites(AnalyzerResultBase):
    def __init__(self):
        self.cipher_suites = {}

    def add_cipher_suites(self, tls_version, cipher_suites):
        self.cipher_suites[tls_version] = cipher_suites

    def as_json(self):
        return json.dumps({
            'cipher_suites': {
                tls_version.name: [cipher_suite.name for cipher_suite in supported_cipher_suites]
                for tls_version, supported_cipher_suites in self.cipher_suites.items()
            }
        })


class AnalyzerCipherSuites(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which cipher suites supported by the server(s)'

    def analyze(self, l7_client):
        result = AnalyzerResultCipherSuites()
        for tls_version in AnalyzerVersions().analyze(l7_client).versions:
            accepted_cipher_suites = []
            remaining_cipher_suites = list(TlsCipherSuite)
            while True:
                try:
                    client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host)
                    client_hello.cipher_suites = TlsCipherSuiteVector(remaining_cipher_suites)
                    client_hello.protocol_version = TlsProtocolVersionFinal(tls_version)

                    server_messages = l7_client.do_tls_handshake(client_hello, client_hello.protocol_version)

                    server_cipher_suite = server_messages[TlsHandshakeType.SERVER_HELLO].cipher_suite

                    for index, cipher_suite in enumerate(remaining_cipher_suites):
                        if cipher_suite == server_cipher_suite:
                            del remaining_cipher_suites[index]
                            accepted_cipher_suites.append(cipher_suite)
                            break
                except TlsAlert as e:
                    if e.description == TlsAlertDescription.HANDSHAKE_FAILURE:
                        break
                    else:
                        raise e
                except NetworkError as e:
                    if e.error == NetworkErrorType.NO_RESPONSE:
                        break

            result.add_cipher_suites(tls_version, accepted_cipher_suites)

        return result
