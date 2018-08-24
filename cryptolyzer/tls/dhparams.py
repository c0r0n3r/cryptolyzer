#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives import serialization

from cryptoparser.common.exception import NetworkError, NetworkErrorType

from cryptoparser.tls.client import TlsHandshakeClientHelloKeyExchangeDHE, TlsAlert
from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerTlsBase, AnalyzerResultBase


class AnalyzerResultDHParams(AnalyzerResultBase):
    def __init__(self, dhparams):
        print(dhparams[0].public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        self.dhparams = dhparams

    def as_json(self):
        return json.dumps({'dhparams': [repr(version) for dhparam in self.dhparams]})


class AnalyzerDHParams(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check DH parameters offered by the server(s)'

    def analyze(self, l7_client, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeDHE(l7_client.host)

        dhparams = []
        try:
            server_messages = l7_client.do_tls_handshake(
                client_hello,
                client_hello.protocol_version,
                TlsHandshakeType.SERVER_KEY_EXCHANGE)
        except TlsAlert as e:
            pass
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e
        else:
            server_key_exchange_message = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
            server_key_exchange_message.parse_dh_params()
            dhparams.append(server_key_exchange_message.dh_public_key)

        return AnalyzerResultDHParams(dhparams)
