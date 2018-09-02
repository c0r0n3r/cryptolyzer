#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.exception import NetworkError, NetworkErrorType

from cryptoparser.tls.client import TlsHandshakeClientHelloKeyExchangeDHE, TlsAlert
from cryptoparser.tls.subprotocol import TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.result import AnalyzerResultBase, DHParameter


class AnalyzerResultDHParams(AnalyzerResultBase):
    def __init__(self, dhparams):
        self.dhparams = dhparams


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
        dh_public_keys = []
        for _ in (1, 2):
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
                dh_public_keys.append(server_key_exchange_message.dh_public_key)

                if len(dh_public_keys) == 2:
                    dhparams.append(DHParameter(
                        dh_public_keys[0],
                        dh_public_keys[0].public_numbers().y == dh_public_keys[1].public_numbers(),
                    ))

        return AnalyzerResultDHParams(dhparams)