#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.base import TwoByteEnumComposer, TwoByteEnumParsable

from cryptoparser.ssh.subprotocol import SshKeyExchangeInit

from cryptolyzer.common.analyzer import AnalyzerSshBase, AnalyzerResultSsh
from cryptolyzer.common.exception import NetworkError, NetworkErrorType


class AnalyzerResultCiphers(AnalyzerResultSsh):
    def __init__(
        self,
        kex_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        ):

        self.kex_algorithms = kex_algorithms
        self.encryption_algorithms = {
            'client_to_server': encryption_algorithms_client_to_server,
            'server_to_client': encryption_algorithms_server_to_client,
        }
        self.mac_algorithms = {
            'client_to_server': mac_algorithms_client_to_server,
            'server_to_client': mac_algorithms_server_to_client,
        }


class AnalyzerCiphers(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which cipher suites supported by the server(s)'

    def analyze(self, l7_client):
        try:
            server_messages = l7_client.do_handshake(last_message_type=SshKeyExchangeInit)
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e

        key_exchange_init_message = server_messages[SshKeyExchangeInit]
        return AnalyzerResultCiphers(
            key_exchange_init_message.kex_algorithms,
            key_exchange_init_message.encryption_algorithms_client_to_server,
            key_exchange_init_message.encryption_algorithms_server_to_client,
            key_exchange_init_message.mac_algorithms_client_to_server,
            key_exchange_init_message.mac_algorithms_server_to_client,
        )

