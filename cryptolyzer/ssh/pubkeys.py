#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.base import TwoByteEnumComposer, TwoByteEnumParsable

from cryptoparser.ssh.subprotocol import SshECDHKeyExchangeReply

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.result import AnalyzerResultBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType

from cryptolyzer.ssh.client import SshDisconnect
from cryptolyzer.ssh.client import SshKeyExchangeInitHostKeyDSS, SshKeyExchangeInitHostKeyRSA
from cryptolyzer.ssh.client import SshKeyExchangeInitHostKeyECDSA, SshKeyExchangeInitHostKeyEDDSA
from cryptolyzer.ssh.client import SshKeyExchangeInitHostCertificateDSS, SshKeyExchangeInitHostCertificateRSA
from cryptolyzer.ssh.client import SshKeyExchangeInitHostCertificateECDSA, SshKeyExchangeInitHostCertificateEDDSA


class AnalyzerResultPublicKeys(AnalyzerResultBase):
    def __init__(self, public_keys):
        self.public_keys = public_keys


class AnalyzerPublicKeys(AnalyzerSshBase):
    _KEY_EXCHANGE_INIT_MESSAGES = [
        SshKeyExchangeInitHostKeyDSS(),
        SshKeyExchangeInitHostKeyRSA(),
        SshKeyExchangeInitHostKeyECDSA(),
        SshKeyExchangeInitHostKeyEDDSA(),
        SshKeyExchangeInitHostCertificateDSS(),
        SshKeyExchangeInitHostCertificateRSA(),
        SshKeyExchangeInitHostCertificateECDSA(),
        SshKeyExchangeInitHostCertificateEDDSA(),
    ]

    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which public keys or certificates used by the server(s)'

    def analyze(self, l7_client):

        host_public_keys = []
        for key_exchange_init_message in self._KEY_EXCHANGE_INIT_MESSAGES:
            try:
                server_messages = l7_client.do_handshake(
                    key_exchange_init_message=key_exchange_init_message,
                    last_message_type=SshECDHKeyExchangeReply
                )
                ecdh_key_exchange_reply_message = server_messages[SshECDHKeyExchangeReply.get_message_code()]
                host_public_keys.append(ecdh_key_exchange_reply_message.host_public_key)
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    break
                else:
                    raise e
            except SshDisconnect:
                pass

        return AnalyzerResultPublicKeys(host_public_keys)
