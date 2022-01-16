#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

import attr
import six

from cryptoparser.common.algorithm import Authentication

from cryptoparser.ssh.ciphersuite import SshHostKeyType
from cryptoparser.ssh.key import SshPublicKeyBase
from cryptoparser.ssh.subprotocol import (
    SshDHKeyExchangeReplyBase,
    SshMessageCode,
)

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh
from cryptolyzer.common.exception import NetworkError, NetworkErrorType

from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptolyzer.ssh.client import (
    SshDisconnect,
    SshKeyExchangeInitHostKeyDSS,
    SshKeyExchangeInitHostKeyECDSA,
    SshKeyExchangeInitHostKeyEDDSA,
    SshKeyExchangeInitHostKeyRSA,
)


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultSsh):
    public_keys = attr.ib(validator=attr.validators.deep_iterable(attr.validators.instance_of(SshPublicKeyBase)))


class AnalyzerPublicKeys(AnalyzerSshBase):
    _KEY_EXCHANGE_INIT_MESSAGES_BY_TYPE = OrderedDict([
        ((SshHostKeyType.KEY, Authentication.DSS), SshKeyExchangeInitHostKeyDSS()),
        ((SshHostKeyType.KEY, Authentication.ECDSA), SshKeyExchangeInitHostKeyECDSA()),
        ((SshHostKeyType.KEY, Authentication.EDDSA), SshKeyExchangeInitHostKeyEDDSA()),
        ((SshHostKeyType.KEY, Authentication.RSA), SshKeyExchangeInitHostKeyRSA()),
    ])

    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which public keys or certificates used by the server(s)'

    @classmethod
    def _get_dh_key_exchange_reply_message_class(cls, server_messages):
        return six.next(iter(filter(
            lambda server_message: issubclass(server_message, SshDHKeyExchangeReplyBase),
            server_messages
        )))

    def analyze(self, analyzable):
        analyzer_result = AnalyzerCiphers().analyze(analyzable)
        host_key_types = set(map(
            lambda host_key_algorithm: (host_key_algorithm.value.key_type, host_key_algorithm.value.authentication),
            analyzer_result.host_key_algorithms
        ))

        host_public_keys = []
        for host_key_type, key_exchange_init_message in self._KEY_EXCHANGE_INIT_MESSAGES_BY_TYPE.items():
            if host_key_type not in host_key_types:
                continue

            try:
                server_messages = analyzable.do_handshake(
                    key_exchange_init_message=key_exchange_init_message,
                    last_message_type=SshMessageCode.NEWKEYS
                )
                dh_key_exchange_reply_message = server_messages[
                    self._get_dh_key_exchange_reply_message_class(server_messages)
                ]
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    pass
                else:
                    raise e
            except SshDisconnect:
                pass
            except StopIteration:
                pass
            else:
                host_public_keys.append(dh_key_exchange_reply_message.host_public_key)

        return AnalyzerResultPublicKeys(
            AnalyzerTargetSsh.from_l7_client(analyzable),
            host_public_keys,
        )
