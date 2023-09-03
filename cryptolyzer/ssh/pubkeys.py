#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

import attr
import six

from cryptodatahub.common.algorithm import Authentication


from cryptodatahub.ssh.algorithm import SshHostKeyType
from cryptoparser.ssh.key import SshPublicKeyBase
from cryptoparser.ssh.subprotocol import (
    SshDHKeyExchangeReplyBase,
    SshMessageCode,
)

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptolyzer.ssh.client import (
    SshDisconnect,
    SshKeyExchangeInitHostKeyDSS,
    SshKeyExchangeInitHostKeyECDSA,
    SshKeyExchangeInitHostKeyED25519,
    SshKeyExchangeInitHostKeyRSA,
    SshKeyExchangeInitHostCertificateV00DSS,
    SshKeyExchangeInitHostCertificateV00RSA,
    SshKeyExchangeInitHostCertificateV01DSS,
    SshKeyExchangeInitHostCertificateV01RSA,
    SshKeyExchangeInitHostCertificateV01ECDSA,
    SshKeyExchangeInitHostCertificateV01ED25519,
)


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultSsh):
    public_keys = attr.ib(validator=attr.validators.deep_iterable(attr.validators.instance_of(SshPublicKeyBase)))


class AnalyzerPublicKeys(AnalyzerSshBase):
    _KEY_EXCHANGE_INIT_MESSAGES_BY_TYPE = OrderedDict([
        ((SshHostKeyType.KEY, Authentication.DSS), SshKeyExchangeInitHostKeyDSS()),
        ((SshHostKeyType.KEY, Authentication.ECDSA), SshKeyExchangeInitHostKeyECDSA()),
        ((SshHostKeyType.KEY, Authentication.ED25519), SshKeyExchangeInitHostKeyED25519()),
        ((SshHostKeyType.KEY, Authentication.RSA), SshKeyExchangeInitHostKeyRSA()),
        ((SshHostKeyType.CERTIFICATE, Authentication.DSS), SshKeyExchangeInitHostCertificateV00DSS()),
        ((SshHostKeyType.CERTIFICATE, Authentication.RSA), SshKeyExchangeInitHostCertificateV00RSA()),
        ((SshHostKeyType.CERTIFICATE, Authentication.DSS), SshKeyExchangeInitHostCertificateV01DSS()),
        ((SshHostKeyType.CERTIFICATE, Authentication.RSA), SshKeyExchangeInitHostCertificateV01RSA()),
        ((SshHostKeyType.CERTIFICATE, Authentication.ECDSA), SshKeyExchangeInitHostCertificateV01ECDSA()),
        ((SshHostKeyType.CERTIFICATE, Authentication.ED25519), SshKeyExchangeInitHostCertificateV01ED25519()),
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
        LogSingleton().disabled = True
        analyzer_result = AnalyzerCiphers().analyze(analyzable)
        LogSingleton().disabled = False
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
                host_public_key = dh_key_exchange_reply_message.host_public_key
                host_public_keys.append(host_public_key)
                LogSingleton().log(level=60, msg=six.u('Server offers %s host key') % (
                    host_public_key.host_key_algorithm.value.code
                ))

        return AnalyzerResultPublicKeys(
            AnalyzerTargetSsh.from_l7_client(analyzable),
            host_public_keys,
        )
