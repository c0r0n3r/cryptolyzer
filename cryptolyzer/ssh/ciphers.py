# -*- coding: utf-8 -*-

import attr

import six

from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)
from cryptoparser.ssh.subprotocol import SshMessageCode, SshKeyExchangeInit
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh
from cryptolyzer.common.utils import LogSingleton


@attr.s
class AnalyzerResultCiphers(AnalyzerResultSsh):  # pylint: disable=too-many-instance-attributes
    """
    :class: Analyzer result relates to the negotiable cryptographic algorithms.

    :param kex_algorithms: List of the negotiable key exchange algorithms.
    :param host_key_algorithms: List of the negotiable host key algorithms.
    :param encryption_algorithms_client_to_server: List of the negotiable encryption algorithms in client-to-server
        direction.
    :param encryption_algorithms_server_to_client: List of the negotiable encryption algorithms in server-to-client
        direction.
    :param mac_algorithms_client_to_server: List of the negotiable message authentication code algorithms in
        client-to-server direction.
    :param mac_algorithms_server_to_client: List of the negotiable message authentication code algorithms in
        server-to-client direction.
    :param compression_algorithms_client_to_server: List of the negotiable compression algorithms in client-to-server
        direction.
    :param compression_algorithms_server_to_client: List of the negotiable compression algorithms in server-to-client
        direction.
    :param hassh_fingerprint: `HASSH <https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/>`__
        fingerprint of the negotiable algorithms.
    """

    kex_algorithms = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshKexAlgorithm, ) + six.string_types)
        ),
        metadata={'human_readable_name': 'KEX Algorithms'}
    )
    host_key_algorithms = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshHostKeyAlgorithm, ) + six.string_types)
        ),
    )
    encryption_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshEncryptionAlgorithm, ) + six.string_types)
        ),
        metadata={'human_readable_name': 'Encryption Algorithms Client to Server'}
    )
    encryption_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshEncryptionAlgorithm, ) + six.string_types)
        ),
        metadata={'human_readable_name': 'Encryption Algorithms Server to Client'}
    )
    mac_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshMacAlgorithm, ) + six.string_types)
        ),
        metadata={'human_readable_name': 'MAC Algorithms Client to Server'}
    )
    mac_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshMacAlgorithm, ) + six.string_types)
        ),
        metadata={'human_readable_name': 'MAC Algorithms Server to Client'}
    )
    compression_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshCompressionAlgorithm, ) + six.string_types)
        ),
        metadata={'human_readable_name': 'Compression Algorithms Client to Server'}
    )
    compression_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshCompressionAlgorithm, ) + six.string_types)
        ),
        metadata={'human_readable_name': 'Compression Algorithms Server to Client'}
    )
    hassh_fingerprint = attr.ib(
        validator=attr.validators.instance_of(six.string_types),
        metadata={'human_readable_name': 'HASSH fingerprint'}
    )


class AnalyzerCiphers(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which cipher suites supported by the server(s)'

    @staticmethod
    def _log_algorithms(protocol_version, key_exchange_init_message, message_attr_name, algorithm_name=None):
        if algorithm_name is None:
            algorithm_name = message_attr_name.replace('_', ' ')

        LogSingleton().log(level=60, msg=six.u('Server offers %s %s (%s)') % (
            algorithm_name,
            ', '.join(list(map(
                lambda algorithm: algorithm if isinstance(algorithm, six.string_types) else algorithm.value.code,
                getattr(key_exchange_init_message, message_attr_name)
            ))),
            protocol_version,
        ))

    def analyze(self, analyzable):
        server_messages = analyzable.do_handshake(last_message_type=SshMessageCode.KEXINIT)
        key_exchange_init_message = server_messages[SshKeyExchangeInit]

        protocol_version = SshProtocolVersion(SshVersion.SSH2)
        self._log_algorithms(protocol_version, key_exchange_init_message, 'kex_algorithms', 'KEX algorithms')
        self._log_algorithms(protocol_version, key_exchange_init_message, 'host_key_algorithms', None)
        self._log_algorithms(
            protocol_version, key_exchange_init_message, 'encryption_algorithms_client_to_server', None
        )
        self._log_algorithms(
            protocol_version, key_exchange_init_message, 'encryption_algorithms_server_to_client', None
        )
        self._log_algorithms(
            protocol_version, key_exchange_init_message,
            'mac_algorithms_client_to_server', 'MAC algorithms client to server'
        )
        self._log_algorithms(
            protocol_version, key_exchange_init_message,
            'mac_algorithms_server_to_client', 'MAC algorithms server to client'
        )
        self._log_algorithms(
            protocol_version, key_exchange_init_message, 'compression_algorithms_client_to_server', None
        )
        self._log_algorithms(
            protocol_version, key_exchange_init_message, 'compression_algorithms_server_to_client', None
        )

        return AnalyzerResultCiphers(
            AnalyzerTargetSsh.from_l7_client(analyzable, protocol_version),
            list(key_exchange_init_message.kex_algorithms),
            list(key_exchange_init_message.host_key_algorithms),
            list(key_exchange_init_message.encryption_algorithms_client_to_server),
            list(key_exchange_init_message.encryption_algorithms_server_to_client),
            list(key_exchange_init_message.mac_algorithms_client_to_server),
            list(key_exchange_init_message.mac_algorithms_server_to_client),
            list(key_exchange_init_message.compression_algorithms_client_to_server),
            list(key_exchange_init_message.compression_algorithms_server_to_client),
            key_exchange_init_message.hassh_server,
        )
