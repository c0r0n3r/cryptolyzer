# -*- coding: utf-8 -*-

import attr

from cryptoparser.ssh.ciphersuite import (
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


@attr.s  # pylint: disable=too-many-instance-attributes
class AnalyzerResultCiphers(AnalyzerResultSsh):
    kex_algorithms = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshKexAlgorithm, str))
        ),
        metadata={'human_readable_name': 'KEX Algorithms'}
    )
    host_key_algorithms = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshHostKeyAlgorithm, str))
        ),
    )
    encryption_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshEncryptionAlgorithm, str))
        ),
        metadata={'human_readable_name': 'Encryption Algorithms Client to Server'}
    )
    encryption_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshEncryptionAlgorithm, str))
        ),
        metadata={'human_readable_name': 'Encryption Algorithms Server to Client'}
    )
    mac_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshMacAlgorithm, str))
        ),
        metadata={'human_readable_name': 'MAC Algorithms Client to Server'}
    )
    mac_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshMacAlgorithm, str))
        ),
        metadata={'human_readable_name': 'MAC Algorithms Server to Client'}
    )
    compression_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshCompressionAlgorithm, str))
        ),
        metadata={'human_readable_name': 'Compression Algorithms Client to Server'}
    )
    compression_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((SshCompressionAlgorithm, str))
        ),
        metadata={'human_readable_name': 'Compression Algorithms Server to Client'}
    )


class AnalyzerCiphers(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which cipher suites supported by the server(s)'

    def analyze(self, analyzable):
        server_messages = analyzable.do_handshake(last_message_type=SshMessageCode.KEXINIT)
        key_exchange_init_message = server_messages[SshKeyExchangeInit]
        return AnalyzerResultCiphers(
            AnalyzerTargetSsh.from_l7_client(analyzable, SshProtocolVersion(SshVersion.SSH2)),
            list(key_exchange_init_message.kex_algorithms),
            list(key_exchange_init_message.host_key_algorithms),
            list(key_exchange_init_message.encryption_algorithms_client_to_server),
            list(key_exchange_init_message.encryption_algorithms_server_to_client),
            list(key_exchange_init_message.mac_algorithms_client_to_server),
            list(key_exchange_init_message.mac_algorithms_server_to_client),
            list(key_exchange_init_message.compression_algorithms_client_to_server),
            list(key_exchange_init_message.compression_algorithms_server_to_client),
        )
