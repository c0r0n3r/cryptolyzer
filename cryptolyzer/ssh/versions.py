# -*- coding: utf-8 -*-

import attr

from cryptoparser.ssh.subprotocol import SshProtocolMessage
from cryptoparser.ssh.version import SshProtocolVersion, SshSoftwareVersionBase

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh


@attr.s
class AnalyzerResultVersions(AnalyzerResultSsh):  # pylint: disable=too-few-public-methods
    protocol_versions = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(SshProtocolVersion))
    )
    software_version = attr.ib(validator=attr.validators.instance_of(SshSoftwareVersionBase))


class AnalyzerVersions(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    def analyze(self, analyzable):
        supported_protocols = []

        server_messages = analyzable.do_handshake(last_message_type=SshProtocolMessage)
        protocol_message = server_messages[SshProtocolMessage]
        supported_protocols = protocol_message.protocol_version.supported_versions
        return AnalyzerResultVersions(
            AnalyzerTargetSsh.from_l7_client(analyzable),
            [SshProtocolVersion(supported_protocol) for supported_protocol in supported_protocols],
            protocol_message.software_version,
        )
