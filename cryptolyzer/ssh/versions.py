# -*- coding: utf-8 -*-

import six

import attr

from cryptoparser.ssh.subprotocol import SshProtocolMessage
from cryptoparser.ssh.version import SshProtocolVersion, SshSoftwareVersionBase

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh
from cryptolyzer.common.utils import LogSingleton


@attr.s
class AnalyzerResultVersions(AnalyzerResultSsh):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to protocol and software versions

    :param protocol_versions: List of supported protocol versions.
    :param software_version: Software versions (and vendor) of the server.
    """

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
        ssh_protocol_versions = [SshProtocolVersion(supported_protocol) for supported_protocol in supported_protocols]
        LogSingleton().log(level=60, msg=six.u('Server offers protocol version %s') % (
            ', '.join([str(ssh_protocol_version) for ssh_protocol_version in ssh_protocol_versions]),
        ))

        return AnalyzerResultVersions(
            AnalyzerTargetSsh.from_l7_client(analyzable),
            ssh_protocol_versions,
            protocol_message.software_version,
        )
