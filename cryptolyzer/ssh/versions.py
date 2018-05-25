#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.base import TwoByteEnumComposer, TwoByteEnumParsable

from cryptoparser.ssh.subprotocol import SshProtocolMessage

from cryptolyzer.common.analyzer import AnalyzerSshBase, AnalyzerResultSsh
from cryptolyzer.common.exception import NetworkError, NetworkErrorType


class AnalyzerResultVersions(AnalyzerResultSsh):  # pylint: disable=too-few-public-methods
    def __init__(self, versions):
        super(AnalyzerResultVersions, self).__init__()

        self.versions = versions

    def as_json(self):
        return json.dumps({'versions': [repr(version) for version in self.versions]})


class AnalyzerVersions(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    def analyze(self, l7_client):
        supported_protocols = []

        try:
            server_messages = l7_client.do_handshake(last_message_type=SshProtocolMessage)
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e
        else:
            supported_protocols = server_messages[SshProtocolMessage].protocol_version.supported_versions

        return AnalyzerResultVersions(supported_protocols)
