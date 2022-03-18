# -*- coding: utf-8 -*-

import six

import attr

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.ssh.subprotocol import SshMessageCode

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultBase
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ssh.server import L7ServerSshBase


@attr.s
class AnalyzerResultGenerate(AnalyzerResultBase):
    pass


class AnalyzerGenerate(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'generate'

    @classmethod
    def get_help(cls):
        return 'Generate HASSH fingerprint(s)'

    @classmethod
    def get_clients(cls):
        return list(get_leaf_classes(L7ServerSshBase))

    @classmethod
    def get_default_scheme(cls):
        return 'ssh'

    def analyze(self, analyzable):
        analyzable.max_handshake_count = 1
        analyzable.init_connection()
        client_messages = analyzable.do_ssh_handshake()
        if not client_messages:
            raise NetworkError(NetworkErrorType.NO_CONNECTION)

        fingerprint = client_messages[0][SshMessageCode.KEXINIT].hassh
        LogSingleton().log(
            level=60, msg=six.u('Client offers SSH key exchange init which HASSH fingerprint is "%s"') % (fingerprint, )
        )
        return AnalyzerResultGenerate(
            fingerprint
        )
