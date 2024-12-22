# -*- coding: utf-8 -*-

import abc

from test.common.classes import TestThreadedServer, TestLoggerBase

from cryptoparser.ssh.subprotocol import SshMessageBase

from cryptolyzer.common.transfer import L4TransferSocketParams


class TestSshCases:
    class TestSshClientBase(TestLoggerBase):
        @staticmethod
        @abc.abstractmethod
        def get_result(host, port, l4_socket_params=L4TransferSocketParams(), ip=None):
            raise NotImplementedError()


class L7ServerSshTest(TestThreadedServer):
    def __init__(self, l7_server):
        self.l7_server = l7_server
        super().__init__(self.l7_server)

    def run(self):
        self._server.do_ssh_handshake()


class TestSshMessageInvalid(SshMessageBase):
    @classmethod
    def get_message_code(cls):
        return 1

    @classmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    def compose(self):
        return b'invalid message'
