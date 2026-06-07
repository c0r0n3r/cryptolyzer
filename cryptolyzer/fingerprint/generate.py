# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import abc
import hashlib

import attr

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.ssh.subprotocol import SshMessageCode
from cryptoparser.tls.subprotocol import TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultFingerprintGenerate
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ssh.server import L7ServerSshBase
from cryptolyzer.tls.server import L7ServerTlsBase


@attr.s
class AnalyzerResultGenerateTls(AnalyzerResultFingerprintGenerate):
    target_hash = attr.ib(init=False, validator=attr.validators.instance_of(str))

    def __attrs_post_init__(self):
        tag_hash = hashlib.md5()
        tag_hash.update(self.target.encode('ascii'))
        self.target_hash = tag_hash.hexdigest()


class _FingerprintGeneratorBase():
    @classmethod
    @abc.abstractmethod
    def get_server_base_class(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def do_handshake(self, analyzable):
        raise NotImplementedError()

    @abc.abstractmethod
    def get_result(self, client_messages):
        raise NotImplementedError()

    @abc.abstractmethod
    def get_log_messages(self, result):
        raise NotImplementedError()


class _TlsFingerprintGenerator(_FingerprintGeneratorBase):
    @classmethod
    def get_server_base_class(cls):
        return L7ServerTlsBase

    def do_handshake(self, analyzable):
        return analyzable.do_handshake()

    def get_result(self, client_messages):
        return AnalyzerResultGenerateTls(client_messages[0][TlsHandshakeType.CLIENT_HELLO].ja3())

    def get_log_messages(self, result):
        return (f'Client offers TLS client hello which JA3 tag is "{result.target}"',)


class _SshFingerprintGenerator(_FingerprintGeneratorBase):
    @classmethod
    def get_server_base_class(cls):
        return L7ServerSshBase

    def do_handshake(self, analyzable):
        return analyzable.do_ssh_handshake()

    def get_result(self, client_messages):
        return AnalyzerResultFingerprintGenerate(client_messages[0][SshMessageCode.KEXINIT].hassh)

    def get_log_messages(self, result):
        return (f'Client offers SSH key exchange init which HASSH fingerprint is "{result.target}"',)


class AnalyzerGenerate(AnalyzerBase):
    _GENERATORS = (_TlsFingerprintGenerator, _SshFingerprintGenerator)

    @classmethod
    def get_name(cls):
        return 'generate'

    @classmethod
    def get_help(cls):
        return 'Generate fingerprint(s)'

    @classmethod
    def get_clients(cls):
        return [
            client
            for generator_class in cls._GENERATORS
            for client in get_leaf_classes(generator_class.get_server_base_class())
        ]

    @classmethod
    def get_default_scheme(cls):
        return 'tls'

    def _get_generator(self, analyzable):
        for generator_class in self._GENERATORS:
            if isinstance(analyzable, generator_class.get_server_base_class()):
                return generator_class()

        raise NotImplementedError()

    def analyze(self, analyzable):
        super().analyze(analyzable)

        generator = self._get_generator(analyzable)

        analyzable.max_handshake_count = 1
        analyzable.init_connection()
        client_messages = generator.do_handshake(analyzable)
        if not client_messages:
            raise NetworkError(NetworkErrorType.NO_CONNECTION)

        result = generator.get_result(client_messages)
        for message in generator.get_log_messages(result):
            LogSingleton().log(level=60, msg=message)

        return result
