# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import abc

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.ssh.subprotocol import SshMessageCode
from cryptoparser.tls.subprotocol import TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultFingerprint
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.fingerprint.tag import JA3Fingerprint, JA4Fingerprint, SshFingerprint, TlsFingerprint

from cryptolyzer.ssh.server import L7ServerSshBase
from cryptolyzer.tls.server import L7ServerTlsBase


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
        client_hello = client_messages[0][TlsHandshakeType.CLIENT_HELLO]
        ja4 = client_hello.ja4()
        return AnalyzerResultFingerprint(TlsFingerprint(
            JA3Fingerprint.from_tag(client_hello.ja3()),
            JA4Fingerprint.from_tags(
                ja4.fingerprint, ja4.fingerprint_original, ja4.fingerprint_raw, ja4.fingerprint_raw_original
            ),
        ))

    def get_log_messages(self, result):
        return (
            f'Client offers TLS client hello which JA3 tag is "{result.target.ja3.tag}"',
            f'Client offers TLS client hello which JA4 tag is "{result.target.ja4.tag}"',
        )


class _SshFingerprintGenerator(_FingerprintGeneratorBase):
    @classmethod
    def get_server_base_class(cls):
        return L7ServerSshBase

    def do_handshake(self, analyzable):
        return analyzable.do_ssh_handshake()

    def get_result(self, client_messages):
        return AnalyzerResultFingerprint(
            SshFingerprint(client_messages[0][SshMessageCode.KEXINIT].hassh)
        )

    def get_log_messages(self, result):
        return (f'Client offers SSH key exchange init which HASSH fingerprint is "{result.target.hassh}"',)


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
