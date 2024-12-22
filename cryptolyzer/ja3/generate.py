# -*- coding: utf-8 -*-

import hashlib

import attr

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.tls.subprotocol import TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultBase
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.tls.server import L7ServerTlsBase


@attr.s
class AnalyzerResultGenerate(AnalyzerResultBase):
    target_hash = attr.ib(init=False, validator=attr.validators.instance_of(str))

    def __attrs_post_init__(self):
        tag_hash = hashlib.md5()
        tag_hash.update(self.target.encode('ascii'))
        self.target_hash = tag_hash.hexdigest()


class AnalyzerGenerate(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'generate'

    @classmethod
    def get_help(cls):
        return 'Generate JA3 tag(s)'

    @classmethod
    def get_clients(cls):
        return list(get_leaf_classes(L7ServerTlsBase))

    @classmethod
    def get_default_scheme(cls):
        return 'tls'

    def analyze(self, analyzable):
        analyzable.max_handshake_count = 1
        analyzable.init_connection()
        client_messages = analyzable.do_handshake()
        if not client_messages:
            raise NetworkError(NetworkErrorType.NO_CONNECTION)

        tag = client_messages[0][TlsHandshakeType.CLIENT_HELLO].ja3()
        LogSingleton().log(level=60, msg=f'Client offers TLS client hello which JA3 tag is "{tag}"')

        return AnalyzerResultGenerate(
            tag
        )
