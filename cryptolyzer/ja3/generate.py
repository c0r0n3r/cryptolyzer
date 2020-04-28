# -*- coding: utf-8 -*-

import hashlib

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.tls.subprotocol import TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.result import AnalyzerResultBase

from cryptolyzer.tls.server import L7ServerTlsBase


class AnalyzerResultGenerate(AnalyzerResultBase):
    def __init__(self, target):
        super(AnalyzerResultGenerate, self).__init__(target)

        tag_hash = hashlib.md5()
        tag_hash.update(target.encode('ascii'))
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
        client_messages = analyzable.do_tls_handshake()
        tag = client_messages[0][TlsHandshakeType.CLIENT_HELLO].ja3()

        return AnalyzerResultGenerate(
            tag
        )
