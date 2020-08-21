# -*- coding: utf-8 -*-

import hashlib
import six
import attr

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.tls.subprotocol import TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.result import AnalyzerResultBase

from cryptolyzer.tls.server import L7ServerTlsBase


@attr.s
class AnalyzerResultGenerate(AnalyzerResultBase):
    target_hash = attr.ib(init=False, validator=attr.validators.instance_of(six.string_types))

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
        tag = client_messages[0][TlsHandshakeType.CLIENT_HELLO].ja3()

        return AnalyzerResultGenerate(
            tag
        )
