# -*- coding: utf-8 -*-

from cryptolyzer.common.analyzer import ProtocolHandlerBase

from cryptolyzer.ja3.decode import AnalyzerDecode
from cryptolyzer.ja3.generate import AnalyzerGenerate


class ProtocolHandlerJA3Base(ProtocolHandlerBase):
    @classmethod
    def get_protocol(cls):
        return 'ja3'

    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerDecode,
            AnalyzerGenerate,
        )

    @classmethod
    def _get_analyzer_args(cls):
        return ([], {})
