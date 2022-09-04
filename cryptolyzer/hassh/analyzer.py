# -*- coding: utf-8 -*-

from cryptolyzer.common.analyzer import ProtocolHandlerBase

from cryptolyzer.hassh.generate import AnalyzerGenerate


class ProtocolHandlerHASSHBase(ProtocolHandlerBase):
    @classmethod
    def get_protocol(cls):
        return 'hassh'

    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerGenerate,
        )

    @classmethod
    def _get_analyzer_args(cls):
        return ([], {})
