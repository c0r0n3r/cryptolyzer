# -*- coding: utf-8 -*-

import attr

from cryptoparser.httpx.header import HttpHeaderFieldBase, HttpHeaderFields

from cryptolyzer.common.analyzer import AnalyzerHttpBase
from cryptolyzer.common.result import AnalyzerResultHttp, AnalyzerTargetHttp


@attr.s
class AnalyzerResultHeaders(AnalyzerResultHttp):  # pylint: disable=too-few-public-methods
    headers = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(HttpHeaderFieldBase)
        )
    )


class AnalyzerHeaders(AnalyzerHttpBase):
    @classmethod
    def get_name(cls):
        return 'headers'

    @classmethod
    def get_help(cls):
        return 'Check which response headers are sent by the server(s)'

    @staticmethod
    def _analyze_headers(analyzable, version):  # pylint: disable=unused-argument
        return HttpHeaderFields.parse_exact_size(analyzable.do_handshake())

    def analyze(self, analyzable, protocol_version):
        headers = self._analyze_headers(analyzable, protocol_version)

        return AnalyzerResultHeaders(
            AnalyzerTargetHttp.from_l7_client(analyzable, protocol_version),
            list(headers)
        )
