# -*- coding: utf-8 -*-

import six

import attr

from cryptoparser.httpx.header import HttpHeaderFieldBase, HttpHeaderFieldUnparsed, HttpHeaderFields

from cryptolyzer.common.analyzer import AnalyzerHttpBase
from cryptolyzer.common.result import AnalyzerResultHttp, AnalyzerTargetHttp
from cryptolyzer.common.utils import LogSingleton


@attr.s
class AnalyzerResultHeaders(AnalyzerResultHttp):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to the response headers.

    :param versions: List of the response headers.
    """

    headers = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((HttpHeaderFieldBase, HttpHeaderFieldUnparsed))
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
        header_fields = HttpHeaderFields.parse_exact_size(analyzable.do_handshake())
        LogSingleton().log(level=60, msg=six.u('Server offers headers %s') % (
            ', '.join(list(map(
                lambda header_field:
                    header_field.name
                    if isinstance(header_field, HttpHeaderFieldUnparsed)
                    else header_field.get_canonical_name(),
                header_fields
            )))
        ))
        return header_fields

    def analyze(self, analyzable, protocol_version):
        headers = self._analyze_headers(analyzable, protocol_version)

        return AnalyzerResultHeaders(
            AnalyzerTargetHttp.from_l7_client(analyzable, protocol_version),
            list(headers)
        )
