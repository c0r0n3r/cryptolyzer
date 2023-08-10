# -*- coding: utf-8 -*-

from cryptolyzer.common.analyzer import ProtocolHandlerBase

from cryptolyzer.dnsrec.dnssec import AnalyzerDnsSec
from cryptolyzer.dnsrec.mail import AnalyzerDnsMail


class ProtocolHandlerDnsRecordBase(ProtocolHandlerBase):
    @classmethod
    def _l7_client_from_uri(cls, uri):
        for analyzer_class in cls.get_analyzers():
            for client_class in analyzer_class.get_clients():
                if client_class.get_scheme() == uri.scheme:
                    return client_class.from_uri(uri)

        raise NotImplementedError()

    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerDnsSec,
            AnalyzerDnsMail,
        )

    @classmethod
    def get_protocol(cls):
        return 'dns'

    @classmethod
    def _get_analyzer_args(cls):
        return ([], {})
