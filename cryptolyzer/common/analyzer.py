#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

from cryptoparser.common.base import JSONSerializable
from cryptoparser.common.utils import get_leaf_classes

class ProtocolHandlerBase(object):
    @classmethod
    def from_protocol(cls, protocol):
        for handler_class in get_leaf_classes(cls):
            if handler_class.get_protocol() == protocol:
                return handler_class()
        else:
            raise ValueError()

    @classmethod
    @abc.abstractmethod
    def get_protocol(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_arguments(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def analyze(self, analyzers, uris):
        for uri in uris:
            kwargs = {'scheme': uri.scheme, 'host': uri.host}
            if uri.port:
                kwargs['port'] = int(uri.port)
            l7_client = L7Client.from_scheme(**kwargs)

            for analyzer in analyzers:
                yield self._analyze(analyzer, l7_client)

    def _analyze(self, analyzer, l7_client):
        return analyzer.analyze(l7_client)

    @classmethod
    def analyzer_from_name(cls, name):
        analyzer_list = [
            analyzer_class
            for analyzer_class in cls.get_analyzers()
            if analyzer_class.get_name() == name
        ]
        if len(analyzer_list) != 1:
            raise ValueError

        return analyzer_list[0]()


class AnalyzerBase(object):
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def analyze(self, l7_client):
        raise NotImplementedError()


class AnalyzerResultBase(JSONSerializable):
    @staticmethod
    def _bytes_to_colon_separated_hex(byte_array):
        return ':'.join(['{:02X}'.format(x) for x in byte_array])


from cryptolyzer.tls import ciphers, pubkeys, curves, sigalgos, versions
from cryptoparser.tls.client import L7Client

from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion, SslProtocolVersion


class ProtocolHandlerTlsCurrentVersionBase(ProtocolHandlerBase):
    @classmethod
    def get_analyzers(cls):
        return [analyzer_class for analyzer_class in get_leaf_classes(AnalyzerBase)]

    @classmethod
    def get_clients(cls):
        return [client_class for client_class in get_leaf_classes(L7Client)]

    def _analyze(self, analyzer, l7_client):
        return analyzer.analyze(l7_client, self._get_protocol_version())

    @classmethod
    @abc.abstractmethod
    def _get_protocol_version(cls):
        raise NotImplementedError()

class ProtocolHandlerSsl2(ProtocolHandlerTlsCurrentVersionBase):
    @classmethod
    def get_protocol(cls):
        return 'ssl2'

    @classmethod
    def _get_protocol_version(cls):
        return SslProtocolVersion()

class ProtocolHandlerSsl3(ProtocolHandlerTlsCurrentVersionBase):
    @classmethod
    def get_protocol(cls):
        return 'ssl3'

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.SSL3)


class ProtocolHandlerTls10(ProtocolHandlerTlsCurrentVersionBase):
    @classmethod
    def get_protocol(cls):
        return 'tls1'

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_0)


class ProtocolHandlerTls11(ProtocolHandlerTlsCurrentVersionBase):
    @classmethod
    def get_protocol(cls):
        return 'tls1_1'

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_1)


class ProtocolHandlerTls12(ProtocolHandlerTlsCurrentVersionBase):
    @classmethod
    def get_protocol(cls):
        return 'tls1_2'

    @classmethod
    def _get_protocol_version(cls):
        return TlsProtocolVersionFinal(TlsVersion.TLS1_2)
