# -*- coding: utf-8 -*-

import abc

from collections import OrderedDict

import attr

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.httpx.version import HttpVersion

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.result import AnalyzerResultHttp
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.httpx.content import AnalyzerConetnt
from cryptolyzer.httpx.headers import AnalyzerHeaders


class ProtocolHandlerHttpBase(ProtocolHandlerBase):
    @classmethod
    @abc.abstractmethod
    def _get_version(cls):
        raise NotImplementedError()

    @classmethod
    def get_protocol(cls):
        return cls._get_version().value.identifier

    @classmethod
    def _get_analyzer_args(cls):
        return ([], {'protocol_version': cls._get_version()})

    @classmethod
    def _l7_client_from_params(cls, uri, socket_params):
        for analyzer_class in cls.get_analyzers():
            for client_class in analyzer_class.get_clients():
                if client_class.get_scheme() == uri.scheme:
                    client = client_class.from_uri(uri)
                    client.l4_socket_params = socket_params
                    return client

        raise NotImplementedError()


class ProtocolHandlerHttpExactVersion(ProtocolHandlerHttpBase):
    @classmethod
    @abc.abstractmethod
    def _get_version(cls):
        raise NotImplementedError()


class ProtocolHandlerHttp11(ProtocolHandlerHttpExactVersion):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerConetnt,
            AnalyzerHeaders,
        )

    @classmethod
    def _get_version(cls):
        return HttpVersion.HTTP1_1


@attr.s
class AnalyzerResultHttpAllSupportedVersions(AnalyzerResultHttp):
    results = attr.ib(validator=attr.validators.instance_of(OrderedDict))

    def _asdict(self):
        results = []
        for version, result in iter(self.results.items()):
            result_as_dict = result._asdict()
            del result_as_dict['target']

            results.append((version.value, result_as_dict))

        return OrderedDict([('target', self.target)] + results)


class ProtocolHandlerHttpAllSupportedVersions(ProtocolHandlerHttpBase):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerHttp11.get_analyzers()

    @classmethod
    def get_protocol(cls):
        return 'http'

    @classmethod
    def _get_version(cls):
        raise NotImplementedError()

    def analyze(self, analyzer, uri, socket_params=L4TransferSocketParams()):
        results = []
        target = None
        for protocol_handler_class in get_leaf_classes(ProtocolHandlerHttpExactVersion):
            if isinstance(analyzer, protocol_handler_class.get_analyzers()):
                result = protocol_handler_class().analyze(analyzer, uri, socket_params)
                target = result.target

                results.append(
                    (protocol_handler_class._get_version(), result)  # pylint: disable=protected-access
                )

        return AnalyzerResultHttpAllSupportedVersions(target, OrderedDict(results))
