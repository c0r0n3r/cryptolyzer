#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import glob
import importlib
import pkgutil
import os

from cryptoparser.common.base import Serializable
from cryptoparser.common.utils import get_leaf_classes


class ProtocolHandlerBase(object):
    @classmethod
    def import_plugins(cls):
        plugins_dirs = set()
        for path in glob.iglob('cryptolyzer/*/analyzer.py'):
            if not path.startswith(os.path.join('cryptolyzer', 'common')):
                plugin_path_parts = path.split(os.path.sep)[:-1]
                for index in range(len(plugin_path_parts)):
                    plugins_dirs.add('.'.join(plugin_path_parts[:index + 1]))

        plugins_dirs = list(plugins_dirs)
        plugins_dirs.sort(key=len)

        for plugins_dir in plugins_dirs:
            ns_pkg = importlib.import_module(plugins_dir, package=None)
            for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
                if name.endswith('.analyzer'):
                    importlib.import_module(name)

    @classmethod
    def from_protocol(cls, protocol):
        cls.import_plugins()

        for handler_class in get_leaf_classes(cls):
            if handler_class.get_protocol() == protocol:
                return handler_class()
        raise KeyError()

    @classmethod
    def get_protocols(cls):
        cls.import_plugins()

        for handler_class in get_leaf_classes(cls):
            yield handler_class.get_protocol()

    @classmethod
    @abc.abstractmethod
    def get_protocol(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_analyzers(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_clients(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_analyzer_args(cls):
        raise NotImplementedError()

    @classmethod
    def _l7_client_from_uri(cls, uri):
        kwargs = {'scheme': uri.scheme, 'address': uri.host}

        if uri.port:
            kwargs['port'] = int(uri.port)

        for client_class in cls.get_clients():
            if client_class.get_scheme() == uri.scheme:
                return client_class.from_scheme(**kwargs)

        raise NotImplementedError()

    def analyze(self, analyzer, uri):
        analyzer = self._analyzer_from_name(analyzer)
        l7_client = self._l7_client_from_uri(uri)
        args, kwargs = self._get_analyzer_args()
        return analyzer.analyze(l7_client, *args, **kwargs)

    @classmethod
    def _analyzer_from_name(cls, name):
        analyzer_list = [
            analyzer_class
            for analyzer_class in cls.get_analyzers()
            if analyzer_class.get_name() == name
        ]

        if len(analyzer_list) != 1:
            raise ValueError  # pragma: no cover

        return analyzer_list[0]()


class AnalyzerBase(object):
    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def analyze(self, l7_client):
        raise NotImplementedError()


class AnalyzerResultBase(Serializable):
    pass


class AnalyzerTlsBase(object):
    @abc.abstractmethod
    def analyze(self, l7_client, protocol_version):
        raise NotImplementedError()
