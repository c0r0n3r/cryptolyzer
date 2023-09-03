# -*- coding: utf-8 -*-

import abc
import glob
import importlib
import ipaddress
import pkgutil

try:
    import pathlib
except ImportError:  # pragma: no cover
    import pathlib2 as pathlib  # pragma: no cover

import six

from cryptoparser.common.base import Serializable
from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion
from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.dnsrec.client import L7ClientDnsBase
from cryptolyzer.httpx.client import L7ClientHttpBase
from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.tls.client import L7ClientTlsBase


@six.add_metaclass(abc.ABCMeta)
class ProtocolHandlerBase(object):
    @classmethod
    def import_plugins(cls):
        plugin_root_dir_parts = pathlib.PurePath(*pathlib.PurePath(__file__).parts[:-2])  # remove common/analyzer.py
        plugin_module_dir_parts = set()
        plugin_paths = filter(
            lambda path: path != __file__,
            glob.iglob(str(plugin_root_dir_parts / '*' / 'analyzer.py'))
        )
        for path in plugin_paths:
            plugin_path_parts = pathlib.PurePath(path).parts[-3:-1]  # split plugin dirs
            for index in range(len(plugin_path_parts)):
                plugin_module_dir_parts.add('.'.join(plugin_path_parts[:index + 1]))

        plugin_module_dir_parts = list(plugin_module_dir_parts)
        plugin_module_dir_parts.sort(key=len)
        for plugins_dir in plugin_module_dir_parts:
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
        raise KeyError(protocol)

    @classmethod
    def get_protocols(cls):
        cls.import_plugins()

        return sorted([
            handler_class.get_protocol()
            for handler_class in get_leaf_classes(cls)
        ])

    @classmethod
    @abc.abstractmethod
    def get_protocol(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_analyzers(cls):
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
        if uri.fragment:
            try:
                ipaddress.ip_address(uri.fragment)
            except ValueError:
                pass
            else:
                kwargs['ip'] = uri.fragment

        for analyzer_class in cls.get_analyzers():
            for client_class in analyzer_class.get_clients():
                if client_class.get_scheme() == uri.scheme:
                    return client_class.from_scheme(**kwargs)

        raise NotImplementedError()

    def analyze(self, analyzer, uri, timeout=None):
        LogSingleton().log(level=60, msg=six.u('Analysis started; protocol="%s", analyzer="%s"') % (
            self.get_protocol(), analyzer.get_name(),
        ))

        l7_client = self._l7_client_from_uri(uri)
        if timeout is not None:
            l7_client.timeout = timeout
        args, kwargs = self._get_analyzer_args()
        return analyzer.analyze(l7_client, *args, **kwargs)

    @classmethod
    def analyzer_from_name(cls, name):
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
    def analyze(self, analyzable):
        raise NotImplementedError()


class AnalyzerResultBase(Serializable):
    pass


class AnalyzerTlsBase(object):
    _ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS = [
        TlsAlertDescription.HANDSHAKE_FAILURE,  # no matching algorithms
        TlsAlertDescription.CLOSE_NOTIFY,  # no matching algorithms
        TlsAlertDescription.INSUFFICIENT_SECURITY,  # not enough secure matching algorithms
        TlsAlertDescription.ILLEGAL_PARAMETER  # unimplemented matching algorithms
    ]

    @classmethod
    def get_clients(cls):
        return list(get_leaf_classes(L7ClientTlsBase))

    @classmethod
    def get_default_scheme(cls):
        return 'tls'

    @abc.abstractmethod
    def analyze(self, analyzable, protocol_version):
        raise NotImplementedError()


class ProtocolHandlerTlsBase(ProtocolHandlerBase):
    @classmethod
    @abc.abstractmethod
    def get_protocol_version(cls):
        raise NotImplementedError()

    @classmethod
    def get_protocol(cls):
        return cls.get_protocol_version().identifier

    @classmethod
    def _get_analyzer_args(cls):
        return ([], {'protocol_version': cls.get_protocol_version()})


class ProtocolHandlerTlsExactVersion(ProtocolHandlerTlsBase):
    @classmethod
    @abc.abstractmethod
    def get_protocol_version(cls):
        raise NotImplementedError()


class ProtocolHandlerSshBase(ProtocolHandlerBase):
    @classmethod
    def get_protocol(cls):
        return SshProtocolVersion(SshVersion.SSH2).identifier

    @classmethod
    def _get_analyzer_args(cls):
        return ([], {})

    @classmethod
    @abc.abstractmethod
    def get_analyzers(cls):
        raise NotImplementedError()


class ProtocolHandlerSshExactVersion(ProtocolHandlerSshBase):
    @classmethod
    @abc.abstractmethod
    def get_protocol_version(cls):
        raise NotImplementedError()


class AnalyzerSshBase(object):
    @classmethod
    def get_clients(cls):
        return list(get_leaf_classes(L7ClientSsh))

    @classmethod
    def get_default_scheme(cls):
        return 'ssh'

    @abc.abstractmethod
    def analyze(self, analyzable):
        raise NotImplementedError()


class AnalyzerHttpBase(object):
    @classmethod
    def get_clients(cls):
        return list(get_leaf_classes(L7ClientHttpBase))

    @classmethod
    def get_default_scheme(cls):
        return 'https'

    @abc.abstractmethod
    def analyze(self, analyzable, protocol_version):
        raise NotImplementedError()


class AnalyzerDnsRecordBase(object):
    @classmethod
    def get_clients(cls):
        return list(get_leaf_classes(L7ClientDnsBase))

    @classmethod
    def get_default_scheme(cls):
        return 'dns'

    @abc.abstractmethod
    def analyze(self, analyzable):
        raise NotImplementedError()
