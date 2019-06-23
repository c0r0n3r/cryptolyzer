# -*- coding: utf-8 -*-

from collections import OrderedDict

import abc

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.result import AnalyzerResultAllSupportedVersions

from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptolyzer.ssh.versions import AnalyzerVersions


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
    def _get_protocol_version(cls):
        raise NotImplementedError()


class ProtocolHandlerSsh2(ProtocolHandlerSshExactVersion):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerCiphers,
        )

    @classmethod
    def _get_protocol_version(cls):
        return SshProtocolVersion(SshVersion.SSH2)


class AnalyzerResultSshAllSupportedVersions(AnalyzerResultAllSupportedVersions):
    pass


class ProtocolHandlerSshAllSupportedVersions(ProtocolHandlerSshBase):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerVersions,
            AnalyzerCiphers,
        )

    @classmethod
    def get_protocol(cls):
        return 'ssh'

    def analyze(self, analyzer, uri):
        base_analyze = super(ProtocolHandlerSshAllSupportedVersions, self).analyze
        analyzer_result = base_analyze(AnalyzerVersions(), uri)
        if isinstance(analyzer, AnalyzerVersions):
            return analyzer_result

        results = []
        target = None
        for protocol_handler_class in get_leaf_classes(ProtocolHandlerSshExactVersion):
            if isinstance(analyzer, protocol_handler_class.get_analyzers()):
                result = protocol_handler_class().analyze(analyzer, uri)
                target = result.target

                results.append(
                    (protocol_handler_class._get_protocol_version(), result)  # pylint: disable=protected-access
                )

        return AnalyzerResultSshAllSupportedVersions(target, OrderedDict(results))
