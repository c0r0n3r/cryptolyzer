# -*- coding: utf-8 -*-

from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.analyzer import ProtocolHandlerSshBase, ProtocolHandlerSshExactVersion

from cryptolyzer.ssh.all import AnalyzerAll
from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptolyzer.ssh.dhparams import AnalyzerDHParams
from cryptolyzer.ssh.pubkeys import AnalyzerPublicKeys
from cryptolyzer.ssh.versions import AnalyzerVersions
from cryptolyzer.ssh.vulnerabilities import AnalyzerVulnerabilities


class ProtocolHandlerSsh2(ProtocolHandlerSshExactVersion):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerCiphers,
            AnalyzerDHParams,
            AnalyzerPublicKeys,
        )

    @classmethod
    def get_protocol_version(cls):
        return SshProtocolVersion(SshVersion.SSH2)  # pragma: no cover


class ProtocolHandlerSshVersionIndependent(ProtocolHandlerSshBase):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerVersions,
            AnalyzerAll,
            AnalyzerVulnerabilities,
        )

    @classmethod
    def get_protocol(cls):
        return 'ssh'
