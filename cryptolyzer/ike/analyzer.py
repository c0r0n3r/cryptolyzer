# SPDX-License-Identifier: MPL-2.0

from cryptodatahub.ike.version import IkeVersion

from cryptolyzer.common.analyzer import ProtocolHandlerIKEBase, ProtocolHandlerIKEExactVersion

from cryptolyzer.ike.ciphers import AnalyzerCiphers
from cryptolyzer.ike.dhparams import AnalyzerDHParams
from cryptolyzer.ike.curves import AnalyzerCurves
from cryptolyzer.ike.versions import AnalyzerVersions


class ProtocolHandlerIKEv1(ProtocolHandlerIKEExactVersion):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerCiphers,
            AnalyzerDHParams,
            AnalyzerCurves,
        )

    @classmethod
    def get_protocol(cls):
        return 'ikev1'

    @classmethod
    def get_protocol_version(cls):
        return IkeVersion.V1


class ProtocolHandlerIKEv2(ProtocolHandlerIKEExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerIKEv1.get_analyzers()

    @classmethod
    def get_protocol(cls):
        return 'ikev2'

    @classmethod
    def get_protocol_version(cls):
        return IkeVersion.V2


class ProtocolHandlerIKEVersionIndependent(ProtocolHandlerIKEBase):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerVersions,
        )

    @classmethod
    def get_protocol(cls):
        return 'ike'

    @classmethod
    def get_protocol_version(cls):
        return None
