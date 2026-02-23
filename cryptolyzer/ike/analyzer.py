# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from cryptoparser.ike.version import IsakmpVersion

from cryptolyzer.common.analyzer import ProtocolHandlerIKEBase, ProtocolHandlerIKEExactVersion

from cryptolyzer.ike.dhparams import AnalyzerDHParams
from cryptolyzer.ike.curves import AnalyzerCurves
from cryptolyzer.ike.versions import AnalyzerVersions


class ProtocolHandlerIKEv1(ProtocolHandlerIKEExactVersion):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerDHParams,
            AnalyzerCurves,
        )

    @classmethod
    def get_protocol_version(cls):
        return IsakmpVersion.V1


class ProtocolHandlerIKEv2(ProtocolHandlerIKEExactVersion):
    @classmethod
    def get_analyzers(cls):
        return ProtocolHandlerIKEv1.get_analyzers()

    @classmethod
    def get_protocol_version(cls):
        return IsakmpVersion.V2


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
