# SPDX-License-Identifier: MPL-2.0

from cryptodatahub.ike.version import IkeVersion

from cryptolyzer.common.analyzer import ProtocolHandlerIKEBase, ProtocolHandlerIKEExactVersion

from cryptolyzer.ike.ciphers import AnalyzerCiphers
from cryptolyzer.ike.dhparams import AnalyzerDHParams
from cryptolyzer.ike.curves import AnalyzerCurves
from cryptolyzer.ike.extensions import AnalyzerExtensions
from cryptolyzer.ike.simulations import AnalyzerIkev1Simulations, AnalyzerIkev2Simulations
from cryptolyzer.ike.versions import AnalyzerVersions
from cryptolyzer.ike.pubkeys import AnalyzerPublicKeys
from cryptolyzer.ike.pubkeyreq import AnalyzerPublicKeyRequest


# analyzers common to both IKE versions; each version adds its own simulations
# analyzer, whose axes and result model differ by version
_VERSION_SHARED_ANALYZERS = (
    AnalyzerCiphers,
    AnalyzerDHParams,
    AnalyzerCurves,
    AnalyzerExtensions,
    AnalyzerPublicKeys,
    AnalyzerPublicKeyRequest,
)


class ProtocolHandlerIKEv1(ProtocolHandlerIKEExactVersion):
    @classmethod
    def get_analyzers(cls):
        return _VERSION_SHARED_ANALYZERS + (
            AnalyzerIkev1Simulations,
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
        return _VERSION_SHARED_ANALYZERS + (
            AnalyzerIkev2Simulations,
        )

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
