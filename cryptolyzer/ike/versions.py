# SPDX-License-Identifier: MPL-2.0

import typing

import attr

from cryptodatahub.ike.algorithm import (
    Ikev2ExchangeType,
    Ikev2NotifyType,
    Ikev1ExchangeType,
    Ikev1NotifyType,
)

from cryptodatahub.ike.version import IkeVersion

from cryptoparser.ike.version import IsakmpProtocolVersion
from cryptolyzer.ike.common import AnalyzerIKEBase

from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke

from cryptolyzer.ike.client import Ikev2SecurityAssociationAnyAlgorithm, Ikev1SecurityAssociationMandatoryMostPopular


@attr.s
class AnalyzerResultVersions(AnalyzerResultIKE):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to protocol version.

    :param versions: supported protocol versions (IKEv1/IKEv2).
    :param alerts_unsupported_version: whether unsupported protocol version is alerted.
    """

    versions: list[IsakmpProtocolVersion] = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of(IsakmpProtocolVersion)
        ),
        metadata={'human_readable_name': 'Protocol Versions'},
    )
    alerts_unsupported_version: typing.Optional[bool] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool)),
        metadata={'human_readable_name': 'Alerts Unsupported Version'},
    )


class AnalyzerVersions(AnalyzerIKEBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    def _probe_version(
        self,
        analyzable,
        handshake_callable,
        acceptable_notify_types: typing.Container,
    ) -> bool:
        """
        Return True if the version is supported: the responder either answered the
        IKE_SA_INIT or rejected it with an acceptable notify; False on NO_RESPONSE.
        """
        outcome = self._probe_ike_sa_init(analyzable, handshake_callable, acceptable_notify_types)
        return outcome.server_messages is not None or outcome.notify is not None

    def analyze(self, analyzable, protocol_version):
        """
        :type analyzable: AnalyzerTargetIKE
        :type protocol_version: IsakmpProtocolVersion
        :rtype: AnalyzerResultVersions
        """
        super().analyze(analyzable, protocol_version)
        supported_versions = []
        alerts_unsupported_version = None

        if self._probe_version(
            analyzable,
            lambda: analyzable.do_ikev2_handshake(
                init_message=Ikev2SecurityAssociationAnyAlgorithm(),
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
            ),
            [Ikev2NotifyType.NO_PROPOSAL_CHOSEN, Ikev2NotifyType.INVALID_KE_PAYLOAD],
        ):
            supported_versions.append(IsakmpProtocolVersion(IkeVersion.V2, 0))

        if self._probe_version(
            analyzable,
            lambda: analyzable.do_ikev1_handshake(
                init_message=Ikev1SecurityAssociationMandatoryMostPopular(Ikev1ExchangeType.IDENTITY_PROTECTION),
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
            ),
            [Ikev1NotifyType.NO_PROPOSAL_CHOSEN],
        ):
            supported_versions.append(IsakmpProtocolVersion(IkeVersion.V1, 0))

        return AnalyzerResultVersions(
            target=AnalyzerTargetIke.from_l7_client(analyzable),
            versions=sorted(supported_versions),
            alerts_unsupported_version=alerts_unsupported_version,
        )
