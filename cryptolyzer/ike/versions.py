# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import typing

import attr

from cryptodatahub.ike.algorithm import (
    Ikev2ExchangeType,
    Ikev2NotifyType,
    Ikev1ExchangeType,
    Ikev1NotifyType,
)

from cryptoparser.ike.version import IsakmpVersion, IsakmpProtocolVersion
from cryptolyzer.common.analyzer import AnalyzerIKEBase

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ike.client import Ikev2SecurityAssociationAnyAlgorithm, Ikev1SecurityAssociationMandatoryMostPopular
from cryptolyzer.ike.exception import IsakmpNotify


def _probe_version(
    analyzable,
    handshake_callable,
    acceptable_notify_types: typing.Container,
) -> bool:
    """
    Run handshake; on NO_RESPONSE log and return False; on NO_CONNECTION or other re-raise.
    Return True if version is supported.
    """
    try:
        handshake_callable()
    except IsakmpNotify as e:
        if e.notify not in acceptable_notify_types:
            raise
        LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
        return True
    except NetworkError as e:
        if e.error == NetworkErrorType.NO_RESPONSE:
            addr = f'{analyzable.address}:{analyzable.port}'
            LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
            return False
        raise
    return True


@attr.s
class AnalyzerResultVersions(AnalyzerResultIKE):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to protocol version.

    :param versions: supported protocol versions (IKEv1/IKEv2).
    :param alerts_unsupported_version: whether unsupported protocol version is alerted.
    """

    versions: typing.List[IsakmpProtocolVersion] = attr.ib(
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

    def analyze(self, analyzable, protocol_version):
        """
        :type analyzable: AnalyzerTargetIKE
        :type protocol_version: IsakmpProtocolVersion
        :rtype: AnalyzerResultVersions
        """
        supported_versions = []
        alerts_unsupported_version = None

        if _probe_version(
            analyzable,
            lambda: analyzable.do_ikev2_handshake(
                init_message=Ikev2SecurityAssociationAnyAlgorithm(),
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
            ),
            [Ikev2NotifyType.NO_PROPOSAL_CHOSEN, Ikev2NotifyType.INVALID_KE_PAYLOAD],
        ):
            supported_versions.append(IsakmpProtocolVersion(IsakmpVersion.V2, 0))

        if _probe_version(
            analyzable,
            lambda: analyzable.do_ikev1_handshake(
                init_message=Ikev1SecurityAssociationMandatoryMostPopular(Ikev1ExchangeType.IDENTITY_PROTECTION),
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
            ),
            [Ikev1NotifyType.NO_PROPOSAL_CHOSEN],
        ):
            supported_versions.append(IsakmpProtocolVersion(IsakmpVersion.V1, 0))

        return AnalyzerResultVersions(
            target=AnalyzerTargetIke.from_l7_client(analyzable),
            versions=sorted(supported_versions),
            alerts_unsupported_version=alerts_unsupported_version,
        )
