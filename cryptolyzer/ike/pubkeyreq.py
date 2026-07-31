# SPDX-License-Identifier: MPL-2.0

"""IKE public-key-request analyzer."""

import collections
import typing

import attr

from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1CertificateType,
    Ikev1ExchangeType,
    Ikev1PayloadType,
    Ikev2AuthenticationMethod,
    Ikev2CertificateType,
    Ikev2DiffieHellmanGroup,
    Ikev2PayloadType,
)

from cryptoparser.ike.isakmp import IsakmpMessage
from cryptoparser.ike.ikev1 import Ikev1PayloadCertificateRequest
from cryptoparser.ike.ikev2 import Ikev2PayloadCertificateRequest

from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.crypto import _NegotiatedIkev2Transforms
from cryptolyzer.ike.pubkey import _AnalyzerIkePubkeyBase


@attr.s
class AnalyzerResultIkev1PublicKeyRequest(AnalyzerResultIKE):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result for IKEv1 CERTREQ payloads (RFC 2408 §3.10).

    :param certificate_types: Certificate Encodings the responder advertised (deduplicated, first-seen order).
    :param distinguished_names: Parsed X.501 subject-DN dicts extracted from each X.509 CERTREQ (deduplicated,
        first-seen order). ``None`` when the responder sent no CERTREQ payloads.
    """

    certificate_types = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.in_(Ikev1CertificateType),
        )),
        metadata={'human_readable_name': 'Certificate Types'},
    )
    distinguished_names = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(collections.OrderedDict),
        )),
        metadata={'human_readable_name': 'Trusted Distinguished Names'},
    )


@attr.s
class AnalyzerResultIkev2PublicKeyRequest(AnalyzerResultIKE):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result for IKEv2 CERTREQ payloads (RFC 7296 §3.7).

    :param certificate_types: Certificate Encodings the responder advertised (deduplicated, first-seen order).
    :param trusted_ca_hashes: 20-octet SHA-1(SPKI) hashes extracted from every X.509 CERTREQ's concatenated authority
        field (deduplicated, first-seen order). ``None`` when the responder sent no CERTREQ payloads.
    """

    certificate_types = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.in_(Ikev2CertificateType),
        )),
        metadata={'human_readable_name': 'Certificate Types'},
    )
    trusted_ca_hashes = attr.ib(
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(bytes),
        )),
        metadata={'human_readable_name': 'Trusted CA SHA-1(SPKI) Hashes'},
    )


@attr.s
class _Ikev1PubkeyreqState:  # pylint: disable=too-few-public-methods
    certificate_types: list[Ikev1CertificateType] = attr.ib(factory=list)
    distinguished_names: list[collections.OrderedDict] = attr.ib(factory=list)
    certreq_seen: bool = attr.ib(default=False)


@attr.s
class _Ikev2PubkeyreqState:  # pylint: disable=too-few-public-methods
    certificate_types: list[Ikev2CertificateType] = attr.ib(factory=list)
    trusted_ca_hashes: list[bytes] = attr.ib(factory=list)
    certreq_seen: bool = attr.ib(default=False)


class AnalyzerPublicKeyRequest(_AnalyzerIkePubkeyBase):
    """Enumerate which trust anchors the responder requests from the initiator via CERTREQ payloads (RFC 2408 §3.10
    for IKEv1, RFC 7296 §3.7 for IKEv2). Runs the shared pubkey probe grid and walks each response's CERTREQ payloads
    for the responder's trusted-CA hint list."""

    _ANALYZER_LABEL = 'pubkeyreq'

    #: RFC 7296 §3.7: encodings whose CERTREQ Certification Authority field carries concatenated 20-octet SHA-1(SPKI)
    #: hashes of trusted CAs. Other encodings (raw public key, PGP, DNS) carry different content and are skipped.
    _IKEV2_CERTREQ_HASH_BEARING_ENCODINGS: typing.ClassVar[frozenset[Ikev2CertificateType]] = frozenset({
        Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
        Ikev2CertificateType.HASH_AND_URL_OF_X509_CERTIFICATE,
        Ikev2CertificateType.HASH_AND_URL_OF_X509_BUNDLE,
    })

    @classmethod
    def get_name(cls) -> str:
        return 'pubkeyreq'

    @classmethod
    def get_help(cls) -> str:
        return 'Check which certificate authorities the server(s) request from the initiator'

    @staticmethod
    def _get_ikev1_certreq_data(
            response: IsakmpMessage,
    ) -> tuple[list[Ikev1CertificateType], list[collections.OrderedDict]]:
        """Collect Certificate Types and Distinguished Names from CERTREQ payloads (RFC 2408 §3.10)."""
        certificate_types: list[Ikev1CertificateType] = []
        distinguished_names: list[collections.OrderedDict] = []
        for payload in response.payloads:
            if not isinstance(payload, Ikev1PayloadCertificateRequest):
                continue

            if payload.cert_encoding not in certificate_types:
                certificate_types.append(payload.cert_encoding)

            if payload.cert_encoding != Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE:
                continue

            parsed = payload.get_distinguished_name()
            if parsed is not None and parsed not in distinguished_names:
                distinguished_names.append(parsed)

        return certificate_types, distinguished_names

    @classmethod
    def _get_ikev2_certreq_data(
            cls, inner_payloads: list[typing.Any],
    ) -> tuple[list[Ikev2CertificateType], list[bytes]]:
        """Collect Certificate Types and trusted-CA SHA-1(SPKI) hashes from CERTREQ payloads (RFC 7296 §3.7)."""
        certificate_types: list[Ikev2CertificateType] = []
        trusted_ca_hashes: list[bytes] = []
        for payload in inner_payloads:
            if not isinstance(payload, Ikev2PayloadCertificateRequest):
                continue

            if payload.cert_encoding not in certificate_types:
                certificate_types.append(payload.cert_encoding)

            if payload.cert_encoding not in cls._IKEV2_CERTREQ_HASH_BEARING_ENCODINGS:
                continue

            for trusted_ca_hash in payload.get_authority_hashes():
                if trusted_ca_hash not in trusted_ca_hashes:
                    trusted_ca_hashes.append(trusted_ca_hash)

        return certificate_types, trusted_ca_hashes

    @classmethod
    def _ikev1_new_state(cls) -> _Ikev1PubkeyreqState:
        return _Ikev1PubkeyreqState()

    @classmethod
    def _ikev1_absorb(
            cls,
            state: _Ikev1PubkeyreqState,
            response: IsakmpMessage,
            _auth_method: Ikev1AuthenticationMethod,
    ) -> None:
        if response.exchange_type != Ikev1ExchangeType.AGGRESSIVE:
            return
        for payload in response.payloads:
            if payload.get_payload_type() == Ikev1PayloadType.CERTIFICATE_REQUEST:
                state.certreq_seen = True
                break
        per_probe_types, per_probe_names = cls._get_ikev1_certreq_data(response)
        for cert_type in per_probe_types:
            if cert_type not in state.certificate_types:
                state.certificate_types.append(cert_type)
        for name in per_probe_names:
            if name not in state.distinguished_names:
                state.distinguished_names.append(name)

    @classmethod
    def _ikev1_build_result(
            cls,
            target: AnalyzerTargetIke,
            state: _Ikev1PubkeyreqState,
    ) -> AnalyzerResultIkev1PublicKeyRequest:
        return AnalyzerResultIkev1PublicKeyRequest(
            target=target,
            certificate_types=state.certificate_types if state.certreq_seen else None,
            distinguished_names=state.distinguished_names if state.distinguished_names else None,
        )

    @classmethod
    def _ikev2_new_state(cls) -> _Ikev2PubkeyreqState:
        return _Ikev2PubkeyreqState()

    @classmethod
    def _ikev2_absorb(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            cls,
            state: _Ikev2PubkeyreqState,
            analyzable: L7ClientIPsecBase,
            dh_group: Ikev2DiffieHellmanGroup,
            algorithm_set: _NegotiatedIkev2Transforms,
            _auth_method: Ikev2AuthenticationMethod,
    ) -> None:
        probe_outcome = cls._ikev2_run_eap_probe(analyzable, dh_group, algorithm_set)
        if probe_outcome is None:
            return
        all_payloads = list(probe_outcome[0]) + list(probe_outcome[1])
        if any(payload.get_payload_type() == Ikev2PayloadType.CERTREQ for payload in all_payloads):
            state.certreq_seen = True
        per_probe_types, per_probe_hashes = cls._get_ikev2_certreq_data(all_payloads)
        for cert_type in per_probe_types:
            if cert_type not in state.certificate_types:
                state.certificate_types.append(cert_type)
        for trusted_ca_hash in per_probe_hashes:
            if trusted_ca_hash not in state.trusted_ca_hashes:
                state.trusted_ca_hashes.append(trusted_ca_hash)

    @classmethod
    def _ikev2_dh_group_sufficient(cls, state: _Ikev2PubkeyreqState) -> bool:
        # First DH group that yielded CERTREQ payloads is enough — the responder's trust list does not depend on the
        # negotiated group so multi-probing further groups only duplicates work.
        return state.certreq_seen

    @classmethod
    def _ikev2_build_result(
            cls,
            target: AnalyzerTargetIke,
            state: _Ikev2PubkeyreqState,
    ) -> AnalyzerResultIkev2PublicKeyRequest:
        return AnalyzerResultIkev2PublicKeyRequest(
            target=target,
            certificate_types=state.certificate_types if state.certreq_seen else None,
            trusted_ca_hashes=state.trusted_ca_hashes if state.trusted_ca_hashes else None,
        )
