# SPDX-License-Identifier: MPL-2.0

import enum
import hashlib
import ipaddress
import typing

import attr

from cryptodatahub.common.algorithm import IpProtocolNumber
from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1CertificateType,
    Ikev1IdType,
    Ikev1PayloadType,
    Ikev2AuthenticationMethod,
    Ikev2CertificateType,
    Ikev2DiffieHellmanGroup,
    Ikev2IdType,
)
from cryptoparser.common.base import Serializable
from cryptoparser.ike.isakmp import IsakmpMessage
from cryptoparser.ike.ikev1 import Ikev1PayloadCertificate
from cryptoparser.ike.ikev2 import (
    Ikev2AuthDigitalSignatureEnvelope,
    Ikev2PayloadAuthentication,
    Ikev2PayloadCertificate,
    Ikev2PayloadIdentificationResponderBase,
)

from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke
from cryptolyzer.common.x509 import (
    CertificateChainX509,
    CertificateChainX509Validator,
    PublicKeyX509,
)
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.crypto import _NegotiatedIkev2Transforms
from cryptolyzer.ike.pubkey import _AnalyzerIkePubkeyBase


class Transport(Serializable, enum.Enum):
    AGGRESSIVE_CLEARTEXT = 'IKEv1 aggressive (cleartext)'
    IKEV2_EAP_MODE = 'IKEv2 EAP mode'

    def _as_markdown(self, level: int) -> tuple[bool, str]:
        return False, self.value


@attr.s
class IkeIdentification(Serializable):
    """One IKEv1 IDENTIFICATION payload (RFC 2408 §3.8, RFC 2407 §4.6.2) captured from a peer."""

    id_type: Ikev1IdType = attr.ib(
        validator=attr.validators.instance_of(Ikev1IdType),
        metadata={'human_readable_name': 'ID Type'},
    )
    protocol_id: IpProtocolNumber = attr.ib(
        validator=attr.validators.instance_of(IpProtocolNumber),
        metadata={'human_readable_name': 'Protocol ID'},
    )
    port: int = attr.ib(validator=attr.validators.instance_of(int))
    id_data: typing.Union[bytes, bytearray] = attr.ib(
        validator=attr.validators.instance_of((bytes, bytearray)),
        metadata={'human_readable_name': 'ID Data'},
    )

    _IKEV2_TO_IKEV1_ID_TYPE: typing.ClassVar[dict[Ikev2IdType, Ikev1IdType]] = {
        Ikev2IdType.IPV4_ADDR: Ikev1IdType.IPV4_ADDR,
        Ikev2IdType.FQDN: Ikev1IdType.FQDN,
        Ikev2IdType.RFC822_ADDR: Ikev1IdType.USER_FQDN,
        Ikev2IdType.IPV6_ADDR: Ikev1IdType.IPV6_ADDR,
        Ikev2IdType.DER_ASN1_DN: Ikev1IdType.DER_ASN1_DN,
        Ikev2IdType.DER_ASN1_GN: Ikev1IdType.DER_ASN1_GN,
    }

    @staticmethod
    def wire_bytes(id_payload: typing.Any) -> bytes:
        """Mirror per-type ``_encode_identifier`` logic on cryptoparser ``IkeIdentification*Mixin`` mixins via public
        :attr:`identifier` to avoid poking cryptoparser's protected methods."""
        identifier = id_payload.identifier
        if isinstance(identifier, str):
            return identifier.encode('ascii')
        if isinstance(identifier, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return identifier.packed
        return bytes(identifier)

    @classmethod
    def ikev1_id_type_from_ikev2(cls, id_type: Ikev2IdType) -> Ikev1IdType:
        """IPv4/IPv6 address, FQDN, and DER-encoded distinguished/general name pass through unchanged; the IKEv2-only
        e-mail address falls back to user FQDN; every other IKEv2-only identity (Fibre Channel name, NULL identity,
        ...) falls back to the opaque key ID."""
        return cls._IKEV2_TO_IKEV1_ID_TYPE.get(id_type, Ikev1IdType.KEY_ID)


@attr.s
class CertificateChainIke(Serializable):  # pylint: disable=too-many-instance-attributes
    """One certificate-bearing result row from an IKE pubkeys probe.

    There is one row per certificate encoding the responder offered. Only one of ``certificate_chain`` / ``raw_bytes``
    is populated, picked by the encoding:

    - X.509 signature certificate / PKCS#7-wrapped X.509 certificate → ``certificate_chain`` populated with the parsed
      X.509 chain.
    - Certificate revocation list / authority revocation list → ``raw_bytes`` populated with the raw payload.
    - Other encodings (PGP, DNS-signed key, Kerberos token, SPKI, X.509 attribute) are out of scope per RFC 4945 §3.2.1
      and currently rejected by the analyzer.

    :param identification: Responder's identification payload.
    :param auth_method_used: Authentication method the responder offered (RSA signature, ECDSA over P-256 / P-384 /
        P-521 — selected on the analyzer side).
    :param signature_length: Octet length of the responder's signature payload (analytics; tells RSA modulus size or
        ECDSA curve from r||s).
    :param transport: How the certificate reached the analyzer — see :class:`Transport`.
    :param auth_envelope: IKEv2-only — populated when the responder's authentication payload uses the RFC 7427 digital
        signature envelope. Carries the algorithm-identifier OID + raw signature bytes extracted from the payload's
        authentication data field. ``None`` for IKEv1 and for the IKEv2 legacy authentication methods.
    """

    cert_encoding = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of((Ikev1CertificateType, Ikev2CertificateType))
        ),
    )
    identification = attr.ib(validator=attr.validators.instance_of(IkeIdentification))
    auth_method_used = attr.ib(validator=attr.validators.instance_of(
        (Ikev1AuthenticationMethod, Ikev2AuthenticationMethod)
    ))
    signature_length = attr.ib(
        validator=attr.validators.instance_of(int),
        metadata={'human_friendly': False},
    )
    transport = attr.ib(validator=attr.validators.in_(Transport))
    certificate_chain = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(CertificateChainX509)),
    )
    raw_bytes = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of((bytes, bytearray))),
    )
    auth_envelope = attr.ib(
        default=None,
        validator=attr.validators.optional(
            attr.validators.instance_of(Ikev2AuthDigitalSignatureEnvelope)
        ),
    )

    @staticmethod
    def _build_x509_chain(cert_payloads: list[Ikev1PayloadCertificate]) -> CertificateChainX509:
        public_keys = [
            PublicKeyX509.from_der(bytes(cert_payload.certificate_data))
            for cert_payload in cert_payloads
        ]
        return CertificateChainX509Validator()(items=public_keys, certificate_status_list=[])

    @classmethod
    def from_ikev1_aggressive_response(
            cls,
            response: IsakmpMessage,
            auth_method: Ikev1AuthenticationMethod,
    ) -> typing.Optional['CertificateChainIke']:
        """Return ``None`` if IDir or SIG_R missing (RFC 2409 §5.1). SIG_R present but CERT absent yields a cert-less
        row (``cert_encoding=None`` / ``certificate_chain=None`` / ``raw_bytes=None``) — distinguishes
        ``send_cert=never`` from probe failure."""
        id_payloads = response.get_payloads_by_type(Ikev1PayloadType.IDENTIFICATION)
        if not id_payloads:
            return None
        id_payload = id_payloads[0]

        signature_payloads = response.get_payloads_by_type(Ikev1PayloadType.SIGNATURE)
        if not signature_payloads:
            return None
        signature_length = len(bytes(signature_payloads[0].signature_data))

        identification = IkeIdentification(
            id_type=id_payload.id_type,
            protocol_id=id_payload.protocol_id,
            port=id_payload.port,
            id_data=IkeIdentification.wire_bytes(id_payload),
        )

        cert_payloads = response.get_payloads_by_type(Ikev1PayloadType.CERTIFICATE)
        x509_cert_payloads = [
            cert_payload for cert_payload in cert_payloads
            if cert_payload.cert_encoding == Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE
        ]
        if x509_cert_payloads:
            return cls(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                identification=identification,
                auth_method_used=auth_method,
                signature_length=signature_length,
                transport=Transport.AGGRESSIVE_CLEARTEXT,
                certificate_chain=cls._build_x509_chain(x509_cert_payloads),
            )

        if cert_payloads:
            first = cert_payloads[0]
            return cls(
                cert_encoding=first.cert_encoding,
                identification=identification,
                auth_method_used=auth_method,
                signature_length=signature_length,
                transport=Transport.AGGRESSIVE_CLEARTEXT,
                raw_bytes=bytes(first.certificate_data),
            )

        return cls(
            cert_encoding=None,
            identification=identification,
            auth_method_used=auth_method,
            signature_length=signature_length,
            transport=Transport.AGGRESSIVE_CLEARTEXT,
        )

    @classmethod
    def from_ikev2_eap_inner_payloads(
            cls,
            inner_payloads: list[typing.Any],
    ) -> typing.Optional['CertificateChainIke']:
        """Return ``None`` if IDr or AUTH missing (responder refused EAP-mode or SK envelope decrypted to something
        unexpected). Payload chain per RFC 7296 §2.16: ``IDr, [CERT,] AUTH, [EAP]``."""
        identification_responder = None
        cert_payloads: list[Ikev2PayloadCertificate] = []
        auth_payload: typing.Optional[Ikev2PayloadAuthentication] = None

        for payload in inner_payloads:
            if isinstance(payload, Ikev2PayloadIdentificationResponderBase):
                identification_responder = payload
            elif isinstance(payload, Ikev2PayloadCertificate):
                cert_payloads.append(payload)
            elif isinstance(payload, Ikev2PayloadAuthentication):
                auth_payload = payload

        if identification_responder is None or auth_payload is None:
            return None

        identification = IkeIdentification(
            id_type=IkeIdentification.ikev1_id_type_from_ikev2(identification_responder.id_type),
            protocol_id=IpProtocolNumber.HOPOPT,
            port=0,
            id_data=IkeIdentification.wire_bytes(identification_responder),
        )

        x509_cert_payloads = [
            cert_payload for cert_payload in cert_payloads
            if cert_payload.cert_encoding == Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE
        ]
        certificate_chain = cls._build_x509_chain(x509_cert_payloads) if x509_cert_payloads else None
        raw_bytes = (
            bytes(cert_payloads[0].certificate_data) if cert_payloads and not x509_cert_payloads
            else None
        )

        auth_envelope: typing.Optional[Ikev2AuthDigitalSignatureEnvelope] = None
        if auth_payload.auth_method == Ikev2AuthenticationMethod.DIGITAL_SIGNATURE:
            auth_envelope = auth_payload.parse_digital_signature_envelope()

        return cls(
            cert_encoding=cert_payloads[0].cert_encoding if cert_payloads else None,
            identification=identification,
            auth_method_used=auth_payload.auth_method,
            signature_length=len(bytes(auth_payload.auth_data)),
            transport=Transport.IKEV2_EAP_MODE,
            certificate_chain=certificate_chain,
            raw_bytes=raw_bytes,
            auth_envelope=auth_envelope,
        )

    def fingerprint(self) -> bytes:
        """Stable dedup key for one probe outcome. When an X.509 chain is present, hashes the leaf certificate's DER
        so probes returning the same end-entity certificate collapse to one row regardless of the authentication
        method that selected them. When only raw payload bytes are present (raw public key or other non-X.509
        encoding), those bytes are the identifier. When neither is present (authentication succeeded without a
        certificate payload), falls back to the responder's identification + authentication method so two distinct
        identity-only rows do not collide."""
        if self.certificate_chain is not None and self.certificate_chain.items:
            leaf = self.certificate_chain.items[0]
            return hashlib.sha256(leaf.der).digest()
        if self.raw_bytes is not None:
            return bytes(self.raw_bytes)
        return repr((self.identification, self.auth_method_used)).encode('utf-8')


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultIKE):
    """
    :param public_keys: List of certificate-bearing rows the responder offered (one per ``cert_encoding``).
    """

    public_keys: list[CertificateChainIke] = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(CertificateChainIke)),
        metadata={'human_readable_name': 'IKE Public Keys'},
    )


@attr.s
class _Ikev2PubkeysState:  # pylint: disable=too-few-public-methods
    results: list[CertificateChainIke] = attr.ib(factory=list)
    seen_fingerprints: set[bytes] = attr.ib(factory=set)


class AnalyzerPublicKeys(_AnalyzerIkePubkeyBase):
    _ANALYZER_LABEL = 'pubkeys'

    @classmethod
    def get_name(cls) -> str:
        return 'pubkeys'

    @classmethod
    def get_help(cls) -> str:
        return 'Check which public keys used by the server(s)'

    @classmethod
    def _ikev1_new_state(cls) -> list[CertificateChainIke]:
        return []

    @classmethod
    def _ikev1_absorb(
            cls,
            state: list[CertificateChainIke],
            response: IsakmpMessage,
            auth_method: Ikev1AuthenticationMethod,
    ) -> None:
        row = CertificateChainIke.from_ikev1_aggressive_response(response, auth_method)
        if row is not None:
            state.append(row)

    @classmethod
    def _ikev1_build_result(
            cls,
            target: AnalyzerTargetIke,
            state: list[CertificateChainIke],
    ) -> AnalyzerResultPublicKeys:
        return AnalyzerResultPublicKeys(target, state)

    @classmethod
    def _ikev2_new_state(cls) -> _Ikev2PubkeysState:
        return _Ikev2PubkeysState()

    @classmethod
    def _ikev2_absorb(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            cls,
            state: _Ikev2PubkeysState,
            analyzable: L7ClientIPsecBase,
            dh_group: Ikev2DiffieHellmanGroup,
            algorithm_set: _NegotiatedIkev2Transforms,
            auth_method: Ikev2AuthenticationMethod,  # pylint: disable=unused-argument
    ) -> None:
        row = cls._ikev2_try_eap_probe(
            analyzable, dh_group, algorithm_set,
            lambda _init_payloads, inner_payloads:
                CertificateChainIke.from_ikev2_eap_inner_payloads(inner_payloads),
        )
        if row is None:
            return
        fingerprint = row.fingerprint()
        if fingerprint in state.seen_fingerprints:
            return
        state.seen_fingerprints.add(fingerprint)
        state.results.append(row)

    @classmethod
    def _ikev2_dh_group_sufficient(cls, state: _Ikev2PubkeysState) -> bool:
        # First DH group that yielded a chain is enough — the responder's cert-chain choice does not depend on the
        # negotiated group so multi-probing further accepted groups only duplicates work.
        return bool(state.results)

    @classmethod
    def _ikev2_build_result(
            cls,
            target: AnalyzerTargetIke,
            state: _Ikev2PubkeysState,
    ) -> AnalyzerResultPublicKeys:
        return AnalyzerResultPublicKeys(target, state.results)
