# SPDX-License-Identifier: MPL-2.0
# pylint: disable=too-many-lines

import abc
import secrets
import typing

from cryptodatahub.common.algorithm import IpProtocolNumber
from cryptodatahub.common.parameter import ECParamWellKnown
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1CertificateType,
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1ExchangeType,
    Ikev1LifeType,
    Ikev1NotifyType,
    Ikev1ProtocolId,
    Ikev1TransformId,
    Ikev2AuthenticationMethod,
    Ikev2CertificateType,
    Ikev2DiffieHellmanGroup,
    Ikev2ExchangeType,
    Ikev2HashAlgorithm,
    Ikev2PayloadType,
)

from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.version import IsakmpProtocolVersion
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadCookie,
    Ikev2NotifyPayloadInvalidKe,
    Ikev2PayloadCertificateRequest,
    Ikev2PayloadIdentificationInitiatorRfc822Addr,
)
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeAuthenticationMethod,
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
    Ikev1AttributeKeyLength,
    Ikev1AttributeLifeDuration,
    Ikev1AttributeLifeType,
    Ikev1PayloadCertificateRequest,
    Ikev1PayloadIdentificationFqdn,
    Ikev1PayloadKeyExchange,
    Ikev1PayloadNonce,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
    Ikev1PayloadTransform,
    Ikev1Situation,
)

from cryptolyzer import __setup__
from cryptolyzer.ike.common import AnalyzerIKEBase
from cryptolyzer.common.dhparam import get_dh_ephemeral_key_forged, int_to_bytes
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.common.crypto import HashCryptodome
from cryptolyzer.ike.client import (
    Ikev2SecurityAssociationSpecialization,
    L7ClientIPsecBase,
)
from cryptolyzer.ike.dh import AnalyzerDHBase
from cryptolyzer.ike.crypto import (
    Ikev2KeyScheduleCryptodome,
    Ikev2SkDecryptorCryptodome,
    Ikev2SkDecryptorNonAeadCryptodome,
    Ikev2SkDecryptor,
    _NegotiatedIkev1Transforms,
    _NegotiatedIkev2Transforms,
    dhe_ephemeral_material_backend,
)
from cryptolyzer.ike.exception import (
    IsakmpNotify,
    Ikev2SkAuthenticationError,
    Ikev2TransformDerivationError,
)
from cryptolyzer.ike.isakmp import parse_ike_message


_IKEV1_PUBKEY_AUTH_METHODS: tuple[Ikev1AuthenticationMethod, ...] = (
    Ikev1AuthenticationMethod.RSA_SIGNATURES,
    Ikev1AuthenticationMethod.ECDSA_SHA_256_P_256,
    Ikev1AuthenticationMethod.ECDSA_SHA_384_P_384,
    Ikev1AuthenticationMethod.ECDSA_SHA_512_P_521,
)
_IKEV1_CERTREQ_ACCEPT_ANY_CA: bytes = b''
_IKEV1_INITIATOR_ID_FQDN: str = __setup__.__technical_name__


_IKEV2_PUBKEY_AUTH_METHODS: tuple[Ikev2AuthenticationMethod, ...] = (
    Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE,
    Ikev2AuthenticationMethod.DSS_DIGITAL_SIGNATURE,
    Ikev2AuthenticationMethod.ECDSA_SHA_256_P_256,
    Ikev2AuthenticationMethod.ECDSA_SHA_384_P_384,
    Ikev2AuthenticationMethod.ECDSA_SHA_512_P_521,
    Ikev2AuthenticationMethod.DIGITAL_SIGNATURE,
)
_IKEV2_PROBE_CERTREQ_ENCODINGS: tuple[Ikev2CertificateType, ...] = (
    Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
    Ikev2CertificateType.HASH_AND_URL_OF_X509_CERTIFICATE,
    Ikev2CertificateType.HASH_AND_URL_OF_X509_BUNDLE,
    Ikev2CertificateType.RAW_PUBLIC_KEY,
)
_IKEV2_PROBE_PREFERRED_DH_GROUPS: tuple[Ikev2DiffieHellmanGroup, ...] = (
    dhe_ephemeral_material_backend.supported_dh_groups()
)
_IKEV2_INITIATOR_ID_RFC822_ADDR: str = (
    f'{__setup__.__technical_name__}@{__setup__.__technical_name__}'
)

_IKEV2_PROBE_MAX_INIT_ATTEMPTS = 3


class _AnalyzerIkePubkeyBase(AnalyzerIKEBase):
    """Shared IKEv1 + IKEv2 probe-grid skeleton for pubkey-facing analyzers (pubkeys, pubkeyreq).

    Handles DH-group discovery, per-version grid log, per-iteration probe log, and the loop that drives one probe per
    ``(dh_group, auth_method)`` cell. Subclasses provide the per-iteration probe callable + per-version accumulator
    hooks that build the concrete result row(s).
    """

    @classmethod
    def _ikev1_build_aggressive_proposal(cls,
            auth_method: Ikev1AuthenticationMethod,
            dh_group: Ikev1DiffieHellmanGroup,
            algorithm_set: '_NegotiatedIkev1Transforms',
    ) -> Ikev1PayloadProposal:
        """``algorithm_set`` narrows to the server-confirmed ``(encr, hash, key_length)`` so the responder cannot
        reject on cipher / hash / key-length mismatch."""
        attributes = [
            Ikev1AttributeEncryptionAlgorithm(algorithm_set.encryption_algorithm),
        ]
        if algorithm_set.key_length is not None:
            attributes.append(Ikev1AttributeKeyLength(algorithm_set.key_length))
        attributes.extend([
            Ikev1AttributeHashAlgorithm(algorithm_set.hash_algorithm),
            Ikev1AttributeDiffieHellmanGroup(dh_group),
            Ikev1AttributeAuthenticationMethod(auth_method),
            Ikev1AttributeLifeType(value=Ikev1LifeType.SECONDS),
            Ikev1AttributeLifeDuration(value=86400),
        ])
        return Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP,
            transforms=[Ikev1PayloadTransform(
                transform_id=Ikev1TransformId.KEY_IKE,
                attributes=attributes,
            )],
        )

    @classmethod
    def _ikev1_build_key_exchange_payload(cls,
            dh_group: Ikev1DiffieHellmanGroup,
    ) -> Ikev1PayloadKeyExchange:
        """MODP groups use a forged half-key mod ``p`` (pubkeys probe discards the shared secret); ECDH groups need
        a real ephemeral because Cryptodome's point-validation-on-import rejects forged random points."""
        key_parameter = dh_group.value.key_parameter
        if isinstance(key_parameter, DHParamWellKnown):
            return Ikev1PayloadKeyExchange(
                key_exchange_data=int_to_bytes(
                    get_dh_ephemeral_key_forged(
                        key_parameter.value.parameter_numbers.p,
                    ),
                    key_parameter.value.field_size // 8,
                ),
            )
        if isinstance(key_parameter, ECParamWellKnown):
            ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
            return Ikev1PayloadKeyExchange(
                key_exchange_data=dhe_ephemeral_material_backend.key_exchange_wire_bytes(dh_group, ephemeral),
            )
        raise NotImplementedError(dh_group)

    @classmethod
    def _ikev1_build_aggressive_init_message(cls,
            auth_method: Ikev1AuthenticationMethod,
            dh_group: Ikev1DiffieHellmanGroup,
            algorithm_set: typing.Optional[_NegotiatedIkev1Transforms] = None,
    ) -> IsakmpMessage:
        """RFC 2409 §5.1 payload order ``HDR, SA, KE, Ni, IDii, CERTREQ``. Built directly because
        ``Ikev1SecurityAssociationSpecialization`` puts KE / Ni before SA (wire-incorrect for Aggressive Mode) and
        has no IDii / CERTREQ knob."""
        proposal = cls._ikev1_build_aggressive_proposal(auth_method, dh_group, algorithm_set)

        security_association = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=[proposal],
        )

        key_exchange = cls._ikev1_build_key_exchange_payload(dh_group)

        nonce = Ikev1PayloadNonce(nonce_data=secrets.token_bytes(32))

        initiator_id = Ikev1PayloadIdentificationFqdn(
            protocol_id=IpProtocolNumber.HOPOPT,
            port=0,
            identifier=_IKEV1_INITIATOR_ID_FQDN,
        )

        cert_request = Ikev1PayloadCertificateRequest(
            cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
            certification_authority=_IKEV1_CERTREQ_ACCEPT_ANY_CA,
        )

        return IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=secrets.randbits(64),
            responder_spi=0,
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=[
                security_association,
                key_exchange,
                nonce,
                initiator_id,
                cert_request,
            ],
        )

    @classmethod
    def _ikev1_run_aggressive_probe(cls,
            l7_client: L7ClientIPsecBase,
            auth_method: Ikev1AuthenticationMethod,
            dh_group: Ikev1DiffieHellmanGroup,
            algorithm_set: typing.Optional[_NegotiatedIkev1Transforms] = None,
    ) -> typing.Optional[IsakmpMessage]:
        """Return the last responder :class:`IsakmpMessage`, or ``None`` on any benign failure (``NO_PROPOSAL_CHOSEN``,
        other error notifies, no response)."""
        init_message = cls._ikev1_build_aggressive_init_message(auth_method, dh_group, algorithm_set)

        try:
            server_messages = l7_client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            )
        except IsakmpNotify as exc:
            if exc.notify == Ikev1NotifyType.NO_PROPOSAL_CHOSEN:
                LogSingleton().log(
                    level=40,
                    msg=f'No proposal chosen; auth_method={str(auth_method.value)}',
                )
                return None
            LogSingleton().log(
                level=60,
                msg=f'Notify response from server; auth_method={str(auth_method.value)}, notify={exc.notify}',
            )
            return None
        except NetworkError as exc:
            if exc.error == NetworkErrorType.NO_RESPONSE:
                LogSingleton().log(
                    level=60,
                    msg=f'No response from server; auth_method={str(auth_method.value)}, '
                        f'address={l7_client.address}:{l7_client.port}',
                )
                return None
            raise

        aggressive_messages = server_messages.get(Ikev1ExchangeType.AGGRESSIVE, [])
        if not aggressive_messages:
            return None
        return aggressive_messages[-1]

    @classmethod
    def _ikev2_build_eap_mode_inner_payloads(cls,
            initiator_identification_data: str = _IKEV2_INITIATOR_ID_RFC822_ADDR,
    ) -> list[typing.Any]:
        """RFC 7296 §2.16: omit AUTH to signal EAP; responder sends ``IDr, [CERT,] AUTH, EAP``. SAi2 + TSi + TSr
        skipped — cryptoparser does not yet model traffic selectors and §2.21.2 lets the responder still return
        ``IDr, [CERT,] AUTH`` alongside a Child-SA error."""
        payloads: list[typing.Any] = [
            Ikev2PayloadIdentificationInitiatorRfc822Addr(
                flags=set(),
                identifier=initiator_identification_data,
            ),
        ]
        payloads.extend(
            Ikev2PayloadCertificateRequest(
                flags=set(),
                cert_encoding=cert_encoding,
                certification_authority=b'',
            )
            for cert_encoding in _IKEV2_PROBE_CERTREQ_ENCODINGS
        )
        return payloads

    @classmethod
    def _receive_isakmp_message(cls, l4_transfer: typing.Any) -> tuple[IsakmpMessage, bytes]:
        """Returns ``(parsed_message, raw_bytes)``. Raw bytes are needed to compute the SK envelope AAD."""
        receivable_byte_num = 0
        while True:
            try:
                message, parsed_length = parse_ike_message(l4_transfer.buffer)
                raw_bytes = bytes(l4_transfer.buffer[:parsed_length])
                l4_transfer.flush_buffer(parsed_length)
                return message, raw_bytes
            except NotEnoughData as exc:
                receivable_byte_num = exc.bytes_needed

            try:
                l4_transfer.receive(receivable_byte_num)
            except NotEnoughData as exc:
                if l4_transfer.buffer:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION) from exc
                raise NetworkError(NetworkErrorType.NO_RESPONSE) from exc

    @classmethod
    def _ikev2_run_eap_probe(cls,
            l7_client: L7ClientIPsecBase,
            dh_group: Ikev2DiffieHellmanGroup,
            algorithm_set: typing.Optional[_NegotiatedIkev2Transforms] = None,
    ) -> typing.Optional[tuple[list[typing.Any], list[typing.Any]]]:
        """Returns ``(ike_sa_init_response_payloads, ike_auth_inner_payloads)`` or ``None`` on any benign failure."""
        captured: list[list[typing.Any]] = []

        def capture(init_payloads: list[typing.Any],
                    inner_payloads: list[typing.Any]) -> None:
            captured.append(init_payloads)
            captured.append(inner_payloads)

        cls._ikev2_try_eap_probe(l7_client, dh_group, algorithm_set, capture)
        if not captured:
            return None
        return captured[0], captured[1]

    @classmethod
    def _ikev2_try_eap_probe(cls,
            l7_client: L7ClientIPsecBase,
            dh_group: Ikev2DiffieHellmanGroup,
            algorithm_set: typing.Optional[_NegotiatedIkev2Transforms],
            inner_payloads_extractor: typing.Callable[[list[typing.Any], list[typing.Any]], typing.Any],
    ) -> typing.Optional[typing.Any]:  # pylint: disable=too-many-locals
        """Run one IKEv2 EAP-mode pubkeys probe (RFC 7296 §2.16).

        Drives the wire directly: IKE_SA_INIT → derive ``SK_*`` → IKE_AUTH with omitted AUTH (EAP-mode signal) → decrypt
        the responder's reply → invoke ``inner_payloads_extractor(init_payloads, inner_payloads)`` to shape the
        return. Returns ``None`` on any benign failure (responder refused EAP-mode, network silence, parse error).
        Handles both AEAD (AES-GCM, ChaCha20-Poly1305) and non-AEAD (AES-CBC + HMAC) SK envelopes; the compose /
        decrypt pair is chosen by :meth:`Ikev2SkDecryptor.select_envelope_funcs` from the negotiated encryption
        transform.
        """
        try:
            l7_client.init_connection()
        except NetworkError as exc:
            LogSingleton().log(
                level=60, msg=f'IKEv2 EAP probe init failed: {exc.error}',
            )
            return None

        try:
            return cls._ikev2_try_eap_probe_inner(
                l7_client, dh_group, algorithm_set, inner_payloads_extractor,
            )
        except NetworkError as exc:
            LogSingleton().log(
                level=60, msg=f'IKEv2 EAP probe network error: {exc.error}',
            )
            return None
        except Ikev2SkAuthenticationError as exc:
            LogSingleton().log(
                level=60, msg=f'IKEv2 EAP probe SK authentication failure; error={exc}',
            )
            return None
        except Ikev2TransformDerivationError as exc:
            LogSingleton().log(
                level=60, msg=f'IKEv2 EAP probe transform not supported; error={exc}',
            )
            return None
        except (InvalidType, KeyError) as exc:
            LogSingleton().log(
                level=60, msg=f'IKEv2 EAP probe parse error; error_type={type(exc).__name__}, error={exc}',
            )
            return None
        finally:
            l7_client._close_connection()  # pylint: disable=protected-access

    @classmethod
    def _ikev2_format_negotiated_transforms_for_log(cls,
            transforms: _NegotiatedIkev2Transforms,
    ) -> str:
        """Format one ``Server offered`` log line per ``ike/`` IKE log format (event phrase + ``; key=value`` pairs)."""
        mode = (
            transforms.encryption_descriptor.block_cipher_mode.name
            if transforms.encryption_descriptor.block_cipher_mode is not None
            else 'NONE'
        )
        integ = (
            str(transforms.integrity_algorithm.value)
            if transforms.integrity_algorithm is not None
            else 'NONE'
        )
        return (
            'Server offered; '
            f'encr={str(transforms.encryption_algorithm.value)}, '
            f'mode={mode}, '
            f'integ={integ}, '
            f'prf={str(transforms.prf.value)}, '
            f'dh={str(transforms.dh_group.value)}'
        )

    @classmethod
    def _ikev2_derive_sk_key_lengths(cls,
            transforms: _NegotiatedIkev2Transforms,
            is_non_aead: bool,
    ) -> tuple[int, int]:
        """Encryption key length includes the salt (RFC 5282 §4 / RFC 7296 §2.13); integrity is HMAC-key length for
        non-AEAD, 0 for AEAD. Sourced from the decryptor's ``_TRANSFORM_PROPERTIES`` / ``_INTEGRITY_PROPERTIES`` so
        fixed-key algorithms (3DES, ChaCha20) that omit the wire Key Length attribute still get the canonical
        ``write_key_length_bytes``."""
        decryptor_class = (
            Ikev2SkDecryptorNonAeadCryptodome if is_non_aead
            else Ikev2SkDecryptorCryptodome
        )
        encryption_parameters = decryptor_class.get_encryption_transform_derivation_parameters(
            transforms.encryption_descriptor,
        )
        sk_encryption_key_length_bytes = (
            encryption_parameters.write_key_length_bytes + encryption_parameters.salt_length_bytes
        )
        if is_non_aead:
            integrity_parameters = (
                Ikev2SkDecryptorNonAeadCryptodome.get_integrity_transform_derivation_parameters(
                    transforms.integrity_algorithm,
                )
            )
            sk_integrity_key_length_bytes = integrity_parameters.effective_key_length_bytes
        else:
            sk_integrity_key_length_bytes = 0
        return sk_encryption_key_length_bytes, sk_integrity_key_length_bytes

    @classmethod
    def _ikev2_derive_sk_decryptors(cls,   # pylint: disable=too-many-arguments,too-many-positional-arguments
            transforms: _NegotiatedIkev2Transforms,
            shared_secret: bytes,
            nonce_initiator: bytes,
            nonce_responder: bytes,
            spi_initiator: int,
            spi_responder: int,
    ) -> typing.Union[
            tuple[Ikev2SkDecryptorCryptodome, Ikev2SkDecryptorCryptodome],
            tuple[Ikev2SkDecryptorNonAeadCryptodome, Ikev2SkDecryptorNonAeadCryptodome],
    ]:
        """AEAD (AES-GCM, ChaCha20-Poly1305) returns :class:`Ikev2SkDecryptorCryptodome` pair with
        ``integrity_key_length_bytes=0``; non-AEAD (AES-CBC) returns :class:`Ikev2SkDecryptorNonAeadCryptodome` pair
        with ``SK_ai`` / ``SK_ar`` sized to the integrity transform's HMAC output length per RFC 4868 §2.1.1."""
        block_cipher_mode = transforms.encryption_descriptor.block_cipher_mode
        is_non_aead = (
            block_cipher_mode is not None
            and not block_cipher_mode.value.aead
        )
        sk_key_total_length, integrity_key_length_bytes = cls._ikev2_derive_sk_key_lengths(
            transforms, is_non_aead,
        )
        schedule = Ikev2KeyScheduleCryptodome(
            prf=transforms.prf,
            shared_secret=shared_secret,
            nonce_initiator=nonce_initiator,
            nonce_responder=nonce_responder,
            spi_initiator=spi_initiator,
            spi_responder=spi_responder,
            encryption_key_length_bytes=sk_key_total_length,
            integrity_key_length_bytes=integrity_key_length_bytes,
        )
        if is_non_aead:
            outgoing = Ikev2SkDecryptorNonAeadCryptodome(
                encryption_transform=transforms.encryption_descriptor,
                integrity_transform=transforms.integrity_algorithm,
                sk_er=schedule.outputs.sk_ei,
                sk_ar=schedule.outputs.sk_ai,
            )
            incoming = Ikev2SkDecryptorNonAeadCryptodome(
                encryption_transform=transforms.encryption_descriptor,
                integrity_transform=transforms.integrity_algorithm,
                sk_er=schedule.outputs.sk_er,
                sk_ar=schedule.outputs.sk_ar,
            )
            return outgoing, incoming
        outgoing = Ikev2SkDecryptorCryptodome(
            encryption_transform=transforms.encryption_descriptor,
            sk_er=schedule.outputs.sk_ei,
        )
        incoming = Ikev2SkDecryptorCryptodome(
            encryption_transform=transforms.encryption_descriptor,
            sk_er=schedule.outputs.sk_er,
        )
        return outgoing, incoming

    @classmethod
    def _ikev2_narrow_sa_proposal_kwargs(cls,
            sa_kwargs: dict[str, typing.Any],
            algorithm_set: _NegotiatedIkev2Transforms,
    ) -> dict[str, typing.Any]:
        """Narrow ``sa_kwargs`` to ``algorithm_set``'s ``(encr, integ, prf)`` so the responder cannot renegotiate to a
        different suite on the follow-up IKE_SA_INIT. Returns the same dict for chaining."""
        sa_kwargs['encryption_algorithm_tuples'] = [(
            algorithm_set.encryption_algorithm,
            algorithm_set.encryption_key_length_bits,
        )]
        sa_kwargs['pseudorandom_functions'] = [algorithm_set.prf]
        if algorithm_set.integrity_algorithm is not None:
            sa_kwargs['integrity_algorithms'] = [algorithm_set.integrity_algorithm]
        return sa_kwargs

    @classmethod
    def _ikev2_send_ike_sa_init_with_retry(cls,
            l7_client: L7ClientIPsecBase,
            dh_group: Ikev2DiffieHellmanGroup,
            algorithm_set: typing.Optional[_NegotiatedIkev2Transforms] = None,
    ) -> typing.Optional[tuple[
            Ikev2SecurityAssociationSpecialization, IsakmpMessage, typing.Any, bytes,
    ]]:
        """Returns ``None`` if no SA-bearing IKE_SA_INIT response after ``_IKEV2_PROBE_MAX_INIT_ATTEMPTS`` attempts."""
        cookie_bytes: typing.Optional[bytes] = None
        cookie_seen = False
        invalid_ke_seen = False
        # RFC 7296 §2.6 COOKIE retry MUST repeat SPIi + nonce + KE (strongSwan cookies hash them); INVALID_KE_PAYLOAD
        # retry negotiates a new DH group so a fresh ephemeral + nonce are legitimate.
        initiator_spi: typing.Optional[int] = None
        nonce_bytes: typing.Optional[bytes] = None
        ephemeral = None

        for _ in range(_IKEV2_PROBE_MAX_INIT_ATTEMPTS):
            if ephemeral is None:
                ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
                nonce_bytes = secrets.token_bytes(32)
            sa_kwargs: dict[str, typing.Any] = {
                'diffie_hellman_groups': [dh_group],
                'ephemeral_key_exchange': ephemeral,
                # ``hash_algorithm is None`` marks RFC 8420 Identity, required for Ed25519 / Ed448 (arbitrary-size
                # input, no prehash). PyCryptodome supports EdDSA natively, so always advertise it.
                'signature_hash_algorithms': tuple(
                    hash_algorithm
                    for hash_algorithm in Ikev2HashAlgorithm
                    if hash_algorithm.value.hash_algorithm is None
                    or hash_algorithm.value.hash_algorithm in HashCryptodome.get_supported_hashes()
                ),
                'cookie': cookie_bytes,
                'nonce': nonce_bytes,
                'initiator_spi': initiator_spi,
            }
            init_message = Ikev2SecurityAssociationSpecialization(
                **cls._ikev2_narrow_sa_proposal_kwargs(sa_kwargs, algorithm_set),
            )
            initiator_spi = init_message.initiator_spi
            l7_client.l4_transfer.send(init_message.compose())
            response_init, _ = cls._receive_isakmp_message(l7_client.l4_transfer)
            if response_init.exchange_type != Ikev2ExchangeType.IKE_SA_INIT:
                return None
            if not response_init.payloads:
                return None

            first_payload = response_init.payloads[0]
            if isinstance(first_payload, Ikev2NotifyPayloadCookie) and not cookie_seen:
                cookie_seen = True
                cookie_bytes = bytes(first_payload.cookie)
                continue
            if isinstance(first_payload, Ikev2NotifyPayloadInvalidKe) and not invalid_ke_seen:
                invalid_ke_seen = True
                dh_group = first_payload.dh_group
                # Fresh DH group requires a fresh ephemeral + nonce.
                ephemeral = None
                nonce_bytes = None
                continue
            if first_payload.get_payload_type() == Ikev2PayloadType.NOTIFY:
                # Other notify (NO_PROPOSAL_CHOSEN, AUTHENTICATION_FAILED, etc.) or a notify we already retried — bail.
                return None

            return init_message, response_init, ephemeral, nonce_bytes

        return None  # pragma: no cover  (defensive: cookie + invalid_ke each retry-once)

    @classmethod
    def _ikev2_try_eap_probe_inner(cls,   # pylint: disable=too-many-locals
            l7_client: L7ClientIPsecBase,
            dh_group: Ikev2DiffieHellmanGroup,
            algorithm_set: typing.Optional[_NegotiatedIkev2Transforms],
            inner_payloads_extractor: typing.Callable[[list[typing.Any], list[typing.Any]], typing.Any],
    ) -> typing.Optional[typing.Any]:
        """``inner_payloads_extractor(init_payloads, inner_payloads)`` shapes the return."""
        init_outcome = cls._ikev2_send_ike_sa_init_with_retry(
            l7_client, dh_group, algorithm_set,
        )
        if init_outcome is None:
            return None
        init_message, response_init, ephemeral, nonce_initiator = init_outcome

        transforms = _NegotiatedIkev2Transforms.from_message(
            response_init.get_payload_by_type(Ikev2PayloadType.SA),
        )
        LogSingleton().log(
            level=60,
            msg=cls._ikev2_format_negotiated_transforms_for_log(transforms),
        )
        outgoing, incoming = cls._ikev2_derive_sk_decryptors(
            transforms,
            ephemeral.compute_shared_secret(dhe_ephemeral_material_backend.peer_key_exchange_from_wire(
                dh_group,
                bytes(response_init.get_payload_by_type(Ikev2PayloadType.KE).key_exchange_data),
            )),
            nonce_initiator,
            bytes(response_init.get_payload_by_type(Ikev2PayloadType.NONCE).nonce_data),
            init_message.initiator_spi,
            response_init.responder_spi,
        )
        compose_ike_auth_message, decrypt_sk_payload = Ikev2SkDecryptor.select_envelope_funcs(outgoing)

        l7_client.l4_transfer.send(compose_ike_auth_message(
            outgoing,
            cls._ikev2_build_eap_mode_inner_payloads(),
            init_message.initiator_spi,
            response_init.responder_spi,
            message_id=1,
        ))
        response_auth, raw_auth = cls._receive_isakmp_message(l7_client.l4_transfer)
        if response_auth.exchange_type != Ikev2ExchangeType.IKE_AUTH:
            return None

        inner_payloads = decrypt_sk_payload(
            incoming,
            response_auth,
            response_auth.get_payload_by_type(Ikev2PayloadType.SK),
            raw_auth,
        )
        return inner_payloads_extractor(list(response_init.payloads), inner_payloads)

    @classmethod
    def _ikev1_log_probe_grid(cls,
            analyzer_label: str,
            dh_group: Ikev1DiffieHellmanGroup,
            algorithm_set: _NegotiatedIkev1Transforms,
    ) -> None:
        key_length = (
            str(algorithm_set.key_length) if algorithm_set.key_length is not None else 'NONE'
        )
        LogSingleton().log(
            level=40,
            msg=(
                f'IKEv1 {analyzer_label} probe grid; '
                f'encr={str(algorithm_set.encryption_algorithm.value)}, '
                f'key_length={key_length}, '
                f'hash={str(algorithm_set.hash_algorithm.value)}, '
                f'auth={str(algorithm_set.authentication_method.value)}, '
                f'dh={str(dh_group.value)}'
            ),
        )

    @classmethod
    def _ikev2_log_probe_grid(cls,
            analyzer_label: str,
            algorithm_set: _NegotiatedIkev2Transforms,
    ) -> None:
        integ = (
            str(algorithm_set.integrity_algorithm.value)
            if algorithm_set.integrity_algorithm is not None
            else 'NONE'
        )
        LogSingleton().log(
            level=40,
            msg=(
                f'IKEv2 {analyzer_label} probe grid; '
                f'encr={str(algorithm_set.encryption_algorithm.value)}, '
                f'key_length_bits={algorithm_set.encryption_key_length_bits}, '
                f'integ={integ}, '
                f'prf={str(algorithm_set.prf.value)}, '
                f'dh={str(algorithm_set.dh_group.value)}'
            ),
        )

    _ANALYZER_LABEL: typing.ClassVar[str]

    def analyze(self, analyzable, protocol_version: IkeVersion):
        """Dispatch on ``protocol_version`` (RFC 7296 §1.4): IKEv1 runs the Aggressive-Mode probe grid; IKEv2 runs the
        EAP-mode IKE_AUTH probe grid per RFC 7296 §2.16.
        """
        super().analyze(analyzable, protocol_version)
        if protocol_version == IkeVersion.V2:
            return self._analyze_ikev2(analyzable)
        return self._analyze_ikev1(analyzable)

    @classmethod
    def _analyze_ikev1(cls, analyzable: L7ClientIPsecBase) -> AnalyzerResultIKE:
        accepted_dh_groups, algorithm_set = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            analyzable,
            dhe_ephemeral_material_backend.supported_ikev1_dh_groups(),
            stop_on_first_accepted=True,
        )
        if not accepted_dh_groups or algorithm_set is None:
            raise ValueError('IKEv1 DH-group discovery yielded no algorithm set')
        dh_group = algorithm_set.dh_group
        cls._ikev1_log_probe_grid(cls._ANALYZER_LABEL, dh_group, algorithm_set)

        state = cls._ikev1_new_state()
        for auth_method in _IKEV1_PUBKEY_AUTH_METHODS:
            LogSingleton().log(
                level=40,
                msg=(
                    f'IKEv1 {cls._ANALYZER_LABEL} probe; '
                    f'auth_method={str(auth_method.value)}, dh={str(dh_group.value)}'
                ),
            )
            response = cls._ikev1_run_aggressive_probe(analyzable, auth_method, dh_group, algorithm_set)
            if response is not None:
                cls._ikev1_absorb(state, response, auth_method)

        return cls._ikev1_build_result(AnalyzerTargetIke.from_l7_client(analyzable), state)

    @classmethod
    def _analyze_ikev2(cls, analyzable: L7ClientIPsecBase) -> AnalyzerResultIKE:
        accepted_dh_groups, algorithm_set = AnalyzerDHBase.discover_supported_ikev2_dh_groups(
            analyzable, _IKEV2_PROBE_PREFERRED_DH_GROUPS,
            stop_on_first_accepted=True,
        )
        if not accepted_dh_groups or algorithm_set is None:
            raise ValueError('IKEv2 DH-group discovery yielded no algorithm set')
        cls._ikev2_log_probe_grid(cls._ANALYZER_LABEL, algorithm_set)

        state = cls._ikev2_new_state()
        for dh_group in accepted_dh_groups:
            for auth_method in _IKEV2_PUBKEY_AUTH_METHODS:
                LogSingleton().log(
                    level=40,
                    msg=f'IKEv2 {cls._ANALYZER_LABEL} probe; auth_method={str(auth_method.value)}',
                )
                cls._ikev2_absorb(state, analyzable, dh_group, algorithm_set, auth_method)
            if cls._ikev2_dh_group_sufficient(state):
                break

        return cls._ikev2_build_result(AnalyzerTargetIke.from_l7_client(analyzable), state)

    @classmethod
    @abc.abstractmethod
    def _ikev1_new_state(cls) -> typing.Any:
        """Return a fresh accumulator for the IKEv1 auth-method loop."""

    @classmethod
    @abc.abstractmethod
    def _ikev1_absorb(cls, state: typing.Any, response: IsakmpMessage,
                      auth_method: Ikev1AuthenticationMethod) -> None:
        """Fold one IKEv1 Aggressive-Mode response into ``state``."""

    @classmethod
    @abc.abstractmethod
    def _ikev1_build_result(cls, target: AnalyzerTargetIke, state: typing.Any) -> AnalyzerResultIKE:
        """Turn the accumulated IKEv1 state into a concrete result."""

    @classmethod
    @abc.abstractmethod
    def _ikev2_new_state(cls) -> typing.Any:
        """Return a fresh accumulator for the IKEv2 (dh_group, auth_method) loop."""

    @classmethod
    @abc.abstractmethod
    def _ikev2_absorb(cls, state: typing.Any, analyzable: L7ClientIPsecBase,
                      dh_group: Ikev2DiffieHellmanGroup,
                      algorithm_set: _NegotiatedIkev2Transforms,
                      auth_method: Ikev2AuthenticationMethod) -> None:
        """Run one IKEv2 EAP probe iteration and fold its outcome into ``state``."""

    @classmethod
    @abc.abstractmethod
    def _ikev2_dh_group_sufficient(cls, state: typing.Any) -> bool:
        """Return ``True`` when the current DH group yielded enough — outer loop breaks."""

    @classmethod
    @abc.abstractmethod
    def _ikev2_build_result(cls, target: AnalyzerTargetIke, state: typing.Any) -> AnalyzerResultIKE:
        """Turn the accumulated IKEv2 state into a concrete result."""
