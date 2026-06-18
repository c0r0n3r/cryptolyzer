# pylint: disable=too-many-lines
"""IKEv2 key schedule (RFC 7296 §2.13-§2.14) and SK envelope primitives.

Mirrors the protocol-neutral / Cryptodome convenience split used by
:mod:`cryptolyzer.tls.crypto`: a backend-neutral class with injected
:class:`HmacBase`, followed by a ``*Cryptodome`` subclass that hides
the injection by auto-building :class:`HmacCryptodome` from the PRF
identifier.
"""

from __future__ import annotations

import hmac
import os
import typing

import attr

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, MAC, NamedGroup
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1EncryptionAlgorithm,
    Ikev1HashAlgorithm,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IntegrityAlgorithm,
    Ikev2PseudorandomFunction,
)
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import InvalidType
from cryptoparser.common.parse import ComposerBinary, ParserBinary
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeAuthenticationMethod,
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
    Ikev1AttributeKeyLength,
    Ikev1PayloadSecurityAssociation,
)
from cryptoparser.ike.ikev2 import (
    IKEV2_PAYLOAD_CLASSES_BY_TYPE,
    Ikev2PayloadEncryptedAndAuthenticated,
    Ikev2PayloadKeyExchange,
    Ikev2PayloadSecurityAssociation,
    Ikev2PayloadType,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
)
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.version import IsakmpProtocolVersion

from cryptolyzer.common.crypto import (
    AeadRecordDecryptorBase,
    CypherBase,
    CypherBlockCryptodome,
    CypherStreamCryptodome,
    EphemeralKeyExchangeBase,
    EphemeralKeyExchangeEllipticCurveCryptodome,
    EphemeralKeyExchangeFiniteFieldCryptodome,
    GmacCryptodome,
    HmacBase,
    NonAeadRecordDecryptorBase,
)


from cryptolyzer.ike.exception import (
    Ikev2SkAuthenticationError,
    Ikev2TransformDerivationError,
)


@attr.s(frozen=True)
class Ikev2KeyScheduleOutputs:
    """Derived ``SK_*`` octets from one :class:`Ikev2KeySchedule` run.

    Mirrors the way TLS 1.3's :class:`Tls13HandshakeDecryptor` exposes
    ``_write_key`` / ``_initialization_vector`` post-init: the
    :class:`Ikev2KeySchedule` precomputes the full ``prf+`` output and
    slices it into the seven keys at construction time, so each property
    is a flat ``bytes`` lookup.
    """

    # ``repr=False`` on every SK_* attr: these are the derived IKEv2
    # keys the analyzer must NEVER surface in a traceback / log /
    # ipython dump. attrs' default ``repr`` would emit them verbatim.
    sk_d = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)
    sk_ai = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)
    sk_ar = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)
    sk_ei = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)
    sk_er = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)
    sk_pi = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)
    sk_pr = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)


@attr.s
class Ikev2KeySchedule:  # pylint: disable=too-many-instance-attributes
    """RFC 7296 §2.13-§2.14 key schedule.

    ``prf`` octets derive ``SKEYSEED``; ``prf+`` octets expand it into the
    seven ``SK_*`` keys. The encryption and integrity key lengths come
    from the negotiated encryption / integrity transforms and MUST be
    supplied by the caller; the PRF key length is derived from the
    injected :class:`HmacBase` digest size.

    :param prf: Negotiated pseudorandom function (used only for
        symmetry with the TLS pattern; the actual primitive is the
        injected ``hmac_primitive``).
    :param shared_secret: ``g^ir`` octets from the IKE_SA_INIT
        Diffie-Hellman exchange.
    :param nonce_initiator: ``Ni`` octets sent by the initiator.
    :param nonce_responder: ``Nr`` octets received from the responder.
    :param spi_initiator: SPIi octets (8 bytes, big-endian integer).
    :param spi_responder: SPIr octets (8 bytes, big-endian integer).
    :param encryption_key_length_bytes: ``SK_ei`` / ``SK_er`` length
        (e.g. 32 for AES-256-GCM with 4-byte salt → 32 octet key + 4
        octet salt; pass 36 if the caller bakes the salt in).
    :param integrity_key_length_bytes: ``SK_ai`` / ``SK_ar`` length
        (0 for AEAD transforms; non-zero only for non-AEAD integrity).
    :param hmac_primitive: HMAC implementation used for ``prf`` /
        ``prf+`` computations; injected for testability.
    """

    prf: Ikev2PseudorandomFunction = attr.ib(
        validator=attr.validators.instance_of(Ikev2PseudorandomFunction)
    )
    # ``repr=False`` on the DH shared secret and both nonces: these
    # are the SKEYSEED inputs; leaking them via a default attrs repr
    # is functionally equivalent to leaking every derived SK_* key.
    shared_secret = attr.ib(
        validator=attr.validators.instance_of((bytes, bytearray)), repr=False,
    )
    nonce_initiator = attr.ib(
        validator=attr.validators.instance_of((bytes, bytearray)), repr=False,
    )
    nonce_responder = attr.ib(
        validator=attr.validators.instance_of((bytes, bytearray)), repr=False,
    )
    spi_initiator: int = attr.ib(validator=attr.validators.instance_of(int))
    spi_responder: int = attr.ib(validator=attr.validators.instance_of(int))
    encryption_key_length_bytes: int = attr.ib(validator=attr.validators.instance_of(int))
    integrity_key_length_bytes: int = attr.ib(validator=attr.validators.instance_of(int))
    hmac_primitive: HmacBase = attr.ib(validator=attr.validators.instance_of(HmacBase))

    _skeyseed = attr.ib(init=False, repr=False)
    _sk_outputs: Ikev2KeyScheduleOutputs = attr.ib(init=False, repr=False)

    def __attrs_post_init__(self) -> None:
        # SKEYSEED = prf(Ni | Nr, g^ir)  — RFC 7296 §2.14
        self._skeyseed = self.prf_octets(
            bytes(self.nonce_initiator) + bytes(self.nonce_responder),
            bytes(self.shared_secret),
        )

        # {SK_d|SK_ai|SK_ar|SK_ei|SK_er|SK_pi|SK_pr} =
        #     prf+(SKEYSEED, Ni|Nr|SPIi|SPIr)
        prf_key_length_bytes = self.hmac_primitive.mac_algorithm.value.digest_size // 8
        seed = (
            bytes(self.nonce_initiator)
            + bytes(self.nonce_responder)
            + self.spi_initiator.to_bytes(8, 'big')
            + self.spi_responder.to_bytes(8, 'big')
        )
        total_length = (
            prf_key_length_bytes                              # SK_d
            + 2 * self.integrity_key_length_bytes             # SK_ai, SK_ar
            + 2 * self.encryption_key_length_bytes            # SK_ei, SK_er
            + 2 * prf_key_length_bytes                        # SK_pi, SK_pr
        )

        material = self.prf_plus(self._skeyseed, seed, total_length)
        cursor = 0

        def take(length: int) -> bytes:
            nonlocal cursor
            chunk = material[cursor:cursor + length]
            cursor += length
            return chunk

        self._sk_outputs = Ikev2KeyScheduleOutputs(
            sk_d=take(prf_key_length_bytes),
            sk_ai=take(self.integrity_key_length_bytes),
            sk_ar=take(self.integrity_key_length_bytes),
            sk_ei=take(self.encryption_key_length_bytes),
            sk_er=take(self.encryption_key_length_bytes),
            sk_pi=take(prf_key_length_bytes),
            sk_pr=take(prf_key_length_bytes),
        )

    def prf_octets(self, key: bytes, data: bytes) -> bytes:
        """``prf(K, S)`` — single PRF invocation (RFC 7296 §2.13)."""
        return self.hmac_primitive.digest(key, data)

    def prf_plus(self, key: bytes, seed: bytes, length: int) -> bytes:
        """``prf+(K, S)`` — variable-length output per RFC 7296 §2.13.

        ``prf+(K, S) = T1 | T2 | T3 | ...`` where
        ``T1 = prf(K, S | 0x01)`` and
        ``Tn = prf(K, Tn-1 | S | n)``.
        """
        output = b''
        previous = b''
        index = 1
        while len(output) < length:
            composer = ComposerBinary()
            composer.compose_raw(previous)
            composer.compose_raw(seed)
            composer.compose_numeric(index, 1)
            previous = self.prf_octets(key, composer.composed_bytes)
            output += previous
            index += 1
        return output[:length]

    @property
    def skeyseed(self) -> bytes:
        """``SKEYSEED`` octets (RFC 7296 §2.14)."""
        return self._skeyseed

    @property
    def outputs(self) -> Ikev2KeyScheduleOutputs:
        """Derived ``SK_*`` outputs."""
        return self._sk_outputs


@attr.s
class Ikev2KeyScheduleCryptodome(Ikev2KeySchedule):
    """Convenience subclass: auto-builds :class:`HmacCryptodome` from ``prf``.

    Mirrors :class:`Tls13HandshakeDecryptorCryptodome`: hides the
    ``hmac_primitive`` injection so call sites do not need to know the
    PRF → MAC mapping.
    """

    hmac_primitive = attr.ib(init=False, default=None)

    def __attrs_post_init__(self) -> None:
        mac_algorithm = self.prf.value.mac
        self.hmac_primitive = HmacBase.for_algorithm(mac_algorithm)
        super().__attrs_post_init__()


class _EphemeralKeyExchangeBackendCryptodome:
    """Factory + ``dh_group`` selector for IKEv2 phase-1 key exchange.

    Mirrors :class:`_EphemeralKeyExchangeBackendCryptodome` in
    :mod:`cryptolyzer.tls.crypto`: wraps the same
    :class:`EphemeralKeyExchangeEllipticCurveCryptodome` /
    :class:`EphemeralKeyExchangeFiniteFieldCryptodome` primitives but
    translates IKEv2's :class:`Ikev2DiffieHellmanGroup` enum to the
    protocol-neutral :class:`NamedGroup` / :class:`DHParamWellKnown`
    that the common primitives consume.
    """

    _IKEV2_KE_PAYLOAD_PREFERRED_ORDER = (
        Ikev2DiffieHellmanGroup.CURVE25519,
        Ikev2DiffieHellmanGroup.CURVE448,
        Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT,
        Ikev2DiffieHellmanGroup.ECP_GROUP_521_BIT,
        Ikev2DiffieHellmanGroup.ECP_GROUP_224_BIT,
        Ikev2DiffieHellmanGroup.ECP_GROUP_192_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_3072_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_4096_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_6144_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_8192_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_1536_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT,
        Ikev2DiffieHellmanGroup.MODP_GROUP_768_BIT,
        # RFC 5114 §2 MODP subgroups (transform IDs 22/23/24). Parameter
        # set carries the full 1024/2048-bit safe prime plus a smaller
        # prime-order subgroup (160/224/256 bits) so private keys stay
        # short. arbitrary-``pow(g, x, p)`` construction in
        # ``EphemeralKeyExchangeFiniteFieldCryptodome`` handles them
        # uniformly with the RFC 3526 groups.
        Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT_256_BIT_SUBGROUP,
        Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT_224_BIT_SUBGROUP,
        Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT_160_BIT_SUBGROUP,
    )

    # IKEv1 (RFC 2409 + RFC 4753) has no Curve25519 / Curve448; ECP + MODP only.
    _IKEV1_KE_PAYLOAD_PREFERRED_ORDER = (
        Ikev1DiffieHellmanGroup.ECP_256_BIT,
        Ikev1DiffieHellmanGroup.ECP_384_BIT,
        Ikev1DiffieHellmanGroup.ECP_521_BIT,
        Ikev1DiffieHellmanGroup.ECP_224_BIT,
        Ikev1DiffieHellmanGroup.ECP_192_BIT,
        Ikev1DiffieHellmanGroup.MODP_2048_BIT,
        Ikev1DiffieHellmanGroup.MODP_3072_BIT,
        Ikev1DiffieHellmanGroup.MODP_4096_BIT,
        Ikev1DiffieHellmanGroup.MODP_6144_BIT,
        Ikev1DiffieHellmanGroup.MODP_8192_BIT,
        Ikev1DiffieHellmanGroup.MODP_1536_BIT,
        Ikev1DiffieHellmanGroup.MODP_1024_BIT,
        Ikev1DiffieHellmanGroup.MODP_768_BIT,
        # RFC 5114 §2 MODP subgroups — see IKEv2 counterpart above.
        Ikev1DiffieHellmanGroup.MODP_2048_BIT_256_BIT_SUBGROUP,
        Ikev1DiffieHellmanGroup.MODP_2048_BIT_224_BIT_SUBGROUP,
        Ikev1DiffieHellmanGroup.MODP_1024_BIT_160_BIT_SUBGROUP,
    )

    # Filter results are cached in the class dict — filtering a
    # preferred-order tuple materialises one ephemeral per group
    # (~5s across all groups because MODP-8192 key generation is
    # slow), and the sets are static for a given backend + build.
    _supported_ikev2_dh_groups_cache: typing.ClassVar[
        tuple[Ikev2DiffieHellmanGroup, ...] | None
    ] = None
    _supported_ikev1_dh_groups_cache: typing.ClassVar[
        tuple[Ikev1DiffieHellmanGroup, ...] | None
    ] = None

    @classmethod
    def supported_dh_groups(cls) -> tuple[Ikev2DiffieHellmanGroup, ...]:
        """``Ikev2DiffieHellmanGroup`` values this backend can materialise."""
        if cls._supported_ikev2_dh_groups_cache is None:
            cls._supported_ikev2_dh_groups_cache = cls._filter_supported(
                cls._IKEV2_KE_PAYLOAD_PREFERRED_ORDER,
            )
        return cls._supported_ikev2_dh_groups_cache

    @classmethod
    def supported_ikev1_dh_groups(cls) -> tuple[Ikev1DiffieHellmanGroup, ...]:
        """``Ikev1DiffieHellmanGroup`` values this backend can materialise."""
        if cls._supported_ikev1_dh_groups_cache is None:
            cls._supported_ikev1_dh_groups_cache = cls._filter_supported(
                cls._IKEV1_KE_PAYLOAD_PREFERRED_ORDER,
            )
        return cls._supported_ikev1_dh_groups_cache

    @classmethod
    def _filter_supported(cls, preferred_order):
        supported = []
        for dh_group in preferred_order:
            try:
                cls.create_ephemeral_material(dh_group)
            except (NotImplementedError, ValueError):
                continue
            supported.append(dh_group)
        return tuple(supported)

    @classmethod
    def clear_supported_dh_groups_cache(cls) -> None:
        """Reset both the IKEv1 and IKEv2 cached filter results so the
        next ``supported_*_dh_groups()`` call re-runs the ~5-second
        filter.

        Test hook — production code should never call this. Both
        callers live in
        :class:`test.ike.test_crypto.TestEphemeralKeyExchangeBackendCryptodome`:
        one asserts the reset itself
        (``test_clear_supported_dh_groups_cache_resets_both_caches``);
        the other uses it to exercise the ``_filter_supported``
        try/except path with a stubbed ``create_ephemeral_material``
        (``test_supported_dh_groups_skips_groups_whose_factory_raises``).
        """
        cls._supported_ikev2_dh_groups_cache = None
        cls._supported_ikev1_dh_groups_cache = None

    @staticmethod
    def create_ephemeral_material(
        dh_group: Ikev1DiffieHellmanGroup | Ikev2DiffieHellmanGroup,
    ) -> EphemeralKeyExchangeBase:
        """Build a real-DH ephemeral instance for ``dh_group``."""
        key_parameter = dh_group.value.key_parameter
        if isinstance(key_parameter, NamedGroup):
            return EphemeralKeyExchangeEllipticCurveCryptodome(named_group=key_parameter)
        if isinstance(key_parameter, DHParamWellKnown):
            return EphemeralKeyExchangeFiniteFieldCryptodome(dh_parameters=key_parameter)
        raise NotImplementedError(dh_group)

    @classmethod
    def build_ke_payload(
        cls,
        dh_group: Ikev2DiffieHellmanGroup,
    ) -> tuple[Ikev2PayloadKeyExchange, EphemeralKeyExchangeBase]:
        """Build one IKEv2 ``KE`` payload + return the ephemeral instance.

        Real-DH equivalent of TLS 1.3's ``build_tls13_key_shares``: lets
        the caller stash the ephemeral so it can later compute ``g^ir``
        from the responder's ``KE`` reply via ``compute_shared_secret``.
        """
        key_exchange = cls.create_ephemeral_material(dh_group)
        payload = Ikev2PayloadKeyExchange(
            flags=set(),
            dh_group=dh_group,
            key_exchange_data=cls.key_exchange_wire_bytes(dh_group, key_exchange),
        )
        return payload, key_exchange

    @staticmethod
    def key_exchange_wire_bytes(
        dh_group: Ikev1DiffieHellmanGroup | Ikev2DiffieHellmanGroup,
        ephemeral_key_exchange: EphemeralKeyExchangeBase,
    ) -> bytes:
        """Convert an ephemeral's public key to IKE (v1 or v2) KE wire form.

        Weierstrass curves (P-256/P-384/P-521): raw ``x || y`` per RFC 5903
        §7 — strip the leading SEC1 uncompressed marker (``0x04``) that
        ``EphemeralKeyExchangeEllipticCurve.public_key_bytes`` emits.
        Montgomery curves and Finite-field groups: already in wire format.
        """
        public_key_bytes = ephemeral_key_exchange.public_key_bytes
        key_parameter = dh_group.value.key_parameter
        if isinstance(key_parameter, NamedGroup) and key_parameter not in (
            NamedGroup.CURVE25519, NamedGroup.CURVE448,
        ):
            return public_key_bytes[1:]

        return public_key_bytes

    @staticmethod
    def peer_key_exchange_from_wire(
        dh_group: Ikev1DiffieHellmanGroup | Ikev2DiffieHellmanGroup,
        key_exchange_data: bytes,
    ) -> bytes:
        """Inverse of :meth:`key_exchange_wire_bytes`.

        Prepends the SEC1 uncompressed marker (``0x04``) so PyCryptodome's
        ``ECC.import_key`` accepts the peer's public value for
        Weierstrass curves.
        """
        key_parameter = dh_group.value.key_parameter
        if isinstance(key_parameter, NamedGroup) and key_parameter not in (
            NamedGroup.CURVE25519, NamedGroup.CURVE448,
        ):
            return b'\x04' + bytes(key_exchange_data)
        return bytes(key_exchange_data)


#: Module-level singleton. Name mirrors
#: :data:`cryptolyzer.tls.crypto.dhe_ephemeral_material_backend` so a
#: ``cryptolyzer.<protocol>.crypto.dhe_ephemeral_material_backend``
#: lookup pattern works across both protocols.
dhe_ephemeral_material_backend = _EphemeralKeyExchangeBackendCryptodome()

# Warm the DH-group filter caches at module import so the first
# analyzer probe does not stall on ~5s of MODP-8192 key generation
# — long enough to overshoot the 1s test-server socket timeout in
# ``test.ike.test_pubkeys.TestAnalyzerPublicKeys``.
dhe_ephemeral_material_backend.supported_dh_groups()
dhe_ephemeral_material_backend.supported_ikev1_dh_groups()


#: RFC 4543 §3.1: per-packet IV in AES-GMAC IKEv2 integrity is 8 octets.
#: Used to reject GMAC-integrity pairings with encryption transforms
#: whose on-wire IV isn't 8 octets (e.g. AES-CBC's 16-octet block).
_GMAC_WIRE_IV_LENGTH_BYTES: int = 8


@attr.s(frozen=True)
class AeadBulkCipherDescriptor:
    """``(bulk_cipher, block_cipher_mode)`` identity for IKEv2 SK transform lookup.

    Name + shape mirror :class:`cryptolyzer.tls.crypto.AeadBulkCipherDescriptor`
    so the same descriptor pattern works for both protocols. The two
    classes are intentionally distinct objects (one per ``crypto`` module)
    until either grows protocol-specific fields; promote to
    :mod:`cryptolyzer.common.crypto` if a third protocol needs the same
    shape.
    """

    bulk_cipher = attr.ib(validator=attr.validators.instance_of(BlockCipher))
    block_cipher_mode = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode))
    )

    # RFC 5282 / RFC 7296 transform ID → descriptor. Populated after
    # class body so entries can instantiate the class itself.
    _ENCR_MAP: typing.ClassVar[dict[
        tuple[Ikev2EncryptionAlgorithm, int | None],
        AeadBulkCipherDescriptor,
    ]] = {}

    @classmethod
    def from_encryption_algorithm(
            cls,
            encryption_transform: Ikev2EncryptionAlgorithm,
            key_length_bits: int | None,
    ) -> AeadBulkCipherDescriptor:
        """Translate ``(Ikev2EncryptionAlgorithm, key_length)`` to the
        :class:`AeadBulkCipherDescriptor` that the SK encrypt / decrypt
        classes index on.

        The cryptodatahub IKEv2 encryption-algorithm enum groups multiple
        AES key sizes under one ``Ikev2EncryptionAlgorithm`` value, so the
        transform's Key Length attribute is what narrows the descriptor
        down to a single ``(bulk_cipher, block_cipher_mode)`` pair.
        Fixed-key algorithms (RFC 7296 §3.3.5: ENCR_3DES,
        ENCR_CHACHA20_POLY1305, …) omit the Key Length attribute and are
        keyed with ``None``.
        """
        descriptor = cls._ENCR_MAP.get((encryption_transform, key_length_bits))
        if descriptor is None:
            raise Ikev2TransformDerivationError(
                f'No AeadBulkCipherDescriptor mapping for '
                f'encryption_transform={encryption_transform.name} key_length_bits={key_length_bits}'
            )
        return descriptor


@attr.s(frozen=True)
class Ikev2EncryptionTransformDerivationParameters:
    """Per-transform AEAD sizing for one IKEv2 SK envelope (RFC 5282 §3-§5).

    Mirrors :class:`Tls13CipherSuiteDerivationParameters`. Lookup table
    is keyed on :class:`AeadBulkCipherDescriptor`, so callers translate
    their negotiated ``Ikev2EncryptionAlgorithm`` + Key Length attribute
    to a ``(bulk_cipher, block_cipher_mode)`` pair before the lookup
    (the cryptodatahub IKEv2 encryption-algorithm enum groups multiple
    key sizes under one ``Ikev2EncryptionAlgorithm`` value, so the
    descriptor narrows down to one concrete variant).
    """

    write_key_length_bytes = attr.ib(validator=attr.validators.instance_of(int))
    on_wire_initialization_vector_length_bytes = attr.ib(
        validator=attr.validators.instance_of(int)
    )
    salt_length_bytes = attr.ib(validator=attr.validators.instance_of(int))
    authentication_tag_length_bytes = attr.ib(validator=attr.validators.instance_of(int))


@attr.s
class Ikev2SkDecryptor(AeadRecordDecryptorBase):
    """RFC 7296 §3.14 / RFC 5282 §3-§5 SK envelope decryptor (AEAD branch).

    Mirrors the shape of :class:`Tls13HandshakeDecryptor`:

    * Inputs (declared attrs): cipher descriptor, ``SK_er`` octets, and an
      injected ``cipher_factory`` callable that maps ``nonce -> CypherBase``.
    * Materialised state (``init=False`` attrs): nonce length, tag length,
      and the AEAD salt (the last ``salt_length_bytes`` octets of ``SK_er``
      per RFC 5282 §4).

    Subclasses :class:`AeadRecordDecryptorBase` — NOT
    :class:`HandshakeDecryptorBase`, which ships TLS-only HKDF labels +
    IV⊕seqnum nonce machinery the IKEv2 path does not use.
    """

    _TRANSFORM_PROPERTIES: typing.ClassVar[
        dict[AeadBulkCipherDescriptor, Ikev2EncryptionTransformDerivationParameters]
    ] = {
        # AES_GCM_16 — RFC 5282 §7.2: transform IDs 18 (128), 19 (192), 20 (256).
        # 8-octet on-wire IV, 4-octet salt (from SK_er tail), 16-octet tag.
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.GCM,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=16, on_wire_initialization_vector_length_bytes=8,
            salt_length_bytes=4, authentication_tag_length_bytes=16,
        ),
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_192, block_cipher_mode=BlockCipherMode.GCM,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=24, on_wire_initialization_vector_length_bytes=8,
            salt_length_bytes=4, authentication_tag_length_bytes=16,
        ),
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=32, on_wire_initialization_vector_length_bytes=8,
            salt_length_bytes=4, authentication_tag_length_bytes=16,
        ),
        # AES-GCM shorter-tag variants — RFC 5282 §7.2: transform IDs
        # 18 (GCM-8, tag 8), 19 (GCM-12, tag 12) at 128/192/256-bit keys.
        # Same 8-octet on-wire IV + 4-octet salt as GCM-16; only the tag
        # length differs. GCM-16 entries are already declared above.
        **{
            AeadBulkCipherDescriptor(
                bulk_cipher=bulk_cipher, block_cipher_mode=gcm_mode,
            ): Ikev2EncryptionTransformDerivationParameters(
                write_key_length_bytes=write_key_length_bytes,
                on_wire_initialization_vector_length_bytes=8,
                salt_length_bytes=4,
                authentication_tag_length_bytes=tag_length_bytes,
            )
            for bulk_cipher, write_key_length_bytes in (
                (BlockCipher.AES_128, 16),
                (BlockCipher.AES_192, 24),
                (BlockCipher.AES_256, 32),
            )
            for gcm_mode, tag_length_bytes in (
                (BlockCipherMode.GCM_8, 8),
                (BlockCipherMode.GCM_12, 12),
            )
        },
        # AES-CCM — RFC 4309 §4: transform IDs 14 (CCM-8), 15 (CCM-12),
        # 16 (CCM-16) at 128/192/256-bit keys. 8-octet on-wire IV,
        # 3-octet salt (from SK_er tail). Tag length differs per variant.
        **{
            AeadBulkCipherDescriptor(
                bulk_cipher=bulk_cipher, block_cipher_mode=ccm_mode,
            ): Ikev2EncryptionTransformDerivationParameters(
                write_key_length_bytes=write_key_length_bytes,
                on_wire_initialization_vector_length_bytes=8,
                salt_length_bytes=3,
                authentication_tag_length_bytes=tag_length_bytes,
            )
            for bulk_cipher, write_key_length_bytes in (
                (BlockCipher.AES_128, 16),
                (BlockCipher.AES_192, 24),
                (BlockCipher.AES_256, 32),
            )
            for ccm_mode, tag_length_bytes in (
                (BlockCipherMode.CCM_8, 8),
                (BlockCipherMode.CCM_12, 12),
                (BlockCipherMode.CCM_16, 16),
            )
        },
        # ChaCha20-Poly1305 — RFC 7634: 32-octet key, 8-octet on-wire IV,
        # 4-octet salt, 16-octet tag. No block cipher mode (stream).
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.CHACHA20, block_cipher_mode=None,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=32, on_wire_initialization_vector_length_bytes=8,
            salt_length_bytes=4, authentication_tag_length_bytes=16,
        ),
    }

    encryption_transform = attr.ib(validator=attr.validators.instance_of(AeadBulkCipherDescriptor))
    # ``sk_er`` = write-key || salt for AEAD; hide from repr so it
    # never lands in a traceback or LogSingleton output.
    sk_er = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)), repr=False)
    cipher_factory = attr.ib(validator=attr.validators.is_callable())

    _authentication_tag_length_bytes = attr.ib(init=False, repr=False)
    _record_initialization_vector_length_bytes = attr.ib(init=False, repr=False)
    _salt = attr.ib(init=False, repr=False)

    @classmethod
    def get_encryption_transform_derivation_parameters(
        cls, encryption_transform: AeadBulkCipherDescriptor,
    ) -> Ikev2EncryptionTransformDerivationParameters:
        """Mirror of :meth:`Tls13HandshakeDecryptor.get_cipher_suite_derivation_parameters`."""
        parameters = cls._TRANSFORM_PROPERTIES.get(encryption_transform)
        if parameters is None:
            raise ValueError(f'{encryption_transform} is not supported by {cls.__name__}')
        return parameters

    def __attrs_post_init__(self) -> None:
        parameters = self.get_encryption_transform_derivation_parameters(self.encryption_transform)
        sk_er_bytes = bytes(self.sk_er)
        if len(sk_er_bytes) != parameters.write_key_length_bytes + parameters.salt_length_bytes:
            raise ValueError(
                f'sk_er length {len(sk_er_bytes)} does not match '
                f'expected {parameters.write_key_length_bytes + parameters.salt_length_bytes} '
                f'(write key {parameters.write_key_length_bytes} + salt {parameters.salt_length_bytes})'
            )
        # ``sk_er_bytes[-0:]`` returns ``sk_er_bytes[0:]`` (the full
        # slice) so a future zero-salt AEAD entry would silently make
        # ``_salt`` hold the entire write key. Guard explicitly.
        self._salt = (
            sk_er_bytes[-parameters.salt_length_bytes:]
            if parameters.salt_length_bytes else b''
        )
        self._record_initialization_vector_length_bytes = (
            parameters.salt_length_bytes + parameters.on_wire_initialization_vector_length_bytes
        )
        self._authentication_tag_length_bytes = parameters.authentication_tag_length_bytes

    @property
    def authentication_tag_length_bytes(self) -> int:
        """AEAD tag length in octets for this transform."""
        return self._authentication_tag_length_bytes

    @property
    def record_initialization_vector_length_bytes(self) -> int:
        """Nonce length (salt + on-wire IV) for this transform."""
        return self._record_initialization_vector_length_bytes

    @property
    def on_wire_initialization_vector_length_bytes(self) -> int:
        """On-wire IV length (octets the SK envelope body is prefixed with)."""
        return self._record_initialization_vector_length_bytes - len(self._salt)

    def decrypt(self, ciphertext: bytes | bytearray, additional_data: bytes | bytearray) -> bytes:
        """Decrypt one SK envelope body.

        :param ciphertext: ``on-wire IV | encrypted payloads | AEAD tag``
            from the SK payload's variable-length region.
        :param additional_data: pre-computed AAD per RFC 5282 §5.1 —
            ``IKEHeader | unencrypted payloads | first 4 octets of SK
            header``. Build with :meth:`compute_additional_data`.
        :return: decrypted inner payload bytes (still wrapped in
            ``encrypted payloads | Padding | Pad Length``; strip with
            :meth:`split_padded_plaintext`).
        """
        ciphertext_bytes = bytes(ciphertext)
        additional_data_bytes = bytes(additional_data)
        on_wire_iv_length = (
            self._record_initialization_vector_length_bytes - len(self._salt)
        )
        minimum_body_length = on_wire_iv_length + self._authentication_tag_length_bytes
        if len(ciphertext_bytes) < minimum_body_length:
            raise ValueError(
                f'SK body length {len(ciphertext_bytes)} shorter than '
                f'{minimum_body_length} (on-wire IV {on_wire_iv_length} + '
                f'AEAD tag {self._authentication_tag_length_bytes})'
            )
        on_wire_iv = ciphertext_bytes[:on_wire_iv_length]
        ciphertext_with_tag = ciphertext_bytes[on_wire_iv_length:]
        ciphertext_without_tag = ciphertext_with_tag[:-self._authentication_tag_length_bytes]
        authentication_tag = ciphertext_with_tag[-self._authentication_tag_length_bytes:]

        nonce = self._salt + on_wire_iv
        cipher = self.cipher_factory(nonce)
        return cipher.decrypt_and_verify(
            ciphertext_without_tag, authentication_tag, additional_data_bytes,
        )

    def encrypt(
        self,
        inner_plaintext_padded: bytes | bytearray,
        additional_data: bytes | bytearray,
        on_wire_iv: bytes | None = None,
    ) -> bytes:
        """Encrypt one SK envelope body (inverse of :meth:`decrypt`).

        :param inner_plaintext_padded: ``encrypted payloads | Padding |
            Pad Length`` ready to feed into AEAD.
        :param additional_data: same AAD shape as :meth:`decrypt` —
            ``IKEHeader | unencrypted payloads | first 4 octets of SK
            header``.
        :param on_wire_iv: explicit IV octets. ``None`` generates a
            cryptographically random IV of the negotiated transform's
            length (RFC 5282 §3.1: must be unique per key).
        :return: ``on-wire IV | ciphertext | AEAD tag`` ready to drop
            into the SK payload body.
        """
        on_wire_iv_length = (
            self._record_initialization_vector_length_bytes - len(self._salt)
        )
        if on_wire_iv is None:
            on_wire_iv = os.urandom(on_wire_iv_length)
        if len(on_wire_iv) != on_wire_iv_length:
            raise ValueError(
                f'on_wire_iv length {len(on_wire_iv)} does not match '
                f'expected {on_wire_iv_length}'
            )

        nonce = self._salt + bytes(on_wire_iv)
        cipher = self.cipher_factory(nonce)
        ciphertext, tag = cipher.encrypt_and_digest(
            bytes(inner_plaintext_padded), bytes(additional_data),
        )
        return bytes(on_wire_iv) + ciphertext + tag

    @staticmethod
    def split_padded_plaintext(inner_plaintext: bytes | bytearray) -> bytes:
        """Strip the RFC 7296 §3.14 trailing ``Padding | Pad Length``.

        Parallel to :meth:`Tls13HandshakeDecryptor.split_inner_plaintext`,
        but the IKEv2 trailer is length-prefixed (last octet = pad length)
        rather than zero-padded.
        """
        data = bytes(inner_plaintext)
        if not data:
            raise ValueError('inner plaintext is empty')
        pad_length = data[-1]
        if pad_length + 1 > len(data):
            raise ValueError('pad length exceeds inner plaintext')
        return data[:len(data) - 1 - pad_length]

    @staticmethod
    def compute_additional_data(
        ike_header_bytes: bytes | bytearray,
        unencrypted_payloads_bytes: bytes | bytearray,
        sk_payload_header_bytes: bytes | bytearray,
    ) -> bytes:
        """Build the RFC 5282 §5.1 AAD.

        ``AAD = IKEHeader | unencrypted payloads | first 4 octets of SK header``.
        Parallel to :meth:`Tls13HandshakeDecryptor.compute_additional_data`.
        """
        if len(sk_payload_header_bytes) < 4:
            raise ValueError('SK payload header must be at least 4 octets')
        return (
            bytes(ike_header_bytes)
            + bytes(unencrypted_payloads_bytes)
            + bytes(sk_payload_header_bytes)[:4]
        )

    @staticmethod
    def compose_sk_envelope_headers(
            inner_payloads: list[typing.Any],
            sk_body_length: int,
            initiator_spi: int,
            responder_spi: int,
            message_id: int,
    ) -> tuple[bytes, bytes]:
        """Build the IKE header + SK payload header for one IKE_AUTH message.

        Shared between the AEAD and non-AEAD compose helpers; returns
        ``(ike_header_bytes, sk_header_bytes)``.
        """
        sk_payload_length = Ikev2PayloadEncryptedAndAuthenticated.HEADER_SIZE + sk_body_length
        ike_header_bytes = IsakmpMessage.compose_header(
            initiator_spi, responder_spi, IsakmpProtocolVersion(IkeVersion.V2, 0),
            Ikev2PayloadType.SK, Ikev2ExchangeType.IKE_AUTH,
            {IsakmpFlags.INITIATOR}, message_id,
            IsakmpMessage.HEADER_SIZE + sk_payload_length,
        )
        sk_payload = Ikev2PayloadEncryptedAndAuthenticated(flags=set(), encrypted_data=b'')
        sk_payload.next_payload = inner_payloads[0].get_payload_type()
        sk_header_bytes = sk_payload.compose_header(sk_body_length).composed_bytes
        return ike_header_bytes, sk_header_bytes

    @staticmethod
    def compose_inner_payload_chain(payloads_list: list[typing.Any]) -> bytes:
        """Compose an IKEv2 SK-inner payload chain to bytes.

        Mirrors the chaining logic in
        :class:`cryptoparser.ike.isakmp.IsakmpMessage.compose` (lines
        221-227): walks the list and sets each payload's ``next_payload``
        to the next entry's payload type (or ``NONE`` for the tail)
        before composing.
        """
        composer = ComposerBinary()
        for i, payload in enumerate(payloads_list):
            payload.next_payload = (
                Ikev2PayloadType.NONE if i == len(payloads_list) - 1
                else payloads_list[i + 1].get_payload_type()
            )
            composer.compose_parsable(payload)
        return composer.composed_bytes

    @staticmethod
    def parse_inner_payload_chain(
            payload_bytes: bytes,
            first_payload_type: Ikev2PayloadType,
    ) -> list[typing.Any]:
        """Parse an IKEv2 SK-inner payload chain back into a list.

        Inverse of :meth:`compose_inner_payload_chain`.
        """
        payloads: list[typing.Any] = []
        parser = ParserBinary(payload_bytes)
        next_payload = first_payload_type
        while parser.unparsed_length > 0 and next_payload != Ikev2PayloadType.NONE:
            if next_payload not in IKEV2_PAYLOAD_CLASSES_BY_TYPE:
                raise InvalidType(next_payload)
            payload_class = IKEV2_PAYLOAD_CLASSES_BY_TYPE[next_payload]
            parser.parse_parsable('payload', payload_class)
            payload = parser['payload']
            payloads.append(payload)
            next_payload = payload.next_payload
        return payloads

    @staticmethod
    def pad_inner_plaintext(inner_bytes: bytes, block_size: int) -> bytes:
        """Pad ``inner_bytes`` for SK encryption per RFC 7296 §3.14.

        ``Padding | Pad Length`` aligns to the encryption block boundary.
        For AEAD modes ``block_size`` is 1 (no alignment needed). For
        non-AEAD CBC the caller passes the AES block size (16). Per RFC
        7296 §3.14 padding octets ``MAY have any value``; fill with
        cryptographic-random bytes so the on-wire envelope is not
        trivially fingerprintable as scanner traffic.
        """
        if block_size < 1:
            raise ValueError(f'block_size must be >= 1, got {block_size}')
        pad_length = (-len(inner_bytes) - 1) % block_size
        return inner_bytes + os.urandom(pad_length) + bytes([pad_length])

    @staticmethod
    def compose_ike_auth_message(
            decryptor: typing.Any,
            inner_payloads: list[typing.Any],
            initiator_spi: int,
            responder_spi: int,
            message_id: int = 1,
    ) -> bytes:
        """Compose an outgoing IKE_AUTH outer message with the inner payload
        chain AEAD-wrapped in an SK envelope.

        Caller-supplied ``decryptor`` is an :class:`Ikev2SkDecryptorCryptodome`
        keyed with ``SK_ei`` for the outgoing direction (initiator-to-responder).
        """
        plaintext_padded = Ikev2SkDecryptor.pad_inner_plaintext(
            Ikev2SkDecryptor.compose_inner_payload_chain(inner_payloads),
            block_size=_AEAD_BLOCK_SIZE,
        )
        sk_body_length = (
            decryptor.on_wire_initialization_vector_length_bytes
            + len(plaintext_padded)
            + decryptor.authentication_tag_length_bytes
        )
        ike_header_bytes, sk_header_bytes = Ikev2SkDecryptor.compose_sk_envelope_headers(
            inner_payloads, sk_body_length, initiator_spi, responder_spi, message_id,
        )
        sk_envelope_body = decryptor.encrypt(
            plaintext_padded, ike_header_bytes + sk_header_bytes[:4],
        )
        return ike_header_bytes + sk_header_bytes + sk_envelope_body

    @staticmethod
    def decrypt_sk_payload(
            decryptor: typing.Any,
            response_message: IsakmpMessage,
            sk_payload: Ikev2PayloadEncryptedAndAuthenticated,
            raw_response_bytes: bytes,
    ) -> list[typing.Any]:
        """Inverse of :meth:`compose_ike_auth_message`.

        RFC 5282 §5.1: ``AAD = IKEHeader | unencrypted payloads before SK |
        first 4 octets of SK header``. Walks ``response_message.payloads``
        up to the SK payload to locate the SK offset.
        """
        sk_header_offset = IsakmpMessage.HEADER_SIZE
        for payload in response_message.payloads:
            if payload is sk_payload:
                break
            sk_header_offset += len(payload.compose())
        additional_data = (
            bytes(raw_response_bytes[:sk_header_offset])
            + bytes(raw_response_bytes[sk_header_offset:sk_header_offset + 4])
        )
        try:
            inner_plaintext_padded = decryptor.decrypt(
                bytes(sk_payload.encrypted_data), additional_data,
            )
        except ValueError as exc:
            raise Ikev2SkAuthenticationError(str(exc)) from exc
        inner_bytes = decryptor.split_padded_plaintext(inner_plaintext_padded)
        return Ikev2SkDecryptor.parse_inner_payload_chain(inner_bytes, sk_payload.next_payload)

    @staticmethod
    def select_envelope_funcs(
            decryptor: typing.Any,
    ) -> tuple[typing.Callable[..., bytes], typing.Callable[..., list[typing.Any]]]:
        """Pick the matching compose / decrypt helpers for ``decryptor``.

        :class:`Ikev2SkDecryptorNonAead` (or subclass) →
        ``(Ikev2SkDecryptorNonAead.compose_ike_auth_message,
        Ikev2SkDecryptorNonAead.decrypt_sk_payload)``; AEAD decryptor →
        AEAD variants.
        """
        if isinstance(decryptor, Ikev2SkDecryptorNonAead):
            return (
                Ikev2SkDecryptorNonAead.compose_ike_auth_message,
                Ikev2SkDecryptorNonAead.decrypt_sk_payload,
            )
        return (
            Ikev2SkDecryptor.compose_ike_auth_message,
            Ikev2SkDecryptor.decrypt_sk_payload,
        )


@attr.s
class Ikev2SkDecryptorCryptodome(Ikev2SkDecryptor):
    """Convenience subclass: auto-builds ``cipher_factory`` from the
    ``encryption_transform`` descriptor.

    Mirrors :class:`Tls13HandshakeDecryptorCryptodome`'s ChaCha-vs-AES
    branching in
    :meth:`cryptolyzer.tls.crypto.Tls13HandshakeDecryptorCryptodome.__attrs_post_init__`.
    """

    _PRF_TO_MAC: typing.ClassVar[dict[Ikev2PseudorandomFunction, MAC]] = {
        # RFC 4306 §5 — HMAC-based PRFs (transform IDs 1, 2, 5, 6, 7).
        # HMAC-MD5 is legacy but still accepted by some responders.
        Ikev2PseudorandomFunction.PRF_HMAC_MD5: MAC.MD5,
        Ikev2PseudorandomFunction.PRF_HMAC_SHA1: MAC.SHA1,
        Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256: MAC.SHA2_256,
        Ikev2PseudorandomFunction.PRF_HMAC_SHA2_384: MAC.SHA2_384,
        Ikev2PseudorandomFunction.PRF_HMAC_SHA2_512: MAC.SHA2_512,
        # RFC 4615 — AES-CMAC-PRF-128 (transform ID 8). 16-byte AES-128
        # key, 16-byte output. CMAC construction; ``build_mac_primitive``
        # returns :class:`CmacCryptodome`.
        Ikev2PseudorandomFunction.PRF_AES128_CMAC: MAC.AES_CMAC_PRF_128,
    }

    cipher_factory = attr.ib(init=False, default=None)

    def __attrs_post_init__(self) -> None:
        parameters = self.get_encryption_transform_derivation_parameters(self.encryption_transform)
        write_key = bytes(self.sk_er)[:parameters.write_key_length_bytes]
        bulk_cipher = self.encryption_transform.bulk_cipher
        block_cipher_mode = self.encryption_transform.block_cipher_mode

        if bulk_cipher == BlockCipher.CHACHA20:
            def cipher_factory(nonce: bytes) -> CypherBase:
                return CypherStreamCryptodome(
                    bulk_cipher=BlockCipher.CHACHA20, key=write_key, nonce=nonce,
                )
        else:
            # RFC 5282 §7.2 / RFC 4309 §4: GCM-8/12 and CCM-8/12/16 pin
            # the AEAD tag length per transform, so pass it through to
            # PyCryptodome via ``mac_len=``. GCM-16 uses the default
            # (mac_len=16) so passing 16 explicitly matches the wire
            # tag length recorded in the transform table.
            mac_len = parameters.authentication_tag_length_bytes

            def cipher_factory(nonce: bytes) -> CypherBase:
                return CypherBlockCryptodome(
                    bulk_cipher=bulk_cipher, key=write_key, nonce=nonce,
                    block_cipher_mode=block_cipher_mode, mac_len=mac_len,
                )

        self.cipher_factory = cipher_factory
        super().__attrs_post_init__()


@attr.s(frozen=True)
class Ikev2IntegrityTransformDerivationParameters:
    """Per-integrity-algorithm MAC + ICV truncation sizing for non-AEAD SK
    envelopes (RFC 7296 §3.14 + RFC 4868 + RFC 4543).

    Three MAC families are represented:

    - **HMAC** (RFC 4868): ``mac_algorithm`` = MD5 / SHA1 / SHA2-*. Key
      length defaults to the hash digest size.
    - **AES-CMAC** (RFC 4494): ``mac_algorithm`` =
      :attr:`MAC.AES_CMAC_96`. Key length overridden to 16 (AES-128).
    - **AES-GMAC** (RFC 4543): ``bulk_cipher`` set to AES-128/192/256,
      ``mac_algorithm`` = ``None``. ``key_length_bytes`` is the AES key
      length (16 / 24 / 32) and ``salt_length_bytes`` = 4 for the
      trailing GCM-nonce salt taken from the ``SK_ai`` / ``SK_ar``
      tail (RFC 4543 §5.1).

    :param mac_algorithm: MAC enum member for HMAC / CMAC integrity;
        ``None`` for GMAC (which is keyed by ``bulk_cipher`` instead).
    :param integrity_check_value_length_bytes: ICV octets appended to
        the ciphertext.
    :param key_length_bytes: SK_ai / SK_ar key octets. ``None`` means
        "same as MAC digest size" (HMAC convention). AES-CMAC / AES-GMAC
        set this explicitly to the underlying AES key length.
    :param salt_length_bytes: additional trailing octets appended to the
        MAC key material. Non-zero only for GMAC, where 4 octets of the
        SK_a* tail are consumed as the GCM-nonce salt.
    :param bulk_cipher: AES key size for GMAC integrity; ``None`` for
        HMAC / CMAC integrity.
    """

    mac_algorithm = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(MAC)),
    )
    integrity_check_value_length_bytes = attr.ib(validator=attr.validators.instance_of(int))
    key_length_bytes = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )
    salt_length_bytes = attr.ib(
        default=0,
        validator=attr.validators.instance_of(int),
    )
    bulk_cipher = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipher)),
    )

    @property
    def effective_key_length_bytes(self) -> int:
        """Resolved SK_ai / SK_ar length in bytes, including any GMAC salt tail.

        HMAC convention (``key_length_bytes=None``): use MAC digest size.
        Explicit override: sum of ``key_length_bytes`` + ``salt_length_bytes``
        — for GMAC, the SK_a* material carries AES key AND the 4-octet salt.
        """
        if self.key_length_bytes is not None:
            return self.key_length_bytes + self.salt_length_bytes
        return self.mac_algorithm.value.digest_size // 8

    @property
    def is_gmac(self) -> bool:
        """True when this integrity transform is AES-GMAC (RFC 4543)."""
        return self.bulk_cipher is not None


@attr.s
class Ikev2SkDecryptorNonAead(NonAeadRecordDecryptorBase):  # pylint: disable=too-many-instance-attributes
    """RFC 7296 §3.14 non-AEAD SK envelope decryptor (CBC + HMAC).

    Sibling to :class:`Ikev2SkDecryptor`: same descriptor / parameters
    pattern, but the inner record carries ``IV | ciphertext | Padding |
    Pad Length`` and the AEAD tag is replaced by a trailing HMAC ICV
    derived from ``SK_ar``. Subclasses :class:`NonAeadRecordDecryptorBase`
    so callers can switch between AEAD / non-AEAD by base-class
    instance check.
    """

    _TRANSFORM_PROPERTIES: typing.ClassVar[
        dict[AeadBulkCipherDescriptor, Ikev2EncryptionTransformDerivationParameters]
    ] = {
        # RFC 7296 §3.14: AES-CBC + HMAC for IKEv2 SK. Transform IDs 12/13
        # (AES_CBC_128 / 256). Salt is 0 octets for CBC; IV is the full
        # AES block length (16 octets) sent on the wire.
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=16, on_wire_initialization_vector_length_bytes=16,
            salt_length_bytes=0, authentication_tag_length_bytes=0,
        ),
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_192, block_cipher_mode=BlockCipherMode.CBC,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=24, on_wire_initialization_vector_length_bytes=16,
            salt_length_bytes=0, authentication_tag_length_bytes=0,
        ),
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.CBC,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=32, on_wire_initialization_vector_length_bytes=16,
            salt_length_bytes=0, authentication_tag_length_bytes=0,
        ),
        # RFC 7296 §3.3.5 ENCR_3DES (transform ID 3) — Triple DES CBC.
        # Fixed 24-octet (168-bit) key, 8-octet block size (= 8-octet
        # on-wire IV), no salt, no tag.
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.TRIPLE_DES_168, block_cipher_mode=BlockCipherMode.CBC,
        ): Ikev2EncryptionTransformDerivationParameters(
            write_key_length_bytes=24, on_wire_initialization_vector_length_bytes=8,
            salt_length_bytes=0, authentication_tag_length_bytes=0,
        ),
        # RFC 5930 — AES-CTR for IKEv2 SK. Transform ID 13 at 128/192/
        # 256-bit keys. 8-octet on-wire IV, 4-octet salt (from SK_er
        # tail); the block counter is the trailing 4 octets of the
        # 16-octet counter block and starts at 1.
        **{
            AeadBulkCipherDescriptor(
                bulk_cipher=bulk_cipher, block_cipher_mode=BlockCipherMode.CTR,
            ): Ikev2EncryptionTransformDerivationParameters(
                write_key_length_bytes=write_key_length_bytes,
                on_wire_initialization_vector_length_bytes=8,
                salt_length_bytes=4,
                authentication_tag_length_bytes=0,
            )
            for bulk_cipher, write_key_length_bytes in (
                (BlockCipher.AES_128, 16),
                (BlockCipher.AES_192, 24),
                (BlockCipher.AES_256, 32),
            )
        },
    }

    _INTEGRITY_PROPERTIES: typing.ClassVar[
        dict[Ikev2IntegrityAlgorithm, Ikev2IntegrityTransformDerivationParameters]
    ] = {
        # RFC 2403 — HMAC-MD5-96. Transform ID 1. 16-byte SK_ai key, 12-byte ICV.
        Ikev2IntegrityAlgorithm.AUTH_HMAC_MD5_96: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.MD5, integrity_check_value_length_bytes=12,
        ),
        # RFC 2404 — HMAC-SHA1-96. Transform ID 2. 20-byte SK_ai key, 12-byte ICV.
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA1, integrity_check_value_length_bytes=12,
        ),
        # HMAC-MD5-128 (Transform ID 6) and HMAC-SHA1-160 (Transform ID 7)
        # — full-length ICV variants of the RFC 2403 / 2404 pair. Present in
        # the IANA registry for symmetry with the AH suites; some legacy
        # responders still advertise them.
        Ikev2IntegrityAlgorithm.AUTH_HMAC_MD5_128: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.MD5, integrity_check_value_length_bytes=16,
        ),
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_160: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA1, integrity_check_value_length_bytes=20,
        ),
        # RFC 4868 §2.1 — HMAC-SHA2. Transform IDs 12 (SHA2-256-128), 13
        # (SHA2-384-192), 14 (SHA2-512-256). Truncated ICV is standard.
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_256, integrity_check_value_length_bytes=16,
        ),
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_384_192: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_384, integrity_check_value_length_bytes=24,
        ),
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_512_256: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_512, integrity_check_value_length_bytes=32,
        ),
        # Full-length HMAC-SHA2 variants (Transform IDs beyond RFC 4868)
        # — some strongSwan / Cisco configurations advertise them.
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_96: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_256, integrity_check_value_length_bytes=12,
        ),
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_256: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_256, integrity_check_value_length_bytes=32,
        ),
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_384_384: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_384, integrity_check_value_length_bytes=48,
        ),
        Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_512_512: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_512, integrity_check_value_length_bytes=64,
        ),
        # RFC 4494 — AES-CMAC-96 (transform ID 8). 16-byte SK_ai key
        # (AES-128), 12-byte ICV. CMAC construction, not HMAC —
        # ``build_mac_primitive`` dispatches on the MAC enum family
        # (:class:`CmacCryptodome` here, :class:`HmacCryptodome` above).
        Ikev2IntegrityAlgorithm.AUTH_AES_CMAC_96: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.AES_CMAC_96, integrity_check_value_length_bytes=12,
            key_length_bytes=16,
        ),
        # RFC 4543 — AES-GMAC. Transform IDs 9 (128), 10 (192), 11 (256).
        # 16-byte tag. SK_ai carries AES key + 4-octet salt (RFC 4543 §5.1);
        # GCM nonce = ``salt || wire_iv`` (12 octets). No hash MAC — the
        # underlying primitive is GCM keyed by ``bulk_cipher``.
        Ikev2IntegrityAlgorithm.AUTH_AES_128_GMAC: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=None, integrity_check_value_length_bytes=16,
            key_length_bytes=16, salt_length_bytes=4,
            bulk_cipher=BlockCipher.AES_128,
        ),
        Ikev2IntegrityAlgorithm.AUTH_AES_192_GMAC: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=None, integrity_check_value_length_bytes=16,
            key_length_bytes=24, salt_length_bytes=4,
            bulk_cipher=BlockCipher.AES_192,
        ),
        Ikev2IntegrityAlgorithm.AUTH_AES_256_GMAC: Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=None, integrity_check_value_length_bytes=16,
            key_length_bytes=32, salt_length_bytes=4,
            bulk_cipher=BlockCipher.AES_256,
        ),
    }

    encryption_transform = attr.ib(validator=attr.validators.instance_of(AeadBulkCipherDescriptor))
    integrity_transform = attr.ib(validator=attr.validators.instance_of(Ikev2IntegrityAlgorithm))
    # ``sk_er`` / ``sk_ar`` are the write + integrity keys (RFC 7296
    # §2.14). ``repr=False`` keeps them out of default attrs repr.
    sk_er = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)), repr=False)
    sk_ar = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)), repr=False)
    cipher_factory = attr.ib(validator=attr.validators.is_callable())
    hmac_primitive: HmacBase | None = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(HmacBase)),
    )

    _record_initialization_vector_length_bytes = attr.ib(init=False, repr=False)
    _integrity_check_value_length_bytes = attr.ib(init=False, repr=False)
    _salt = attr.ib(init=False, repr=False)
    _integrity_gmac_primitive: GmacCryptodome | None = attr.ib(
        init=False, repr=False, default=None,
    )
    _integrity_gmac_key_length_bytes = attr.ib(init=False, repr=False, default=0)

    @classmethod
    def get_encryption_transform_derivation_parameters(
        cls, encryption_transform: AeadBulkCipherDescriptor,
    ) -> Ikev2EncryptionTransformDerivationParameters:
        """Mirror of :meth:`Ikev2SkDecryptor.get_encryption_transform_derivation_parameters`."""
        parameters = cls._TRANSFORM_PROPERTIES.get(encryption_transform)
        if parameters is None:
            raise ValueError(f'{encryption_transform} is not supported by {cls.__name__}')
        return parameters

    @classmethod
    def get_integrity_transform_derivation_parameters(
        cls, integrity_transform: Ikev2IntegrityAlgorithm,
    ) -> Ikev2IntegrityTransformDerivationParameters:
        """HMAC + ICV-length descriptor for ``integrity_transform``."""
        parameters = cls._INTEGRITY_PROPERTIES.get(integrity_transform)
        if parameters is None:
            raise ValueError(f'{integrity_transform.name} is not supported by {cls.__name__}')
        return parameters

    def __attrs_post_init__(self) -> None:
        encryption_parameters = self.get_encryption_transform_derivation_parameters(
            self.encryption_transform,
        )
        integrity_parameters = self.get_integrity_transform_derivation_parameters(
            self.integrity_transform,
        )
        expected_sk_er_length = (
            encryption_parameters.write_key_length_bytes
            + encryption_parameters.salt_length_bytes
        )
        sk_er_bytes = bytes(self.sk_er)
        if len(sk_er_bytes) != expected_sk_er_length:
            raise ValueError(
                f'sk_er length {len(sk_er_bytes)} does not match '
                f'expected {expected_sk_er_length} (write key '
                f'{encryption_parameters.write_key_length_bytes} + '
                f'salt {encryption_parameters.salt_length_bytes})'
            )
        # RFC 5930 §3: salt is the tail of SK_er. For CBC transforms
        # salt_length_bytes == 0, so self._salt is empty and every
        # existing entry preserves its previous behaviour.
        self._salt = sk_er_bytes[encryption_parameters.write_key_length_bytes:]
        self._record_initialization_vector_length_bytes = (
            encryption_parameters.on_wire_initialization_vector_length_bytes
        )
        self._integrity_check_value_length_bytes = (
            integrity_parameters.integrity_check_value_length_bytes
        )
        # Cross-field invariant between ``hmac_primitive`` and the
        # ``is_gmac`` flag on ``integrity_parameters``: HMAC / CMAC
        # integrity MUST inject an ``hmac_primitive``; AES-GMAC integrity
        # MUST leave it ``None`` (its keying material and construction
        # differ, so a stale primitive would silently misbehave in the
        # code path that expects a GMAC branch). Catch the mismatch at
        # construction rather than deferring to a later
        # ``AttributeError`` inside ``compute_integrity_check_value``.
        if integrity_parameters.is_gmac and self.hmac_primitive is not None:
            raise ValueError(
                f'AES-GMAC integrity transform '
                f'{self.integrity_transform.name} must be constructed '
                f'without ``hmac_primitive`` (the GmacCryptodome branch '
                f'takes over); pass hmac_primitive=None or omit it.'
            )
        if not integrity_parameters.is_gmac and self.hmac_primitive is None:
            raise ValueError(
                f'HMAC / CMAC integrity transform '
                f'{self.integrity_transform.name} requires ``hmac_primitive``; '
                f'construct via :class:`Ikev2SkDecryptorNonAeadCryptodome` '
                f'which builds one automatically, or inject an HmacBase '
                f'instance explicitly.'
            )
        # RFC 4543 AES-GMAC integrity path: SK_a* = AES key || 4-octet
        # salt. Verify SK_ar carries the combined length + stash a
        # GmacCryptodome + AES-key-length so compute_integrity_check_value
        # can split SK_ar and form the GCM nonce (salt || wire_iv).
        # HMAC / CMAC integrity leaves ``_integrity_gmac_primitive``
        # ``None`` and the existing hmac_primitive-driven path runs.
        if integrity_parameters.is_gmac:
            expected_sk_ar_length = integrity_parameters.effective_key_length_bytes
            if len(self.sk_ar) != expected_sk_ar_length:
                raise ValueError(
                    f'sk_ar length {len(self.sk_ar)} does not match expected '
                    f'{expected_sk_ar_length} for AES-GMAC integrity '
                    f'(AES key {integrity_parameters.key_length_bytes} + '
                    f'salt {integrity_parameters.salt_length_bytes})'
                )
            self._integrity_gmac_primitive = GmacCryptodome(
                block_cipher=integrity_parameters.bulk_cipher,
            )
            self._integrity_gmac_key_length_bytes = integrity_parameters.key_length_bytes

    @property
    def record_initialization_vector_length_bytes(self) -> int:
        """On-wire IV length (the AES block size for CBC)."""
        return self._record_initialization_vector_length_bytes

    @property
    def integrity_check_value_length_bytes(self) -> int:
        """ICV length per RFC 4868 truncation rules."""
        return self._integrity_check_value_length_bytes

    def encrypt(
        self,
        inner_plaintext_padded: bytes | bytearray,
        on_wire_iv: bytes | None = None,
    ) -> bytes:
        """Encrypt one SK envelope body (non-AEAD).

        Returns the bytes that go before the trailing ICV: ``on-wire IV |
        CBC-ciphertext``. The caller is responsible for computing the
        HMAC ICV over the full ``IKEHeader | unencrypted | SK header | on-wire IV | ciphertext``
        and appending it (see :meth:`compute_signed_octets`)."""
        if on_wire_iv is None:
            on_wire_iv = os.urandom(self._record_initialization_vector_length_bytes)
        if len(on_wire_iv) != self._record_initialization_vector_length_bytes:
            raise ValueError(
                f'on_wire_iv length {len(on_wire_iv)} does not match '
                f'expected {self._record_initialization_vector_length_bytes}'
            )

        cipher = self.cipher_factory(bytes(on_wire_iv))
        return bytes(on_wire_iv) + cipher.encrypt(bytes(inner_plaintext_padded))

    def decrypt(
        self,
        ciphertext: bytes | bytearray,
        integrity_check_value: bytes | bytearray,
        signed_octets: bytes | bytearray,
    ) -> bytes:
        """Decrypt one SK envelope body (non-AEAD) after HMAC-verifying the ICV.

        :param ciphertext: ``on-wire IV | encrypted payloads + padding +
            pad length`` from the SK payload's variable-length region
            (without the trailing ICV).
        :param integrity_check_value: trailing ICV bytes of the SK
            payload body.
        :param signed_octets: byte string the ICV is computed over
            (RFC 7296 §3.14). Build via :meth:`compute_signed_octets`.
        :return: decrypted inner payload bytes (still wrapped in
            ``encrypted payloads | Padding | Pad Length``; strip with
            :meth:`Ikev2SkDecryptor.split_padded_plaintext`).
        :raises ValueError: on ICV length mismatch, HMAC verification
            failure, or ciphertext shorter than the on-wire IV.
        """
        ciphertext_bytes = bytes(ciphertext)
        if len(integrity_check_value) != self._integrity_check_value_length_bytes:
            raise ValueError(
                f'integrity_check_value length {len(integrity_check_value)} does not match '
                f'expected {self._integrity_check_value_length_bytes}'
            )
        if len(ciphertext_bytes) < self._record_initialization_vector_length_bytes:
            raise ValueError(
                f'ciphertext length {len(ciphertext_bytes)} shorter than '
                f'on-wire IV {self._record_initialization_vector_length_bytes}'
            )

        on_wire_iv = ciphertext_bytes[:self._record_initialization_vector_length_bytes]
        encrypted_body = ciphertext_bytes[self._record_initialization_vector_length_bytes:]

        # ``wire_iv`` is required by the AES-GMAC integrity path (RFC 4543
        # §5.1: GCM nonce = ``salt || wire_iv``). HMAC / CMAC paths
        # ignore it — passing it unconditionally keeps the call site
        # simple.
        self.verify_integrity_check_value(
            bytes(signed_octets), integrity_check_value, wire_iv=on_wire_iv,
        )

        cipher = self.cipher_factory(on_wire_iv)
        return cipher.decrypt(encrypted_body)

    @staticmethod
    def compute_signed_octets(
        ike_header_bytes: bytes | bytearray,
        unencrypted_payloads_bytes: bytes | bytearray,
        sk_payload_header_bytes: bytes | bytearray,
        sk_payload_body_without_icv: bytes | bytearray,
    ) -> bytes:
        """Build the byte string the HMAC ICV is computed over (RFC 7296 §3.14).

        ``ICV = HMAC(SK_ar, IKE-message-without-ICV)``: everything from
        the IKE header through the SK payload header and on-wire IV +
        ciphertext + padding + pad length, **excluding** the trailing
        ICV bytes themselves."""
        return (
            bytes(ike_header_bytes)
            + bytes(unencrypted_payloads_bytes)
            + bytes(sk_payload_header_bytes)
            + bytes(sk_payload_body_without_icv)
        )

    def compute_integrity_check_value(
        self,
        signed_octets: bytes | bytearray,
        wire_iv: bytes | bytearray | None = None,
    ) -> bytes:
        """Produce the truncated ICV over ``signed_octets`` per RFC 7296 §3.14.

        HMAC / CMAC path: keyed on the full ``sk_ar``, ``wire_iv`` unused.
        AES-GMAC path (RFC 4543): the SK_a* material is split into the
        AES key (first ``key_length_bytes`` octets) and a 4-octet salt.
        The GCM nonce is ``salt || wire_iv`` — the per-packet on-wire
        IV must therefore be supplied. Passing ``wire_iv=None`` with a
        GMAC integrity transform raises ``ValueError``.
        """
        if self._integrity_gmac_primitive is not None:
            if wire_iv is None:
                raise ValueError('AES-GMAC integrity requires wire_iv')
            # RFC 4543 §3.1 pins the per-packet IV to 8 octets so the
            # GCM nonce is exactly ``4-octet salt || 8-octet IV`` = 12
            # octets (§3.2). When the negotiated encryption transform
            # is AES-CBC the caller's ``wire_iv`` is the AES block
            # size (16 octets) — combining that with the 4-octet salt
            # would yield a 20-octet nonce that PyCryptodome silently
            # re-hashes via GHASH, producing a tag no conformant peer
            # will match. Refuse rather than compute a wrong tag.
            wire_iv_bytes = bytes(wire_iv)
            if len(wire_iv_bytes) != _GMAC_WIRE_IV_LENGTH_BYTES:
                # Ikev2TransformDerivationError subclasses ValueError, so
                # existing test-side ``assertRaises(ValueError)`` still
                # catches it — while the pubkey probe driver's
                # ``_try_ikev2_eap_probe`` explicitly handles this
                # exception type as "responder negotiated a transform
                # combination we cannot decrypt" and returns None
                # instead of aborting the whole analyzer session.
                raise Ikev2TransformDerivationError(
                    f'AES-GMAC integrity requires an '
                    f'{_GMAC_WIRE_IV_LENGTH_BYTES}-octet wire_iv (RFC 4543 '
                    f'§3.1), got {len(wire_iv_bytes)}. AES-GMAC integrity '
                    f'is only compatible with encryption transforms whose '
                    f'on-wire IV is 8 octets (e.g. AES-CTR); pairing it '
                    f'with AES-CBC (16-octet IV) is out of scope.'
                )
            aes_key = bytes(self.sk_ar)[:self._integrity_gmac_key_length_bytes]
            salt = bytes(self.sk_ar)[self._integrity_gmac_key_length_bytes:]
            nonce = salt + wire_iv_bytes
            tag = self._integrity_gmac_primitive.digest(aes_key, nonce, bytes(signed_octets))
            return tag[:self._integrity_check_value_length_bytes]
        expected_full = self.hmac_primitive.digest(bytes(self.sk_ar), bytes(signed_octets))
        return expected_full[:self._integrity_check_value_length_bytes]

    def verify_integrity_check_value(
        self,
        signed_octets: bytes,
        integrity_check_value: bytes | bytearray,
        wire_iv: bytes | bytearray | None = None,
    ) -> None:
        """Verify ``integrity_check_value`` against ``signed_octets``.

        ``wire_iv`` — mandatory for AES-GMAC integrity transforms
        (RFC 4543); ignored for HMAC / CMAC.
        """
        expected_truncated = self.compute_integrity_check_value(signed_octets, wire_iv=wire_iv)
        if not hmac.compare_digest(expected_truncated, bytes(integrity_check_value)):
            raise ValueError('IKEv2 SK ICV verification failed')

    @staticmethod
    def split_sk_wire_bytes(
            response_message: IsakmpMessage,
            sk_payload: Ikev2PayloadEncryptedAndAuthenticated,
            raw_response_bytes: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """Slice ``raw_response_bytes`` into ``(ike_header, unencrypted,
        sk_header)`` by walking ``response_message.payloads`` up to
        ``sk_payload`` to locate the SK header offset.

        Any unencrypted payload preceding SK (e.g. NAT_DETECTION_* /
        REDIRECT notifies) shifts that offset.
        """
        sk_header_offset = IsakmpMessage.HEADER_SIZE
        for payload in response_message.payloads:
            if payload is sk_payload:
                break
            sk_header_offset += len(payload.compose())
        ike_header_bytes = bytes(raw_response_bytes[:IsakmpMessage.HEADER_SIZE])
        unencrypted_bytes = bytes(raw_response_bytes[IsakmpMessage.HEADER_SIZE:sk_header_offset])
        sk_header_bytes = bytes(
            raw_response_bytes[sk_header_offset:sk_header_offset
                               + Ikev2PayloadEncryptedAndAuthenticated.HEADER_SIZE]
        )
        return ike_header_bytes, unencrypted_bytes, sk_header_bytes

    @staticmethod
    def compose_ike_auth_message(
            decryptor: typing.Any,
            inner_payloads: list[typing.Any],
            initiator_spi: int,
            responder_spi: int,
            message_id: int = 1,
    ) -> bytes:
        """Compose an outgoing IKE_AUTH outer message with the inner payload
        chain non-AEAD-wrapped in an SK envelope (RFC 7296 §3.14).

        Caller-supplied ``decryptor`` is an
        :class:`Ikev2SkDecryptorNonAeadCryptodome` keyed with ``SK_ei`` +
        ``SK_ai`` for the outgoing direction (initiator-to-responder).
        """
        block_size_bytes = decryptor.encryption_transform.bulk_cipher.value.block_size // 8
        cipher_with_iv = decryptor.encrypt(Ikev2SkDecryptor.pad_inner_plaintext(
            Ikev2SkDecryptor.compose_inner_payload_chain(inner_payloads),
            block_size=block_size_bytes,
        ))
        sk_body_length = len(cipher_with_iv) + decryptor.integrity_check_value_length_bytes
        ike_header_bytes, sk_header_bytes = Ikev2SkDecryptor.compose_sk_envelope_headers(
            inner_payloads, sk_body_length, initiator_spi, responder_spi, message_id,
        )
        integrity_check_value = decryptor.compute_integrity_check_value(
            decryptor.compute_signed_octets(
                ike_header_bytes, b'', sk_header_bytes, cipher_with_iv,
            ),
            wire_iv=cipher_with_iv[:decryptor.record_initialization_vector_length_bytes],
        )
        return ike_header_bytes + sk_header_bytes + cipher_with_iv + integrity_check_value

    @staticmethod
    def decrypt_sk_payload(
            decryptor: typing.Any,
            response_message: IsakmpMessage,
            sk_payload: Ikev2PayloadEncryptedAndAuthenticated,
            raw_response_bytes: bytes,
    ) -> list[typing.Any]:
        """Inverse of :meth:`compose_ike_auth_message`.

        Splits the trailing ICV off ``sk_payload.encrypted_data``,
        HMAC-verifies it against the ``IKEHeader | unencrypted payloads |
        SK header | IV | ciphertext`` prefix of the wire bytes (RFC 7296
        §3.14), then CBC-decrypts the body and strips the
        ``Padding | Pad Length`` trailer.
        """
        encrypted_data = bytes(sk_payload.encrypted_data)
        icv_length = decryptor.integrity_check_value_length_bytes
        cipher_with_iv = encrypted_data[:len(encrypted_data) - icv_length]
        integrity_check_value = encrypted_data[len(encrypted_data) - icv_length:]
        ike_header_bytes, unencrypted_bytes, sk_header_bytes = (
            Ikev2SkDecryptorNonAead.split_sk_wire_bytes(
                response_message, sk_payload, raw_response_bytes,
            )
        )
        signed_octets = decryptor.compute_signed_octets(
            ike_header_bytes, unencrypted_bytes, sk_header_bytes, cipher_with_iv,
        )
        try:
            inner_plaintext_padded = decryptor.decrypt(
                cipher_with_iv, integrity_check_value, signed_octets,
            )
        except ValueError as exc:
            raise Ikev2SkAuthenticationError(str(exc)) from exc
        # RFC 7296 §3.14 ``Padding | Pad Length`` trailer is identical
        # between the AEAD and non-AEAD SK envelope bodies (Figure 21),
        # so the split helper lives on :class:`Ikev2SkDecryptor` and is
        # reused here rather than duplicated.
        return Ikev2SkDecryptor.parse_inner_payload_chain(
            Ikev2SkDecryptor.split_padded_plaintext(inner_plaintext_padded),
            sk_payload.next_payload,
        )


@attr.s
class Ikev2SkDecryptorNonAeadCryptodome(Ikev2SkDecryptorNonAead):
    """Convenience subclass: auto-builds ``cipher_factory`` + HMAC primitive."""

    cipher_factory = attr.ib(init=False, default=None)
    hmac_primitive = attr.ib(init=False, default=None)

    def __attrs_post_init__(self) -> None:
        encryption_parameters = self.get_encryption_transform_derivation_parameters(
            self.encryption_transform,
        )
        integrity_parameters = self.get_integrity_transform_derivation_parameters(
            self.integrity_transform,
        )
        write_key = bytes(self.sk_er)[:encryption_parameters.write_key_length_bytes]
        salt = bytes(self.sk_er)[encryption_parameters.write_key_length_bytes:]
        bulk_cipher = self.encryption_transform.bulk_cipher
        block_cipher_mode = self.encryption_transform.block_cipher_mode

        if block_cipher_mode == BlockCipherMode.CTR:
            # RFC 5930 §3: CTR nonce = salt | on-wire IV (12 octets);
            # block counter is the trailing 4 octets and starts at 1.
            def cipher_factory(on_wire_iv: bytes) -> CypherBase:
                return CypherBlockCryptodome(
                    bulk_cipher=bulk_cipher, key=write_key,
                    nonce=salt + bytes(on_wire_iv),
                    block_cipher_mode=block_cipher_mode,
                    initial_value=1,
                )
        else:
            def cipher_factory(nonce: bytes) -> CypherBase:
                return CypherBlockCryptodome(
                    bulk_cipher=bulk_cipher, key=write_key, nonce=nonce,
                    block_cipher_mode=block_cipher_mode,
                )

        self.cipher_factory = cipher_factory
        # HMAC / CMAC path uses ``mac_algorithm``; GMAC path leaves
        # ``mac_algorithm`` unset and ``__attrs_post_init__`` on the base
        # class builds a :class:`GmacCryptodome` in
        # ``_integrity_gmac_primitive`` instead.
        if integrity_parameters.mac_algorithm is not None:
            self.hmac_primitive = HmacBase.for_algorithm(integrity_parameters.mac_algorithm)
        super().__attrs_post_init__()


@attr.s(frozen=True)
class _NegotiatedIkev2Transforms:
    """Tuple of transforms the responder picked from the initiator's SA."""

    encryption_descriptor = attr.ib(
        validator=attr.validators.instance_of(AeadBulkCipherDescriptor)
    )
    encryption_algorithm = attr.ib(
        validator=attr.validators.instance_of(Ikev2EncryptionAlgorithm)
    )
    encryption_key_length_bits = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )
    integrity_algorithm = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Ikev2IntegrityAlgorithm)
        )
    )
    prf = attr.ib(validator=attr.validators.instance_of(Ikev2PseudorandomFunction))
    dh_group = attr.ib(validator=attr.validators.instance_of(Ikev2DiffieHellmanGroup))

    @classmethod
    def from_message(
            cls,
            sa_payload: Ikev2PayloadSecurityAssociation,
    ) -> _NegotiatedIkev2Transforms:
        """Walk the responder's SA proposal and pull out the chosen
        ENCR / PRF / INTEG / DH transforms plus the encryption key length
        attribute.

        Raises :class:`Ikev2TransformDerivationError` if any of the four
        mandatory transforms is missing — that indicates the responder
        sent a malformed SA response and the analyzer cannot derive
        ``SK_*`` without all four.
        """
        if not sa_payload.proposals:
            raise Ikev2TransformDerivationError('responder SA payload has no proposals')
        proposal = sa_payload.proposals[0]

        encryption_transform: Ikev2TransformEncryptionAlgorithm | None = None
        integrity_transform: Ikev2TransformIntegrity | None = None
        prf_transform: Ikev2TransformPrf | None = None
        dh_transform: Ikev2TransformDhGroup | None = None

        for transform in proposal.transforms:
            if isinstance(transform, Ikev2TransformEncryptionAlgorithm):
                encryption_transform = transform
            elif isinstance(transform, Ikev2TransformIntegrity):
                integrity_transform = transform
            elif isinstance(transform, Ikev2TransformPrf):
                prf_transform = transform
            elif isinstance(transform, Ikev2TransformDhGroup):
                dh_transform = transform

        if encryption_transform is None or prf_transform is None or dh_transform is None:
            raise Ikev2TransformDerivationError('responder SA missing ENCR / PRF / DH transform')

        key_length_bits = encryption_transform.key_length
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            encryption_transform.transform_id, key_length_bits,
        )

        return cls(
            encryption_descriptor=descriptor,
            encryption_algorithm=encryption_transform.transform_id,
            encryption_key_length_bits=key_length_bits,
            integrity_algorithm=(
                integrity_transform.transform_id if integrity_transform is not None else None
            ),
            prf=prf_transform.transform_id,
            dh_group=dh_transform.transform_id,
        )


AeadBulkCipherDescriptor._ENCR_MAP = {  # pylint: disable=protected-access
    (Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
    ),
    (Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 192): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_192, block_cipher_mode=BlockCipherMode.CBC,
    ),
    (Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 256): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.CBC,
    ),
    (Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 128): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.GCM,
    ),
    (Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 192): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_192, block_cipher_mode=BlockCipherMode.GCM,
    ),
    (Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 256): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
    ),
    **{
        (encr, key_length): AeadBulkCipherDescriptor(
            bulk_cipher=bulk_cipher, block_cipher_mode=gcm_mode,
        )
        for bulk_cipher, key_length in (
            (BlockCipher.AES_128, 128),
            (BlockCipher.AES_192, 192),
            (BlockCipher.AES_256, 256),
        )
        for encr, gcm_mode in (
            (Ikev2EncryptionAlgorithm.ENCR_AES_GCM_8, BlockCipherMode.GCM_8),
            (Ikev2EncryptionAlgorithm.ENCR_AES_GCM_12, BlockCipherMode.GCM_12),
        )
    },
    **{
        (encr, key_length): AeadBulkCipherDescriptor(
            bulk_cipher=bulk_cipher, block_cipher_mode=ccm_mode,
        )
        for bulk_cipher, key_length in (
            (BlockCipher.AES_128, 128),
            (BlockCipher.AES_192, 192),
            (BlockCipher.AES_256, 256),
        )
        for encr, ccm_mode in (
            (Ikev2EncryptionAlgorithm.ENCR_AES_CCM_8, BlockCipherMode.CCM_8),
            (Ikev2EncryptionAlgorithm.ENCR_AES_CCM_12, BlockCipherMode.CCM_12),
            (Ikev2EncryptionAlgorithm.ENCR_AES_CCM_16, BlockCipherMode.CCM_16),
        )
    },
    **{
        (Ikev2EncryptionAlgorithm.ENCR_AES_CTR, key_length): AeadBulkCipherDescriptor(
            bulk_cipher=bulk_cipher, block_cipher_mode=BlockCipherMode.CTR,
        )
        for bulk_cipher, key_length in (
            (BlockCipher.AES_128, 128),
            (BlockCipher.AES_192, 192),
            (BlockCipher.AES_256, 256),
        )
    },
    (Ikev2EncryptionAlgorithm.ENCR_CHACHA20_POLY1305, None): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.CHACHA20, block_cipher_mode=None,
    ),
    (Ikev2EncryptionAlgorithm.ENCR_3DES, None): AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.TRIPLE_DES_168, block_cipher_mode=BlockCipherMode.CBC,
    ),
}


@attr.s(frozen=True)
class _NegotiatedIkev1Transforms:
    """Tuple of transforms the responder picked from the initiator's SA payload."""

    encryption_algorithm = attr.ib(
        validator=attr.validators.instance_of(Ikev1EncryptionAlgorithm)
    )
    hash_algorithm = attr.ib(
        validator=attr.validators.instance_of(Ikev1HashAlgorithm)
    )
    authentication_method = attr.ib(
        validator=attr.validators.instance_of(Ikev1AuthenticationMethod)
    )
    dh_group = attr.ib(
        validator=attr.validators.instance_of(Ikev1DiffieHellmanGroup)
    )
    key_length = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )

    @classmethod
    def from_message(
            cls,
            sa_payload: Ikev1PayloadSecurityAssociation,
    ) -> _NegotiatedIkev1Transforms:
        """Walk the responder's IKEv1 SA payload and pull out the picked ENCR / HASH / AUTH / DH attributes plus the
        optional key length.
        """
        if not sa_payload.proposals:
            raise Ikev2TransformDerivationError('responder SA payload has no proposals')

        proposal = sa_payload.proposals[0]
        if not proposal.transforms:
            raise Ikev2TransformDerivationError('responder SA proposal has no transforms')

        transform = proposal.transforms[0]

        encryption_algorithm: Ikev1EncryptionAlgorithm | None = None
        hash_algorithm: Ikev1HashAlgorithm | None = None
        authentication_method: Ikev1AuthenticationMethod | None = None
        dh_group: Ikev1DiffieHellmanGroup | None = None
        key_length: int | None = None

        for attribute in transform.attributes:
            if isinstance(attribute, Ikev1AttributeEncryptionAlgorithm):
                encryption_algorithm = attribute.value
            elif isinstance(attribute, Ikev1AttributeHashAlgorithm):
                hash_algorithm = attribute.value
            elif isinstance(attribute, Ikev1AttributeAuthenticationMethod):
                authentication_method = attribute.value
            elif isinstance(attribute, Ikev1AttributeDiffieHellmanGroup):
                dh_group = attribute.value
            elif isinstance(attribute, Ikev1AttributeKeyLength):
                key_length = attribute.value

        if (
            encryption_algorithm is None
            or hash_algorithm is None
            or authentication_method is None
            or dh_group is None
        ):
            raise Ikev2TransformDerivationError(
                'responder SA missing ENCR / HASH / AUTH / DH attribute'
            )

        return cls(
            encryption_algorithm=encryption_algorithm,
            hash_algorithm=hash_algorithm,
            authentication_method=authentication_method,
            dh_group=dh_group,
            key_length=key_length,
        )


_AEAD_BLOCK_SIZE = 1
