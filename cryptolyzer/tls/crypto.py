"""TLS 1.3 key schedule and record-layer AEAD (RFC 8446)."""

from __future__ import annotations

import typing

import attr

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, Hash, MAC, NamedGroup
from cryptodatahub.tls.algorithm import TlsCipherSuite

from cryptoparser.common.parse import ComposerBinary
from cryptoparser.tls.extension import (
    TlsExtensionKeyShareClient,
    TlsKeyShareEntry,
    TlsNamedCurve,
)
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsContentType
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.crypto import (
    CypherBase,
    CypherBlockCryptodome,
    CypherStreamCryptodome,
    EphemeralKeyExchangeEllipticCurveCryptodome,
    HandshakeDecryptorBase,
    HashBase,
    HashCryptodome,
    HmacBase,
    HmacCryptodome,
)
from cryptolyzer.tls.exception import TlsAlert


@attr.s(frozen=True)
class AeadBulkCipherDescriptor:
    """AEAD-oriented bulk cipher identity for TLS 1.3 suite property lookup."""

    bulk_cipher = attr.ib(validator=attr.validators.instance_of(BlockCipher))
    block_cipher_mode = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode))
    )


@attr.s(frozen=True)
class Tls13CipherSuiteDerivationParameters:
    """HKDF hash and AEAD sizes for one TLS 1.3 cipher suite (RFC 8446)."""

    RECORD_INITIALIZATION_VECTOR_LENGTH_BYTES = 12

    hkdf_hash = attr.ib(validator=attr.validators.instance_of(Hash))
    write_key_length_bytes = attr.ib(validator=attr.validators.instance_of(int))
    authentication_tag_length_bytes = attr.ib(validator=attr.validators.instance_of(int))


@attr.s
class Tls13HandshakeDecryptor(HandshakeDecryptorBase):  # pylint: disable=too-many-instance-attributes
    """TLS 1.3 handshake HKDF key schedule + AEAD record decryption (RFC 8446 §7.1, §5.2).

    Backend-neutral: inject HMAC, hash, and AEAD cipher factory for testing.
    Combines key derivation (HKDF) with record decryption in a single object.
    """

    _CIPHER_SUITE_PROPERTIES: typing.ClassVar[
        dict[AeadBulkCipherDescriptor, Tls13CipherSuiteDerivationParameters]
    ] = {
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128,
            block_cipher_mode=BlockCipherMode.GCM,
        ): Tls13CipherSuiteDerivationParameters(
            hkdf_hash=Hash.SHA2_256,
            write_key_length_bytes=16,
            authentication_tag_length_bytes=16,
        ),
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_256,
            block_cipher_mode=BlockCipherMode.GCM,
        ): Tls13CipherSuiteDerivationParameters(
            hkdf_hash=Hash.SHA2_384,
            write_key_length_bytes=32,
            authentication_tag_length_bytes=16,
        ),
        AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.CHACHA20,
            block_cipher_mode=None,
        ): Tls13CipherSuiteDerivationParameters(
            hkdf_hash=Hash.SHA2_256,
            write_key_length_bytes=32,
            authentication_tag_length_bytes=16,
        ),
    }

    cipher_suite = attr.ib(validator=attr.validators.instance_of(TlsCipherSuite))
    key_exchange_shared_secret = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    handshake_transcript_hash = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    hmac_primitive = attr.ib(validator=attr.validators.instance_of(HmacBase))
    hash_primitive = attr.ib(validator=attr.validators.instance_of(HashBase))
    cipher_factory = attr.ib(validator=attr.validators.is_callable())

    _authentication_tag_length_bytes = attr.ib(init=False, repr=False)
    _initialization_vector = attr.ib(init=False, repr=False)
    _write_key = attr.ib(init=False, repr=False)
    _record_sequence_number = attr.ib(init=False, repr=False)

    @classmethod
    def get_cipher_suite_derivation_parameters(
        cls, cipher_suite: TlsCipherSuite
    ) -> Tls13CipherSuiteDerivationParameters:
        """Return :class:`Tls13CipherSuiteDerivationParameters` for ``cipher_suite``."""
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=cipher_suite.value.bulk_cipher,
            block_cipher_mode=cipher_suite.value.block_cipher_mode,
        )
        parameters = cls._CIPHER_SUITE_PROPERTIES.get(descriptor)
        if parameters is None:
            raise ValueError(f'{cipher_suite.name} is not supported by {cls.__name__}')
        return parameters

    def __attrs_post_init__(self) -> None:
        if TlsProtocolVersion(self.cipher_suite.value.initial_version) <= TlsProtocolVersion(TlsVersion.TLS1_2):
            raise ValueError(f'{self.cipher_suite.name} is not a TLS 1.3 cipher suite')

        cipher_parameters = self.get_cipher_suite_derivation_parameters(self.cipher_suite)
        hash_digest_length = self.hmac_primitive.mac_algorithm.value.digest_size // 8
        write_key_length_bytes = cipher_parameters.write_key_length_bytes

        zero_bytes = bytes([0]) * hash_digest_length
        empty_transcript_hash = self.hash_primitive.digest(b'')

        early_secret = self._hkdf_extract(zero_bytes, zero_bytes)
        derived_secret = self._derive_secret(early_secret, 'derived', empty_transcript_hash)
        handshake_secret = self._hkdf_extract(derived_secret, bytes(self.key_exchange_shared_secret))
        server_handshake_traffic_secret = self._derive_secret(
            handshake_secret, 's hs traffic', bytes(self.handshake_transcript_hash)
        )

        self._write_key = self._hkdf_expand_label(
            server_handshake_traffic_secret,
            'key',
            b'',
            write_key_length_bytes,
        )
        self._initialization_vector = self._hkdf_expand_label(
            server_handshake_traffic_secret,
            'iv',
            b'',
            Tls13CipherSuiteDerivationParameters.RECORD_INITIALIZATION_VECTOR_LENGTH_BYTES,
        )
        self._authentication_tag_length_bytes = cipher_parameters.authentication_tag_length_bytes
        self._record_sequence_number = 0

    @staticmethod
    def split_inner_plaintext(inner_plaintext: bytes | bytearray) -> tuple[TlsContentType, bytes]:
        """Parse ``TLSInnerPlaintext``: strip trailing zero padding; last non-zero octet is real content type."""
        data = bytes(inner_plaintext).rstrip(b'\x00')
        if not data:
            raise TlsAlert(TlsAlertDescription.BAD_RECORD_MAC)
        return TlsContentType(data[-1]), data[:-1]

    @staticmethod
    def compute_additional_data(record: TlsRecord) -> bytes:
        """AEAD additional data for an outer TLS 1.3 ``application_data`` ciphertext record."""
        composer = ComposerBinary()
        composer.compose_numeric(int(record.content_type), 1)
        composer.compose_parsable(record.protocol_version)
        composer.compose_numeric(len(record.fragment), 2)
        return composer.composed_bytes


@attr.s
class Tls13HandshakeDecryptorCryptodome(Tls13HandshakeDecryptor):
    """Convenience: auto-creates PyCryptodome HMAC, hash, and AEAD cipher from cipher suite."""

    _HASH_TO_MAC: typing.ClassVar[dict[Hash, MAC]] = {
        Hash.SHA2_256: MAC.SHA2_256,
        Hash.SHA2_384: MAC.SHA2_384,
        Hash.SHA2_512: MAC.SHA2_512,
    }

    hmac_primitive = attr.ib(init=False, default=None)
    hash_primitive = attr.ib(init=False, default=None)
    cipher_factory = attr.ib(init=False, default=None)

    def __attrs_post_init__(self) -> None:
        parameters = Tls13HandshakeDecryptor.get_cipher_suite_derivation_parameters(self.cipher_suite)
        mac_algorithm = self._HASH_TO_MAC[parameters.hkdf_hash]

        bulk_cipher = self.cipher_suite.value.bulk_cipher
        block_cipher_mode = self.cipher_suite.value.block_cipher_mode

        if bulk_cipher == BlockCipher.CHACHA20:
            def cipher_factory(nonce: bytes) -> CypherBase:
                return CypherStreamCryptodome(
                    bulk_cipher=BlockCipher.CHACHA20, key=self._write_key, nonce=nonce
                )
        else:
            def cipher_factory(nonce: bytes) -> CypherBase:
                return CypherBlockCryptodome(
                    bulk_cipher=bulk_cipher, key=self._write_key, nonce=nonce,
                    block_cipher_mode=block_cipher_mode,
                )

        self.hmac_primitive = HmacCryptodome(mac_algorithm=mac_algorithm)
        self.hash_primitive = HashCryptodome(hash_algorithm=parameters.hkdf_hash)
        self.cipher_factory = cipher_factory

        super().__attrs_post_init__()

    @classmethod
    def transcript_hash(cls, cipher_suite: TlsCipherSuite, handshake_messages: bytes | bytearray) -> bytes:
        """``Transcript-Hash`` octets for the negotiated HKDF hash (RFC 8446 §7.1)."""
        parameters = Tls13HandshakeDecryptor.get_cipher_suite_derivation_parameters(cipher_suite)
        hash_primitive = HashCryptodome(hash_algorithm=parameters.hkdf_hash)
        return hash_primitive.digest(bytes(handshake_messages))


class _EphemeralKeyExchangeBackendCryptodome:
    """Ephemeral EC key agreement backend: creates ``EphemeralKeyExchangeEllipticCurveCryptodome`` instances."""

    _TLS13_KEY_SHARE_CURVE_COUNT_FULL_OFFER = 8
    _TLS13_KEY_SHARE_PREFERRED_ORDER = (
        TlsNamedCurve.X25519,
        TlsNamedCurve.X448,
        TlsNamedCurve.SECP256R1,
        TlsNamedCurve.SECP384R1,
        TlsNamedCurve.SECP521R1,
        TlsNamedCurve.FFDHE2048,
        TlsNamedCurve.FFDHE3072,
        TlsNamedCurve.FFDHE4096,
    )

    @staticmethod
    def supported_named_groups() -> tuple[NamedGroup, ...]:
        return EphemeralKeyExchangeEllipticCurveCryptodome.supported_named_groups()

    @staticmethod
    def create_ephemeral_material(named_group: NamedGroup) -> EphemeralKeyExchangeEllipticCurveCryptodome:
        return EphemeralKeyExchangeEllipticCurveCryptodome(named_group=named_group)

    @classmethod
    def _select_curves_for_tls13_key_share(cls, named_curves):
        """Pick which ``TlsNamedCurve`` values get ``key_share`` entries (ephemeral keys are generated per curve)."""
        curve_list = list(named_curves)
        if len(curve_list) <= cls._TLS13_KEY_SHARE_CURVE_COUNT_FULL_OFFER:
            return curve_list

        allowed = set(curve_list)
        preferred_present = [curve for curve in cls._TLS13_KEY_SHARE_PREFERRED_ORDER if curve in allowed]
        if preferred_present:
            return preferred_present

        return curve_list[:cls._TLS13_KEY_SHARE_CURVE_COUNT_FULL_OFFER]

    @classmethod
    def build_tls13_key_shares(cls, named_curves=None):
        """TLS 1.3 ``key_share`` with real ephemerals for ``extensions=`` plus a map for optional TLS 1.3 decrypt.

        :returns: ``(extensions, client_key_exchange_by_named_curve)`` where the dict maps each offered
            :class:`~cryptoparser.tls.extension.TlsNamedCurve` to the
            :class:`~cryptolyzer.common.crypto.EphemeralKeyExchangeBase` instance used for that entry
            (for ``Transcript-Hash`` / handshake traffic decrypt on the pubkeys path only).
        """
        if named_curves is None:
            named_curves = list(TlsNamedCurve)

        key_share_entries = []
        client_key_exchange_by_named_curve = {}
        for tls_named_curve in cls._select_curves_for_tls13_key_share(named_curves):
            if tls_named_curve.value.named_group is None:
                continue
            try:
                key_exchange = cls.create_ephemeral_material(tls_named_curve.value.named_group)
            except (NotImplementedError, ValueError):
                continue

            key_share_entries.append(TlsKeyShareEntry(tls_named_curve, key_exchange.public_key_bytes))
            client_key_exchange_by_named_curve[tls_named_curve] = key_exchange

        return [TlsExtensionKeyShareClient(key_share_entries)], client_key_exchange_by_named_curve


dhe_ephemeral_material_backend = _EphemeralKeyExchangeBackendCryptodome()
