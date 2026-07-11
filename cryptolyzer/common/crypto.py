"""Shared crypto abstractions (key agreement, AEAD descriptors) and protocol-specific implementations."""

from __future__ import annotations

import abc
import os
import typing

import asn1crypto.keys
import attr

import Crypto.Cipher.AES
import Crypto.Cipher.ChaCha20_Poly1305
import Crypto.Hash.HMAC
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
import Crypto.Protocol.DH
import Crypto.PublicKey.ECC

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, Hash, MAC, NamedGroup, NamedGroupType
from cryptodatahub.common.parameter import DHParamWellKnown

from cryptoparser.common.parse import ComposerBinary


@attr.s
class EphemeralKeyExchangeBase(abc.ABC):
    """Abstract base class for ephemeral key agreement."""

    _private_key = attr.ib(init=False, repr=False)
    _public_key = attr.ib(init=False, repr=False)
    _shared_secret = attr.ib(init=False, repr=False)

    def __attrs_post_init__(self) -> None:
        try:
            self._is_group_supported()
        except NotImplementedError as e:
            raise ValueError(f'{e.args[0].value.name} is not supported by {type(self).__name__}') from e

        self.generate_key_pair()

    @abc.abstractmethod
    def _is_group_supported(self) -> None:
        """Verify that the configured group is supported by this backend."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def public_key_bytes(self) -> bytes:
        """Local ephemeral public key octets in the backend's wire encoding."""
        raise NotImplementedError()

    @abc.abstractmethod
    def generate_key_pair(self) -> None:
        """Generate a new ephemeral key pair."""
        raise NotImplementedError()

    @abc.abstractmethod
    def compute_shared_secret(self, peer_public_bytes: bytes | bytearray) -> bytes:
        """Derive the shared secret from the peer's public key octets."""
        raise NotImplementedError()


@attr.s
class EphemeralKeyExchangeEllipticCurve(EphemeralKeyExchangeBase):
    """Abstract base class for elliptic-curve ephemeral key agreement."""

    named_group: NamedGroup = attr.ib(validator=attr.validators.instance_of(NamedGroup))

    @classmethod
    @abc.abstractmethod
    def supported_named_groups(cls) -> tuple[NamedGroup, ...]:
        """Named groups supported by this implementation."""
        raise NotImplementedError()

    @staticmethod
    def _montgomery_subject_public_key_info_der(named_group: NamedGroup, raw_bytes: bytes | bytearray) -> bytes:
        """Wrap raw Montgomery-curve public key octets in a SubjectPublicKeyInfo DER structure."""
        algorithm = asn1crypto.keys.PublicKeyAlgorithm()
        algorithm['algorithm'] = asn1crypto.keys.PublicKeyAlgorithmId(named_group.value.oid)
        public_key_info = asn1crypto.keys.PublicKeyInfo()
        public_key_info['algorithm'] = algorithm
        public_key_info['public_key'] = bytes(raw_bytes)
        return public_key_info.dump()


@attr.s
class EphemeralKeyExchangeFiniteField(EphemeralKeyExchangeBase):
    """Abstract base class for finite-field ephemeral key agreement."""

    _NAMED_GROUP_TO_DH_PARAMETERS: typing.ClassVar[dict[NamedGroup, DHParamWellKnown]] = {
        NamedGroup.FFDHE2048: DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        NamedGroup.FFDHE3072: DHParamWellKnown.RFC7919_3072_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        NamedGroup.FFDHE4096: DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        NamedGroup.FFDHE6144: DHParamWellKnown.RFC7919_6144_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        NamedGroup.FFDHE8192: DHParamWellKnown.RFC7919_8192_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
    }

    dh_parameters: DHParamWellKnown = attr.ib(validator=attr.validators.instance_of(DHParamWellKnown))

    @classmethod
    def from_named_group(cls, named_group: NamedGroup) -> EphemeralKeyExchangeFiniteField:
        if named_group.value.group_type != NamedGroupType.FINITE_FIELD:
            raise ValueError(f'{named_group.value.name} is not a finite-field NamedGroup')

        dh_parameters = cls._NAMED_GROUP_TO_DH_PARAMETERS.get(named_group)
        if dh_parameters is None:
            raise NotImplementedError(named_group)
        return cls(dh_parameters=dh_parameters)


@attr.s
class EphemeralKeyExchangeEllipticCurveCryptodome(EphemeralKeyExchangeEllipticCurve):
    """PyCryptodome-backed elliptic-curve ephemeral key agreement."""

    _NAMED_GROUP_TO_CURVE_NAME: typing.ClassVar[dict[NamedGroup, str]] = {
        NamedGroup.PRIME256V1: 'p256',
        NamedGroup.SECP384R1: 'p384',
        NamedGroup.SECP521R1: 'p521',
        NamedGroup.CURVE25519: 'curve25519',
        NamedGroup.CURVE448: 'curve448',
    }

    @classmethod
    def supported_named_groups(cls) -> tuple[NamedGroup, ...]:
        return tuple(cls._NAMED_GROUP_TO_CURVE_NAME)

    def _is_group_supported(self) -> None:
        if self.named_group not in self._NAMED_GROUP_TO_CURVE_NAME:
            raise NotImplementedError(self.named_group)

    def generate_key_pair(self) -> None:
        curve_name = self._NAMED_GROUP_TO_CURVE_NAME[self.named_group]
        self._private_key = Crypto.PublicKey.ECC.generate(curve=curve_name)

    def _import_peer_elliptic_curve_public_key(self, key_bytes: bytes | bytearray) -> Crypto.PublicKey.ECC.EccKey:
        """Import the peer's elliptic-curve public key octets."""
        key_bytes = bytes(key_bytes)

        if self.named_group in (NamedGroup.CURVE25519, NamedGroup.CURVE448):
            return Crypto.PublicKey.ECC.import_key(
                EphemeralKeyExchangeEllipticCurve._montgomery_subject_public_key_info_der(self.named_group, key_bytes)
            )

        return Crypto.PublicKey.ECC.import_key(key_bytes, curve_name=self._NAMED_GROUP_TO_CURVE_NAME[self.named_group])

    @property
    def public_key_bytes(self) -> bytes:
        public_key = self._private_key.public_key()
        if self.named_group in (NamedGroup.CURVE25519, NamedGroup.CURVE448):
            return public_key.export_key(format='raw')
        return public_key.export_key(format='SEC1', compress=False)

    def compute_shared_secret(self, peer_public_bytes: bytes | bytearray) -> bytes:
        peer_public_key = self._import_peer_elliptic_curve_public_key(peer_public_bytes)
        return Crypto.Protocol.DH.key_agreement(
            static_priv=self._private_key,
            static_pub=peer_public_key,
            kdf=lambda shared_secret_bytes: shared_secret_bytes,
        )


@attr.s
class EphemeralKeyExchangeFiniteFieldCryptodome(EphemeralKeyExchangeFiniteField):
    """PyCryptodome-backed finite-field ephemeral key agreement."""

    def _is_group_supported(self) -> None:
        pass

    def generate_key_pair(self) -> None:
        params = self.dh_parameters.value
        random_bytes = os.urandom(params.key_size // 8)
        self._private_key = int.from_bytes(random_bytes, 'big') % (params.parameter_numbers.p - 2) + 2
        self._public_key = pow(params.parameter_numbers.g, self._private_key, params.parameter_numbers.p)

    @property
    def public_key_bytes(self) -> bytes:
        params = self.dh_parameters.value
        return self._public_key.to_bytes(params.key_size // 8, 'big')

    def compute_shared_secret(self, peer_public_bytes: bytes | bytearray) -> bytes:
        params = self.dh_parameters.value
        peer_public_key_integer = int.from_bytes(bytes(peer_public_bytes), 'big')
        shared_secret = pow(peer_public_key_integer, self._private_key, params.parameter_numbers.p)
        return shared_secret.to_bytes(params.key_size // 8, 'big')


@attr.s
class CypherBase(abc.ABC):
    """Abstract base class for ciphers."""
    bulk_cipher: BlockCipher = attr.ib(validator=attr.validators.instance_of(BlockCipher))

    @abc.abstractmethod
    def _is_block_cipher_supported(self) -> None:
        """Check if the block cipher is supported."""
        raise NotImplementedError()

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes | bytearray) -> bytes:
        """Encrypt the plaintext."""
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes | bytearray) -> bytes:
        """Decrypt the ciphertext."""
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt_and_verify(
        self,
        ciphertext: bytes | bytearray,
        tag: bytes | bytearray,
        additional_data: bytes | bytearray,
    ) -> bytes:
        """Decrypt ``ciphertext`` and verify the AEAD ``tag`` against ``additional_data``."""
        raise NotImplementedError()


@attr.s
class CypherBlockBase(CypherBase):
    """Abstract base class for block ciphers."""

    key = attr.ib(validator=attr.validators.instance_of(bytes))
    nonce = attr.ib(validator=attr.validators.instance_of(bytes))
    block_cipher_mode: BlockCipherMode = attr.ib(validator=attr.validators.instance_of(BlockCipherMode))

    @abc.abstractmethod
    def _is_block_cipher_mode_supported(self):
        """Check if the block cipher mode is supported."""
        raise NotImplementedError()


@attr.s
class CypherStreamBase(CypherBase):
    """Abstract base class for stream ciphers."""

    key = attr.ib(validator=attr.validators.instance_of(bytes))
    nonce = attr.ib(validator=attr.validators.instance_of(bytes))


@attr.s
class CypherBlockCryptodome(CypherBlockBase):
    """PyCryptodome-backed block cipher."""

    _BLOCK_CIPHER_TO_MODULE: typing.ClassVar[dict[BlockCipher, typing.Any]] = {
        BlockCipher.AES_128: Crypto.Cipher.AES,
        BlockCipher.AES_256: Crypto.Cipher.AES,
    }

    _BLOCK_CIPHER_MODE_TO_CONSTANT: typing.ClassVar[dict[BlockCipherMode, int]] = {
        BlockCipherMode.GCM: Crypto.Cipher.AES.MODE_GCM,
    }

    def __attrs_post_init__(self) -> None:
        try:
            self._is_block_cipher_supported()
            self._is_block_cipher_mode_supported()
        except NotImplementedError as e:
            raise ValueError(f'{e.args[0].name} is not supported by {type(self).__name__}') from e

    def _is_block_cipher_supported(self) -> None:
        if self.bulk_cipher not in self._BLOCK_CIPHER_TO_MODULE:
            raise NotImplementedError(self.bulk_cipher)

    def _is_block_cipher_mode_supported(self) -> None:
        if self.block_cipher_mode not in self._BLOCK_CIPHER_MODE_TO_CONSTANT:
            raise NotImplementedError(self.block_cipher_mode)

    def _new_cipher(self) -> typing.Any:
        module = self._BLOCK_CIPHER_TO_MODULE[self.bulk_cipher]
        mode = self._BLOCK_CIPHER_MODE_TO_CONSTANT[self.block_cipher_mode]
        return module.new(self.key, mode, nonce=self.nonce)

    def encrypt(self, plaintext: bytes | bytearray) -> bytes:
        return self._new_cipher().encrypt(bytes(plaintext))

    def decrypt(self, ciphertext: bytes | bytearray) -> bytes:
        return self._new_cipher().decrypt(bytes(ciphertext))

    def decrypt_and_verify(
        self,
        ciphertext: bytes | bytearray,
        tag: bytes | bytearray,
        additional_data: bytes | bytearray,
    ) -> bytes:
        cipher = self._new_cipher()
        cipher.update(bytes(additional_data))
        return cipher.decrypt_and_verify(bytes(ciphertext), bytes(tag))


@attr.s
class CypherStreamCryptodome(CypherStreamBase):
    """PyCryptodome-backed stream cipher."""

    _STREAM_CIPHER_TO_MODULE = {
        BlockCipher.CHACHA20: Crypto.Cipher.ChaCha20_Poly1305,
    }

    def __attrs_post_init__(self) -> None:
        try:
            self._is_block_cipher_supported()
            self._is_stream_cipher_supported()
        except NotImplementedError as e:
            raise ValueError(f'{e.args[0].name} is not supported by {type(self).__name__}') from e

    def _is_block_cipher_supported(self) -> None:
        if self.bulk_cipher not in self._STREAM_CIPHER_TO_MODULE:
            raise NotImplementedError(self.bulk_cipher)

    def _is_stream_cipher_supported(self) -> None:
        if self.bulk_cipher not in self._STREAM_CIPHER_TO_MODULE:
            raise NotImplementedError(self.bulk_cipher)

    def encrypt(self, plaintext: bytes | bytearray) -> bytes:
        module = self._STREAM_CIPHER_TO_MODULE[self.bulk_cipher]
        return module.new(key=self.key, nonce=self.nonce).encrypt(plaintext)

    def decrypt(self, ciphertext: bytes | bytearray) -> bytes:
        module = self._STREAM_CIPHER_TO_MODULE[self.bulk_cipher]
        return module.new(key=self.key, nonce=self.nonce).decrypt(ciphertext)

    def decrypt_and_verify(
        self,
        ciphertext: bytes | bytearray,
        tag: bytes | bytearray,
        additional_data: bytes | bytearray,
    ) -> bytes:
        module = self._STREAM_CIPHER_TO_MODULE[self.bulk_cipher]
        cipher = module.new(key=self.key, nonce=self.nonce)
        cipher.update(bytes(additional_data))
        return cipher.decrypt_and_verify(bytes(ciphertext), bytes(tag))


@attr.s
class HashBase(abc.ABC):
    """Abstract base class for cryptographic hash primitives."""

    hash_algorithm = attr.ib(validator=attr.validators.instance_of(Hash))

    def __attrs_post_init__(self) -> None:
        try:
            self._is_hash_supported()
        except NotImplementedError as e:
            raise ValueError(f'{e.args[0].name} is not supported by {type(self).__name__}') from e

    @abc.abstractmethod
    def _is_hash_supported(self) -> None:
        """Whether the configured hash algorithm is supported by this backend."""
        raise NotImplementedError()

    @abc.abstractmethod
    def digest(self, data: bytes | bytearray) -> bytes:
        """Raw digest of ``data``."""
        raise NotImplementedError()


@attr.s
class HashCryptodome(HashBase):
    """PyCryptodome-backed hash."""

    _HASH_TO_MODULE: typing.ClassVar[dict[Hash, typing.Any]] = {
        Hash.SHA2_256: Crypto.Hash.SHA256,
        Hash.SHA2_384: Crypto.Hash.SHA384,
        Hash.SHA2_512: Crypto.Hash.SHA512,
    }

    def _is_hash_supported(self) -> None:
        if self.hash_algorithm not in self._HASH_TO_MODULE:
            raise NotImplementedError(self.hash_algorithm)

    @property
    def digestmod_class(self) -> typing.Any:
        """Underlying hash module suitable for HMAC ``digestmod``."""
        return self._HASH_TO_MODULE[self.hash_algorithm]

    def digest(self, data: bytes | bytearray) -> bytes:
        return self.digestmod_class.new(bytes(data)).digest()


@attr.s
class HmacBase(abc.ABC):
    """Abstract base class for HMAC primitives."""

    mac_algorithm: MAC = attr.ib(validator=attr.validators.instance_of(MAC))

    def __attrs_post_init__(self) -> None:
        try:
            self._is_mac_supported()
        except NotImplementedError as e:
            raise ValueError(f'{e.args[0].name} is not supported by {type(self).__name__}') from e

    @abc.abstractmethod
    def _is_mac_supported(self) -> None:
        """Whether the configured MAC algorithm is supported by this backend."""
        raise NotImplementedError()

    @abc.abstractmethod
    def digest(self, key: bytes | bytearray, data: bytes | bytearray) -> bytes:
        """Keyed HMAC digest of ``data`` under ``key``."""
        raise NotImplementedError()


@attr.s
class HmacCryptodome(HmacBase):
    """PyCryptodome-backed HMAC."""

    _MAC_TO_HASH_MODULE: typing.ClassVar[dict[MAC, typing.Any]] = {
        MAC.SHA2_256: Crypto.Hash.SHA256,
        MAC.SHA2_384: Crypto.Hash.SHA384,
        MAC.SHA2_512: Crypto.Hash.SHA512,
    }

    def _is_mac_supported(self) -> None:
        if self.mac_algorithm not in self._MAC_TO_HASH_MODULE:
            raise NotImplementedError(self.mac_algorithm)

    def digest(self, key: bytes | bytearray, data: bytes | bytearray) -> bytes:
        hash_module = self._MAC_TO_HASH_MODULE[self.mac_algorithm]
        return Crypto.Hash.HMAC.new(bytes(key), bytes(data), digestmod=hash_module).digest()


class HandshakeKeyScheduleBase(abc.ABC):
    """Abstract base class for handshake key schedules."""

    @property
    @abc.abstractmethod
    def write_key_length_bytes(self) -> int:
        """Octet length of the symmetric key."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def record_initialization_vector_length_bytes(self) -> int:
        """Octet length of the IV/nonce material."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def server_write_key(self) -> bytes:
        """Symmetric key octets for the server-write direction."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def server_write_initialization_vector(self) -> bytes:
        """IV/nonce seed octets for the server-write direction."""
        raise NotImplementedError()


class AeadRecordDecryptorBase(abc.ABC):
    """Abstract base class for AEAD record decryptors."""

    @property
    @abc.abstractmethod
    def authentication_tag_length_bytes(self) -> int:
        """Octet length of the authentication tag appended after the ciphertext."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def record_initialization_vector_length_bytes(self) -> int:
        """AEAD nonce length for this decryptor."""
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes | bytearray, additional_data: bytes | bytearray) -> bytes:
        """Decrypt and verify one record; ``ciphertext`` includes the tag."""
        raise NotImplementedError()


class HandshakeDecryptorBase(AeadRecordDecryptorBase):
    """Abstract base class for HKDF key schedule and AEAD record decryption."""

    hmac_primitive: HmacBase
    hash_primitive: HashBase
    cipher_factory: typing.Callable
    _authentication_tag_length_bytes: int
    _initialization_vector: bytes
    _record_sequence_number: int = 0

    def _hkdf_extract(self, salt: bytes, input_key_material: bytes) -> bytes:
        """HKDF-Extract."""
        return self.hmac_primitive.digest(salt, input_key_material)

    def _hkdf_expand(self, pseudorandom_key: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand: expand pseudorandom key to ``length`` octets."""
        hash_digest_length = self.hmac_primitive.mac_algorithm.value.digest_size // 8
        hmac_block_count = (length + hash_digest_length - 1) // hash_digest_length
        output_key_material = b''
        previous_hmac_digest = b''
        for iteration_index in range(1, hmac_block_count + 1):
            composer = ComposerBinary()
            composer.compose_raw(previous_hmac_digest)
            composer.compose_raw(info)
            composer.compose_numeric(iteration_index, 1)
            previous_hmac_digest = self.hmac_primitive.digest(pseudorandom_key, composer.composed_bytes)
            output_key_material += previous_hmac_digest
        return output_key_material[:length]

    def _hkdf_expand_label(self, secret: bytes, label: str, context: bytes, length: int) -> bytes:
        """HKDF-Expand-Label: TLS-specific HKDF-Expand with labeled inputs."""
        composer = ComposerBinary()
        composer.compose_numeric(length, 2)
        composer.compose_bytes(b'tls13 ' + label.encode('ascii'), 1)
        composer.compose_bytes(bytes(context), 1)
        return self._hkdf_expand(secret, composer.composed_bytes, length)

    def _derive_secret(self, secret: bytes, label: str, transcript_hash_value: bytes) -> bytes:
        """Derive-Secret: specialised HKDF-Expand-Label using the transcript hash as context."""
        hash_digest_length = self.hmac_primitive.mac_algorithm.value.digest_size // 8
        return self._hkdf_expand_label(secret, label, transcript_hash_value, hash_digest_length)

    @property
    def authentication_tag_length_bytes(self) -> int:
        """Octet length of the authentication tag appended after the ciphertext."""
        return self._authentication_tag_length_bytes

    @property
    def record_initialization_vector_length_bytes(self) -> int:
        """AEAD nonce length for this decryptor."""
        return len(self._initialization_vector)

    def _make_nonce(self) -> bytes:
        """Compute the per-record nonce: write IV XOR padded sequence number."""
        iv_length = len(self._initialization_vector)
        iv_integer = int.from_bytes(self._initialization_vector, 'big')
        return (iv_integer ^ self._record_sequence_number).to_bytes(iv_length, 'big')

    def decrypt(self, ciphertext: bytes | bytearray, additional_data: bytes | bytearray) -> bytes:
        """Decrypt and verify one record, then increment the sequence number."""
        nonce = self._make_nonce()
        ciphertext = bytes(ciphertext)
        additional_data = bytes(additional_data)

        ciphertext_without_tag = ciphertext[:-self._authentication_tag_length_bytes]
        authentication_tag = ciphertext[-self._authentication_tag_length_bytes:]

        cipher = self.cipher_factory(nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext_without_tag, authentication_tag, additional_data)

        self._record_sequence_number += 1
        return plaintext
