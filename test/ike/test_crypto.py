# SPDX-License-Identifier: MPL-2.0
# pylint: disable=too-many-lines

import unittest
import unittest.mock as mock_module

import Crypto.Cipher.AES
import Crypto.Hash.HMAC
import Crypto.Hash.SHA256

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, MAC
from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1EncryptionAlgorithm,
    Ikev1HashAlgorithm,
    Ikev1ProtocolId,
    Ikev1TransformId,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IntegrityAlgorithm,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
)
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import InvalidType
from cryptoparser.common.parse import ComposerBinary
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeAuthenticationMethod,
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
    Ikev1AttributeKeyLength,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
    Ikev1PayloadTransform,
    Ikev1Situation,
)
from cryptoparser.ike.ikev2 import (
    Ikev2PayloadEncryptedAndAuthenticated,
    Ikev2PayloadKeyExchange,
    Ikev2PayloadNonce,
    Ikev2PayloadSecurityAssociation,
    Ikev2PayloadType,
    Ikev2PayloadVendorId,
    Ikev2Proposal,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
)
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.version import IsakmpProtocolVersion

from cryptolyzer.common.crypto import (
    CypherBlockCryptodome,
    CypherStreamCryptodome,
    EphemeralKeyExchangeEllipticCurveCryptodome,
    EphemeralKeyExchangeFiniteFieldCryptodome,
    GmacCryptodome,
    HmacCryptodome,
)
from cryptolyzer.ike.crypto import (
    AeadBulkCipherDescriptor,
    Ikev2IntegrityTransformDerivationParameters,
    Ikev2KeySchedule,
    Ikev2KeyScheduleCryptodome,
    Ikev2SkDecryptor,
    Ikev2SkDecryptorCryptodome,
    Ikev2SkDecryptorNonAead,
    Ikev2SkDecryptorNonAeadCryptodome,
    _NegotiatedIkev1Transforms,
    _NegotiatedIkev2Transforms,
    dhe_ephemeral_material_backend,
)
from cryptolyzer.ike.exception import Ikev2SkAuthenticationError, Ikev2TransformDerivationError


class TestIkev2KeyScheduleCryptodome(unittest.TestCase):
    """Smoke tests for the schedule + Cryptodome convenience subclass.

    RFC 7296 Appendix C / RFC 4868 §2.7 prf+ output vectors would be the
    next layer of verification; this set proves construction + slicing
    are correct under the simplest cipher choice (PRF_HMAC_SHA2_256,
    AEAD AES-128-GCM with 16-octet keys, 0-octet integrity)."""

    def setUp(self):
        self.prf = Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256
        self.shared_secret = bytes(range(32))            # 32-octet g^ir
        self.nonce_initiator = bytes(range(16))          # Ni
        self.nonce_responder = bytes(range(16, 32))      # Nr
        self.spi_initiator = 0xdeadbeefcafebabe
        self.spi_responder = 0xfeedface12345678

    def _build(self, encryption_key_length_bytes=16, integrity_key_length_bytes=0):
        return Ikev2KeyScheduleCryptodome(
            prf=self.prf,
            shared_secret=self.shared_secret,
            nonce_initiator=self.nonce_initiator,
            nonce_responder=self.nonce_responder,
            spi_initiator=self.spi_initiator,
            spi_responder=self.spi_responder,
            encryption_key_length_bytes=encryption_key_length_bytes,
            integrity_key_length_bytes=integrity_key_length_bytes,
        )

    def test_outputs_have_expected_lengths_for_aead_transform(self):
        schedule = self._build(encryption_key_length_bytes=16, integrity_key_length_bytes=0)
        outputs = schedule.outputs

        prf_key_length = 32  # SHA-256
        self.assertEqual(len(outputs.sk_d), prf_key_length)
        self.assertEqual(len(outputs.sk_ai), 0)
        self.assertEqual(len(outputs.sk_ar), 0)
        self.assertEqual(len(outputs.sk_ei), 16)
        self.assertEqual(len(outputs.sk_er), 16)
        self.assertEqual(len(outputs.sk_pi), prf_key_length)
        self.assertEqual(len(outputs.sk_pr), prf_key_length)

    def test_outputs_have_expected_lengths_for_non_aead_transform(self):
        schedule = self._build(encryption_key_length_bytes=32, integrity_key_length_bytes=20)
        outputs = schedule.outputs

        self.assertEqual(len(outputs.sk_ai), 20)
        self.assertEqual(len(outputs.sk_ar), 20)
        self.assertEqual(len(outputs.sk_ei), 32)
        self.assertEqual(len(outputs.sk_er), 32)

    def test_outputs_are_deterministic_for_same_inputs(self):
        outputs_one = self._build().outputs
        outputs_two = self._build().outputs
        self.assertEqual(outputs_one, outputs_two)

    def test_outputs_change_when_shared_secret_changes(self):
        first = self._build().outputs
        original_secret = self.shared_secret
        try:
            self.shared_secret = bytes(reversed(original_secret))
            second = self._build().outputs
        finally:
            self.shared_secret = original_secret

        self.assertNotEqual(first.sk_d, second.sk_d)
        self.assertNotEqual(first.sk_er, second.sk_er)

    def test_skeyseed_matches_prf_definition(self):
        schedule = self._build()
        expected = HmacCryptodome(mac_algorithm=MAC.SHA2_256).digest(
            self.nonce_initiator + self.nonce_responder,
            self.shared_secret,
        )
        self.assertEqual(schedule.skeyseed, expected)

    def test_cryptodome_subclass_auto_wires_hmac_primitive(self):
        schedule = self._build()
        self.assertIsInstance(schedule.hmac_primitive, HmacCryptodome)
        self.assertEqual(schedule.hmac_primitive.mac_algorithm, MAC.SHA2_256)


class TestIkev2KeySchedulePrfPlus(unittest.TestCase):
    """RFC 7296 §2.13 prf+ recurrence verification."""

    def setUp(self):
        self.hmac_primitive = HmacCryptodome(mac_algorithm=MAC.SHA2_256)
        self.schedule = Ikev2KeySchedule(
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            shared_secret=b'\x00' * 32,
            nonce_initiator=b'\x00' * 16,
            nonce_responder=b'\x00' * 16,
            spi_initiator=0,
            spi_responder=0,
            encryption_key_length_bytes=0,
            integrity_key_length_bytes=0,
            hmac_primitive=self.hmac_primitive,
        )

    def test_prf_plus_first_block_matches_prf_with_index_one(self):
        key = b'\x42' * 32
        seed = b'\x01\x02\x03'
        output = self.schedule.prf_plus(key, seed, 32)

        expected_t1 = self.hmac_primitive.digest(key, seed + bytes([1]))
        self.assertEqual(output, expected_t1)

    def test_prf_plus_concatenates_blocks_until_length_reached(self):
        key = b'\x42' * 32
        seed = b'\xff' * 4
        # 50 bytes needs two SHA-256 (32-byte) blocks; result is first 50 octets.
        output = self.schedule.prf_plus(key, seed, 50)

        t1 = self.hmac_primitive.digest(key, seed + bytes([1]))
        t2 = self.hmac_primitive.digest(key, t1 + seed + bytes([2]))
        self.assertEqual(output, (t1 + t2)[:50])


class TestEphemeralKeyExchangeBackendCryptodome(unittest.TestCase):
    """Covers the module-level singleton ``dhe_ephemeral_material_backend``.

    The name + shape mirror :data:`cryptolyzer.tls.crypto.dhe_ephemeral_material_backend`
    so a `cryptolyzer.<protocol>.crypto.dhe_ephemeral_material_backend` lookup
    pattern works across both protocols."""

    def test_supported_dh_groups_returns_at_least_the_modern_set(self):
        supported = dhe_ephemeral_material_backend.supported_dh_groups()
        self.assertIn(Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, supported)
        self.assertIn(Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT, supported)

    def test_create_ephemeral_material_returns_ec_backend_for_ecp_groups(self):
        ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        self.assertIsInstance(ephemeral, EphemeralKeyExchangeEllipticCurveCryptodome)
        self.assertGreater(len(ephemeral.public_key_bytes), 0)

    def test_create_ephemeral_material_returns_ff_backend_for_modp_groups(self):
        ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        self.assertIsInstance(ephemeral, EphemeralKeyExchangeFiniteFieldCryptodome)
        self.assertEqual(len(ephemeral.public_key_bytes), 2048 // 8)

    def test_create_ephemeral_material_rejects_unrecognised_key_parameter(self):
        """``key_parameter`` is constrained to the four parameter registries
        by the cryptodatahub enum; the ``str`` case is the "unsupported" fallthrough
        path, exercised here via a mocked dh_group."""
        bogus_dh_group = mock_module.Mock()
        bogus_dh_group.value.key_parameter = 'UNRECOGNISED_PLACEHOLDER'

        with self.assertRaises(NotImplementedError):
            dhe_ephemeral_material_backend.create_ephemeral_material(bogus_dh_group)

    def test_build_ke_payload_pairs_payload_with_ephemeral_instance(self):
        payload, ephemeral = dhe_ephemeral_material_backend.build_ke_payload(
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        self.assertIsInstance(payload, Ikev2PayloadKeyExchange)
        self.assertEqual(payload.dh_group, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT)
        # RFC 5903 §7: ECP KE wire form is raw x||y (no SEC1 0x04 prefix).
        self.assertEqual(bytes(payload.key_exchange_data), ephemeral.public_key_bytes[1:])
        self.assertEqual(len(payload.key_exchange_data), 64)

    def test_wire_bytes_passthrough_for_modp_group(self):
        dh_group = Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT
        ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
        self.assertEqual(
            dhe_ephemeral_material_backend.key_exchange_wire_bytes(dh_group, ephemeral), ephemeral.public_key_bytes,
        )

    def test_peer_key_exchange_from_wire_passthrough_for_modp_group(self):
        dh_group = Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT
        wire = b'\xab' * 256
        self.assertEqual(dhe_ephemeral_material_backend.peer_key_exchange_from_wire(dh_group, wire), wire)

    def test_supported_dh_groups_skips_groups_whose_factory_raises(self):
        """Defensive ``try/except`` in ``supported_dh_groups`` is exercised
        by patching ``create_ephemeral_material`` so one known-supported
        preferred-order entry raises."""
        backend_cls = type(dhe_ephemeral_material_backend)
        target_group = Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT
        original = backend_cls.create_ephemeral_material

        def stub(dh_group):
            if dh_group is target_group:
                raise NotImplementedError(dh_group)
            return original(dh_group)

        # ``supported_dh_groups`` caches its result (MODP-8192 keygen is too
        # slow to run per-analyzer-call); ``mock.patch.object`` on both cache
        # slots forces a fresh filter pass so the stubbed
        # ``create_ephemeral_material`` is exercised, and auto-restores
        # the original cache values when the ``with`` block exits.
        with mock_module.patch.object(backend_cls, '_supported_ikev2_dh_groups_cache', None), \
                mock_module.patch.object(backend_cls, '_supported_ikev1_dh_groups_cache', None), \
                mock_module.patch.object(
                    backend_cls, 'create_ephemeral_material', staticmethod(stub),
                ):
            supported = backend_cls.supported_dh_groups()

        self.assertNotIn(target_group, supported)
        self.assertIn(Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT, supported)

    def test_clear_supported_dh_groups_cache_forces_filter_rerun(self):
        # Behavioral test for ``clear_supported_dh_groups_cache``: verify
        # that after the reset the next ``supported_dh_groups()`` call
        # re-invokes the underlying filter (rather than serving a cached
        # tuple). Uses a spy on ``create_ephemeral_material`` — the
        # filter's inner loop calls it once per candidate group. Avoids
        # touching the ``_supported_..._cache`` internals directly.
        backend_cls = type(dhe_ephemeral_material_backend)
        # Warm both caches so subsequent supported_dh_groups() calls
        # short-circuit unless the reset actually cleared them.
        backend_cls.supported_dh_groups()
        backend_cls.supported_ikev1_dh_groups()
        backend_cls.clear_supported_dh_groups_cache()
        original = backend_cls.create_ephemeral_material
        call_count = 0

        def counting_stub(dh_group):
            nonlocal call_count
            call_count += 1
            return original(dh_group)

        with mock_module.patch.object(
            backend_cls, 'create_ephemeral_material', staticmethod(counting_stub),
        ):
            backend_cls.supported_dh_groups()
            first_pass = call_count
            backend_cls.supported_ikev1_dh_groups()
        # Both caches were populated (first_pass > 0 for ikev2; the
        # second call added ikev1 entries on top).
        self.assertGreater(first_pass, 0)
        self.assertGreater(call_count, first_pass)


class TestIkev2SkDecryptorCryptodome(unittest.TestCase):
    """Round-trip + lookup-table verification for the SK envelope decryptor.

    The IKEv2 SK envelope is the analyzer's only mechanism for extracting
    the responder's certificate (RFC 7296 §3.14, RFC 5282 §3-§5). These
    tests confirm the decryptor:
    1. accepts SK_er sized to ``write_key + salt`` and rejects mismatches,
    2. round-trips an AEAD encrypt/decrypt pair against
       :class:`CypherBlockCryptodome`,
    3. computes the RFC 5282 §5.1 additional data as documented."""

    _DESCRIPTOR = AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
    )
    _ON_WIRE_IV = b'\x42' * 8
    _PLAINTEXT = b'inner SK payloads + padding + pad length'
    _ADDITIONAL_DATA = b'\xaa' * 32

    def setUp(self):
        self._parameters = Ikev2SkDecryptor.get_encryption_transform_derivation_parameters(
            self._DESCRIPTOR,
        )
        self._write_key = bytes(range(self._parameters.write_key_length_bytes))
        self._salt = bytes(range(self._parameters.salt_length_bytes))
        self._sk_er = self._write_key + self._salt

    def _encrypt(self):
        encryptor = Crypto.Cipher.AES.new(
            self._write_key, Crypto.Cipher.AES.MODE_GCM, nonce=self._salt + self._ON_WIRE_IV,
        )
        encryptor.update(self._ADDITIONAL_DATA)
        ciphertext, tag = encryptor.encrypt_and_digest(self._PLAINTEXT)
        return ciphertext + tag

    def test_get_parameters_lookup_returns_documented_sizes(self):
        self.assertEqual(self._parameters.write_key_length_bytes, 32)
        self.assertEqual(self._parameters.on_wire_initialization_vector_length_bytes, 8)
        self.assertEqual(self._parameters.salt_length_bytes, 4)
        self.assertEqual(self._parameters.authentication_tag_length_bytes, 16)

    def test_get_parameters_lookup_returns_documented_sizes_for_aes_gcm_shorter_tags(self):
        # RFC 5282 §7.2: GCM-8 (tag 8) and GCM-12 (tag 12) share the
        # GCM-16 sizing (8-octet on-wire IV + 4-octet salt); only the
        # tag length differs per variant.
        for bulk_cipher, expected_key_length_bytes in (
            (BlockCipher.AES_128, 16),
            (BlockCipher.AES_192, 24),
            (BlockCipher.AES_256, 32),
        ):
            for gcm_mode, expected_tag_length_bytes in (
                (BlockCipherMode.GCM_8, 8),
                (BlockCipherMode.GCM_12, 12),
            ):
                descriptor = AeadBulkCipherDescriptor(
                    bulk_cipher=bulk_cipher, block_cipher_mode=gcm_mode,
                )
                parameters = Ikev2SkDecryptor.get_encryption_transform_derivation_parameters(
                    descriptor,
                )
                self.assertEqual(parameters.write_key_length_bytes, expected_key_length_bytes)
                self.assertEqual(parameters.on_wire_initialization_vector_length_bytes, 8)
                self.assertEqual(parameters.salt_length_bytes, 4)
                self.assertEqual(parameters.authentication_tag_length_bytes, expected_tag_length_bytes)

    def test_get_parameters_lookup_returns_documented_sizes_for_aes_ccm(self):
        # RFC 4309 §4: CCM-8 (tag 8), CCM-12 (tag 12), CCM-16 (tag 16)
        # at 128/192/256-bit keys. 8-octet on-wire IV, 3-octet salt.
        for bulk_cipher, expected_key_length_bytes in (
            (BlockCipher.AES_128, 16),
            (BlockCipher.AES_192, 24),
            (BlockCipher.AES_256, 32),
        ):
            for ccm_mode, expected_tag_length_bytes in (
                (BlockCipherMode.CCM_8, 8),
                (BlockCipherMode.CCM_12, 12),
                (BlockCipherMode.CCM_16, 16),
            ):
                descriptor = AeadBulkCipherDescriptor(
                    bulk_cipher=bulk_cipher, block_cipher_mode=ccm_mode,
                )
                parameters = Ikev2SkDecryptor.get_encryption_transform_derivation_parameters(
                    descriptor,
                )
                self.assertEqual(parameters.write_key_length_bytes, expected_key_length_bytes)
                self.assertEqual(parameters.on_wire_initialization_vector_length_bytes, 8)
                self.assertEqual(parameters.salt_length_bytes, 3)
                self.assertEqual(parameters.authentication_tag_length_bytes, expected_tag_length_bytes)

    def test_get_parameters_lookup_rejects_unknown_transform(self):
        bogus = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CCM,
        )
        with self.assertRaises(ValueError):
            Ikev2SkDecryptor.get_encryption_transform_derivation_parameters(bogus)

    def test_construct_rejects_sk_er_of_wrong_length(self):
        with self.assertRaises(ValueError):
            Ikev2SkDecryptorCryptodome(
                encryption_transform=self._DESCRIPTOR,
                sk_er=self._write_key,  # missing 4-byte salt
            )

    def test_encrypt_round_trips_through_decrypt(self):
        """encrypt(plaintext) ↔ decrypt(envelope) must commute so the
        EAP-mode probe driver can build outgoing SK envelopes and decrypt
        incoming ones with the same key material."""
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        envelope = decryptor.encrypt(self._PLAINTEXT, self._ADDITIONAL_DATA, on_wire_iv=self._ON_WIRE_IV)
        recovered = decryptor.decrypt(envelope, self._ADDITIONAL_DATA)
        self.assertEqual(recovered, self._PLAINTEXT)

    def test_encrypt_generates_random_iv_when_none_passed(self):
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        envelope_one = decryptor.encrypt(self._PLAINTEXT, self._ADDITIONAL_DATA)
        envelope_two = decryptor.encrypt(self._PLAINTEXT, self._ADDITIONAL_DATA)
        self.assertNotEqual(envelope_one[:8], envelope_two[:8])

    def test_encrypt_rejects_iv_of_wrong_length(self):
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        with self.assertRaises(ValueError):
            decryptor.encrypt(self._PLAINTEXT, self._ADDITIONAL_DATA, on_wire_iv=b'\x00' * 4)

    def test_decrypt_round_trips_aead_payload(self):
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        ciphertext_with_tag = self._encrypt()
        on_wire_envelope = self._ON_WIRE_IV + ciphertext_with_tag

        recovered = decryptor.decrypt(on_wire_envelope, self._ADDITIONAL_DATA)
        self.assertEqual(recovered, self._PLAINTEXT)

    def test_decrypt_rejects_short_body(self):
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        with self.assertRaises(ValueError):
            decryptor.decrypt(b'\x00' * 10, self._ADDITIONAL_DATA)

    def test_decryptor_exposes_nonce_and_tag_length(self):
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        # nonce = salt (4) + on-wire IV (8) = 12.
        self.assertEqual(decryptor.record_initialization_vector_length_bytes, 12)
        self.assertEqual(decryptor.on_wire_initialization_vector_length_bytes, 8)
        self.assertEqual(decryptor.authentication_tag_length_bytes, 16)

    def test_chacha20_poly1305_descriptor_uses_stream_backend(self):
        chacha_descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.CHACHA20, block_cipher_mode=None,
        )
        chacha_parameters = Ikev2SkDecryptor.get_encryption_transform_derivation_parameters(
            chacha_descriptor,
        )
        sk_er = bytes(range(chacha_parameters.write_key_length_bytes + chacha_parameters.salt_length_bytes))
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=chacha_descriptor, sk_er=sk_er,
        )
        # cipher_factory ought to materialise a stream cipher for ChaCha20.
        sample = decryptor.cipher_factory(b'\x00' * 12)
        self.assertIsInstance(sample, CypherStreamCryptodome)

    def test_aes_gcm_descriptor_uses_block_backend(self):
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        sample = decryptor.cipher_factory(b'\x00' * 12)
        self.assertIsInstance(sample, CypherBlockCryptodome)

    def test_split_padded_plaintext_strips_pad_length_and_padding(self):
        inner = b'payload' + b'\x00\x00\x00' + b'\x03'  # 3 octets of padding + pad_length=3
        self.assertEqual(Ikev2SkDecryptor.split_padded_plaintext(inner), b'payload')

    def test_split_padded_plaintext_zero_padding(self):
        inner = b'payload' + b'\x00'  # no padding, pad_length=0
        self.assertEqual(Ikev2SkDecryptor.split_padded_plaintext(inner), b'payload')

    def test_split_padded_plaintext_rejects_empty(self):
        with self.assertRaises(ValueError):
            Ikev2SkDecryptor.split_padded_plaintext(b'')

    def test_split_padded_plaintext_rejects_excessive_pad_length(self):
        with self.assertRaises(ValueError):
            Ikev2SkDecryptor.split_padded_plaintext(b'\x09')  # claims 9 octets of padding in a 1-octet body

    def test_compute_additional_data_concatenates_header_unencrypted_and_sk_prefix(self):
        ike_header = b'\xaa' * 28
        unencrypted = b'\xbb' * 16
        sk_header = b'\x21\x00\x00\x40\xff\xff'  # only first 4 octets used
        aad = Ikev2SkDecryptor.compute_additional_data(ike_header, unencrypted, sk_header)
        self.assertEqual(aad, ike_header + unencrypted + sk_header[:4])

    def test_compute_additional_data_rejects_short_sk_header(self):
        with self.assertRaises(ValueError):
            Ikev2SkDecryptor.compute_additional_data(b'', b'', b'\x21\x00')


class TestIkev2SkDecryptorCryptodomeShortAeadTag(unittest.TestCase):
    """RFC 5282 §7.2 shorter-tag AEAD (AES-GCM-8): cipher_factory must
    thread the transform's tag length via ``mac_len=`` so the envelope
    tag matches the wire size (the default GCM tag is 16 octets)."""

    def test_aes_gcm_8_round_trip_matches_pycryptodome_short_tag(self):
        plaintext = b'inner SK payloads + padding + pad length'
        additional_data = b'\xaa' * 32
        on_wire_iv = b'\x42' * 8
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.GCM_8,
        )
        parameters = Ikev2SkDecryptor.get_encryption_transform_derivation_parameters(descriptor)
        write_key = bytes(range(parameters.write_key_length_bytes))
        salt = bytes(range(parameters.salt_length_bytes))
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=descriptor, sk_er=write_key + salt,
        )
        envelope = decryptor.encrypt(plaintext, additional_data, on_wire_iv=on_wire_iv)
        self.assertEqual(decryptor.authentication_tag_length_bytes, 8)
        self.assertEqual(len(envelope), len(on_wire_iv) + len(plaintext) + 8)

        reference_encryptor = Crypto.Cipher.AES.new(
            write_key, Crypto.Cipher.AES.MODE_GCM,
            nonce=salt + on_wire_iv, mac_len=8,
        )
        reference_encryptor.update(additional_data)
        _, reference_tag = reference_encryptor.encrypt_and_digest(plaintext)
        self.assertEqual(envelope[-8:], reference_tag)
        self.assertEqual(decryptor.decrypt(envelope, additional_data), plaintext)


class TestIkev2SkDecryptorNonAeadCryptodome(unittest.TestCase):
    """Non-AEAD SK envelope (CBC + HMAC) decryptor for IKEv2 servers that
    negotiate legacy encryption transforms.

    Per RFC 7296 §3.14 + RFC 4868: the responder picks the encryption
    + integrity transform pair from the proposed SA, so the analyzer
    must cover non-AEAD or it will return empty against CBC-only
    deployments."""

    _ENCRYPTION_TRANSFORM = AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
    )
    _INTEGRITY_TRANSFORM = Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128
    _ON_WIRE_IV = b'\x42' * 16

    def setUp(self):
        encryption_parameters = Ikev2SkDecryptorNonAead.get_encryption_transform_derivation_parameters(
            self._ENCRYPTION_TRANSFORM,
        )
        self._write_key = bytes(range(encryption_parameters.write_key_length_bytes))
        # 32 bytes of SK_ar (HMAC-SHA-256 expects up-to-block-size keys).
        self._sk_ar = bytes(range(32, 64))

    def _build_decryptor(self):
        return Ikev2SkDecryptorNonAeadCryptodome(
            encryption_transform=self._ENCRYPTION_TRANSFORM,
            integrity_transform=self._INTEGRITY_TRANSFORM,
            sk_er=self._write_key,
            sk_ar=self._sk_ar,
        )

    def _encrypt(self, plaintext: bytes) -> bytes:
        encryptor = Crypto.Cipher.AES.new(
            self._write_key, Crypto.Cipher.AES.MODE_CBC, iv=self._ON_WIRE_IV,
        )
        return encryptor.encrypt(plaintext)

    def test_get_parameters_returns_documented_sizes(self):
        encryption_parameters = Ikev2SkDecryptorNonAead.get_encryption_transform_derivation_parameters(
            self._ENCRYPTION_TRANSFORM,
        )
        integrity_parameters = Ikev2SkDecryptorNonAead.get_integrity_transform_derivation_parameters(
            self._INTEGRITY_TRANSFORM,
        )
        self.assertEqual(encryption_parameters.write_key_length_bytes, 16)
        self.assertEqual(encryption_parameters.on_wire_initialization_vector_length_bytes, 16)
        self.assertEqual(encryption_parameters.salt_length_bytes, 0)
        self.assertEqual(integrity_parameters.integrity_check_value_length_bytes, 16)
        self.assertEqual(integrity_parameters.mac_algorithm, MAC.SHA2_256)

    def test_get_parameters_returns_documented_sizes_for_triple_des_cbc(self):
        # RFC 7296 §3.3.5 ENCR_3DES (transform ID 3): fixed 24-octet
        # key, 8-octet block size = 8-octet on-wire IV, no salt, no tag.
        triple_des_descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.TRIPLE_DES_168, block_cipher_mode=BlockCipherMode.CBC,
        )
        encryption_parameters = Ikev2SkDecryptorNonAead.get_encryption_transform_derivation_parameters(
            triple_des_descriptor,
        )
        self.assertEqual(encryption_parameters.write_key_length_bytes, 24)
        self.assertEqual(encryption_parameters.on_wire_initialization_vector_length_bytes, 8)
        self.assertEqual(encryption_parameters.salt_length_bytes, 0)
        self.assertEqual(encryption_parameters.authentication_tag_length_bytes, 0)

    def test_get_parameters_rejects_unknown_encryption_transform(self):
        bogus = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.GCM,
        )
        with self.assertRaises(ValueError):
            Ikev2SkDecryptorNonAead.get_encryption_transform_derivation_parameters(bogus)

    def test_get_parameters_rejects_unknown_integrity_transform(self):
        # AUTH_AES_XCBC_96 (RFC 3566) requires an AES-XCBC-MAC primitive
        # PyCryptodome does not ship — remains unsupported by
        # ``Ikev2SkDecryptorNonAead._INTEGRITY_PROPERTIES``.
        with self.assertRaises(ValueError):
            Ikev2SkDecryptorNonAead.get_integrity_transform_derivation_parameters(
                Ikev2IntegrityAlgorithm.AUTH_AES_XCBC_96,
            )

    def test_construct_rejects_sk_er_of_wrong_length(self):
        with self.assertRaises(ValueError):
            Ikev2SkDecryptorNonAeadCryptodome(
                encryption_transform=self._ENCRYPTION_TRANSFORM,
                integrity_transform=self._INTEGRITY_TRANSFORM,
                sk_er=self._write_key[:8],  # too short
                sk_ar=self._sk_ar,
            )

    @staticmethod
    def _icv(decryptor, envelope):
        """Compute the correct ICV for ``envelope`` via ``decryptor``
        (used as the signed octets in these unit tests to keep the
        fixture minimal; real callers pass ``compute_signed_octets(...)``)."""
        return decryptor.compute_integrity_check_value(envelope)

    def test_encrypt_round_trips_through_decrypt(self):
        """non-AEAD encrypt/decrypt round-trip for the CBC probe path."""
        plaintext_padded = b'inner SK payloads + padding xyz\x00'  # 32 bytes
        decryptor = self._build_decryptor()
        envelope = decryptor.encrypt(plaintext_padded, on_wire_iv=self._ON_WIRE_IV)
        icv = self._icv(decryptor, envelope)
        recovered = decryptor.decrypt(envelope, icv, envelope)
        self.assertEqual(recovered, plaintext_padded)

    def test_encrypt_rejects_iv_of_wrong_length(self):
        decryptor = self._build_decryptor()
        with self.assertRaises(ValueError):
            decryptor.encrypt(b'\x00' * 32, on_wire_iv=b'\x00' * 4)

    def test_encrypt_generates_random_iv_when_none_passed(self):
        decryptor = self._build_decryptor()
        envelope_one = decryptor.encrypt(b'\x00' * 32)
        envelope_two = decryptor.encrypt(b'\x00' * 32)
        self.assertNotEqual(envelope_one[:16], envelope_two[:16])

    def test_decrypt_round_trips_cbc_payload(self):
        # Plaintext is padded to AES block size (16) so CBC has no surprise.
        plaintext = b'inner SK payloads + padding xyz'  # 31 bytes
        plaintext_padded = plaintext + b'\x00'  # 32 bytes
        ciphertext = self._encrypt(plaintext_padded)
        envelope = self._ON_WIRE_IV + ciphertext

        decryptor = self._build_decryptor()
        icv = self._icv(decryptor, envelope)
        recovered = decryptor.decrypt(envelope, icv, envelope)
        self.assertEqual(recovered, plaintext_padded)

    def test_decrypt_rejects_icv_of_wrong_length(self):
        decryptor = self._build_decryptor()
        with self.assertRaises(ValueError):
            decryptor.decrypt(self._ON_WIRE_IV + b'\x00' * 16, b'\x00' * 8, b'')

    def test_decrypt_rejects_tampered_icv(self):
        decryptor = self._build_decryptor()
        envelope = decryptor.encrypt(b'\x00' * 32, on_wire_iv=self._ON_WIRE_IV)
        with self.assertRaises(ValueError):
            decryptor.decrypt(envelope, b'\x00' * 16, envelope)

    def test_decrypt_rejects_short_ciphertext(self):
        decryptor = self._build_decryptor()
        with self.assertRaises(ValueError):
            decryptor.decrypt(b'\x00' * 4, b'\x00' * 16, b'')

    def test_decryptor_exposes_iv_and_icv_length(self):
        decryptor = self._build_decryptor()
        self.assertEqual(decryptor.record_initialization_vector_length_bytes, 16)
        self.assertEqual(decryptor.integrity_check_value_length_bytes, 16)

    def test_compute_signed_octets_concatenates_in_order(self):
        ike_header = b'\xaa' * 28
        unencrypted = b'\xbb' * 8
        sk_header = b'\x00\x00\x00\x20'
        body = b'\xcc' * 32

        signed = Ikev2SkDecryptorNonAead.compute_signed_octets(
            ike_header, unencrypted, sk_header, body,
        )
        self.assertEqual(signed, ike_header + unencrypted + sk_header + body)

    def test_verify_integrity_check_value_round_trip(self):
        decryptor = self._build_decryptor()
        signed_octets = b'arbitrary signed octets for HMAC'

        hmac_obj = Crypto.Hash.HMAC.new(
            self._sk_ar, signed_octets, digestmod=Crypto.Hash.SHA256,
        )
        full = hmac_obj.digest()
        truncated = full[:16]

        # Round-trip should not raise.
        decryptor.verify_integrity_check_value(signed_octets, truncated)

    def test_verify_integrity_check_value_detects_tampering(self):
        decryptor = self._build_decryptor()
        with self.assertRaises(ValueError):
            decryptor.verify_integrity_check_value(b'signed octets', b'\x00' * 16)

    def test_compute_integrity_check_value_matches_hmac_truncation(self):
        decryptor = self._build_decryptor()
        signed_octets = b'arbitrary signed octets for HMAC'
        expected_full = Crypto.Hash.HMAC.new(
            self._sk_ar, signed_octets, digestmod=Crypto.Hash.SHA256,
        ).digest()

        computed = decryptor.compute_integrity_check_value(signed_octets)
        self.assertEqual(computed, expected_full[:16])

    def test_compute_integrity_check_value_round_trips_through_verify(self):
        decryptor = self._build_decryptor()
        signed_octets = b'\x11\x22\x33\x44' * 8

        icv = decryptor.compute_integrity_check_value(signed_octets)
        # verify_integrity_check_value must accept an ICV produced by
        # compute_integrity_check_value on the same signed_octets.
        decryptor.verify_integrity_check_value(signed_octets, icv)


class TestIkev2SkDecryptorNonAeadCryptodomeCtr(unittest.TestCase):
    """AES-CTR (RFC 5930) non-AEAD SK envelope entries.

    CTR is the first :class:`Ikev2SkDecryptorNonAead` entry with a
    non-zero salt, so these tests specifically exercise the SK_er
    salt-splicing path added when CTR became a first-class transform."""

    _INTEGRITY_TRANSFORM = Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128

    def setUp(self):
        # 32 bytes of SK_ar (HMAC-SHA-256 expects up-to-block-size keys).
        self._sk_ar = bytes(range(32, 64))

    def test_get_parameters_returns_documented_sizes(self):
        # RFC 5930 AES-CTR (transform ID 13): 128/192/256-bit key +
        # 4-octet salt (from SK_er tail), 8-octet on-wire IV, no ICV
        # tag (integrity comes from the paired HMAC transform).
        for bulk_cipher, expected_key_length_bytes in (
            (BlockCipher.AES_128, 16),
            (BlockCipher.AES_192, 24),
            (BlockCipher.AES_256, 32),
        ):
            descriptor = AeadBulkCipherDescriptor(
                bulk_cipher=bulk_cipher, block_cipher_mode=BlockCipherMode.CTR,
            )
            encryption_parameters = Ikev2SkDecryptorNonAead.get_encryption_transform_derivation_parameters(
                descriptor,
            )
            self.assertEqual(encryption_parameters.write_key_length_bytes, expected_key_length_bytes)
            self.assertEqual(encryption_parameters.on_wire_initialization_vector_length_bytes, 8)
            self.assertEqual(encryption_parameters.salt_length_bytes, 4)
            self.assertEqual(encryption_parameters.authentication_tag_length_bytes, 0)

    def test_construct_accepts_sk_er_with_salt(self):
        # SK_er for AES-128-CTR is 16 (write key) + 4 (salt) = 20 octets;
        # the post-init length check must accept the salt tail and store
        # it separately from the write key. This exercises the salt
        # splicing added when non-AEAD CTR became a first-class entry.
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CTR,
        )
        sk_er = bytes(range(20))  # 16 write key + 4 salt
        decryptor = Ikev2SkDecryptorNonAeadCryptodome(
            encryption_transform=descriptor,
            integrity_transform=self._INTEGRITY_TRANSFORM,
            sk_er=sk_er,
            sk_ar=self._sk_ar,
        )
        # For CTR the on-wire IV length is 8 (salt is embedded in the
        # cipher nonce, not the wire representation).
        self.assertEqual(decryptor.record_initialization_vector_length_bytes, 8)

    def test_encrypt_round_trips_through_decrypt_ctr(self):
        # RFC 5930 §3: CTR nonce = salt (4 octets from SK_er tail) |
        # on-wire IV (8 octets); block counter is the trailing 4 octets
        # and starts at 1. The non-AEAD envelope pairs CTR encryption
        # with the HMAC integrity transform for the ICV.
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CTR,
        )
        sk_er = bytes(range(20))  # 16 write key + 4 salt
        decryptor = Ikev2SkDecryptorNonAeadCryptodome(
            encryption_transform=descriptor,
            integrity_transform=self._INTEGRITY_TRANSFORM,
            sk_er=sk_er,
            sk_ar=self._sk_ar,
        )
        plaintext_padded = b'inner SK payloads for CTR round-trip' + b'\x00' * 12
        on_wire_iv = b'\x42' * 8
        envelope = decryptor.encrypt(plaintext_padded, on_wire_iv=on_wire_iv)
        icv = Crypto.Hash.HMAC.new(
            self._sk_ar, envelope, digestmod=Crypto.Hash.SHA256,
        ).digest()[:16]
        recovered = decryptor.decrypt(envelope, icv, envelope)
        self.assertEqual(recovered, plaintext_padded)

    def test_construct_rejects_sk_er_missing_salt(self):
        # Passing an SK_er sized to only the write key (no salt tail)
        # must fail the post-init length check now that CTR entries
        # declare salt_length_bytes=4.
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CTR,
        )
        with self.assertRaises(ValueError):
            Ikev2SkDecryptorNonAeadCryptodome(
                encryption_transform=descriptor,
                integrity_transform=self._INTEGRITY_TRANSFORM,
                sk_er=bytes(range(16)),  # missing 4-octet salt
                sk_ar=self._sk_ar,
            )


class TestIkev2SkDecryptorNonAeadCryptodomeGmac(unittest.TestCase):
    """AES-GMAC (RFC 4543) non-AEAD SK envelope integrity — the sibling
    integrity transform to the HMAC / CMAC entries covered by
    :class:`TestIkev2SkDecryptorNonAeadCryptodome`. RFC 4543 §3.1 pins
    GMAC integrity to encryption transforms whose on-wire IV is 8
    octets, so these tests pair it with AES-CTR (RFC 5930)."""

    _ENCRYPTION_TRANSFORM = AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CTR,
    )
    _INTEGRITY_TRANSFORM = Ikev2IntegrityAlgorithm.AUTH_AES_128_GMAC

    def setUp(self):
        self._sk_er = bytes(range(20))  # 16-octet write key + 4-octet CTR salt
        self._sk_ar = bytes(range(20, 40))  # 16-octet AES key + 4-octet GMAC salt

    def _build_decryptor(self, sk_ar=None):
        return Ikev2SkDecryptorNonAeadCryptodome(
            encryption_transform=self._ENCRYPTION_TRANSFORM,
            integrity_transform=self._INTEGRITY_TRANSFORM,
            sk_er=self._sk_er,
            sk_ar=self._sk_ar if sk_ar is None else sk_ar,
        )

    def test_construct_accepts_sk_ar_sized_to_key_plus_salt(self):
        decryptor = self._build_decryptor()
        self.assertEqual(decryptor.record_initialization_vector_length_bytes, 8)

    def test_construct_rejects_sk_ar_of_wrong_length(self):
        with self.assertRaises(ValueError):
            self._build_decryptor(sk_ar=self._sk_ar[:10])

    def test_compute_integrity_check_value_requires_wire_iv(self):
        decryptor = self._build_decryptor()
        with self.assertRaises(ValueError) as ctx:
            decryptor.compute_integrity_check_value(b'signed octets')
        self.assertEqual(str(ctx.exception), 'AES-GMAC integrity requires wire_iv')

    def test_compute_integrity_check_value_rejects_wrong_wire_iv_length(self):
        # A 16-octet wire_iv is what AES-CBC encryption would supply —
        # GMAC integrity only pairs with an 8-octet on-wire IV
        # (RFC 4543 §3.1); refuse rather than compute a wrong tag.
        # Raises :class:`Ikev2TransformDerivationError` (a ValueError
        # subclass) so the pubkey probe driver's existing catch handles
        # it as "responder negotiated a transform combination we cannot
        # decrypt" — not a fatal analyzer-session abort.
        decryptor = self._build_decryptor()
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            decryptor.compute_integrity_check_value(b'signed octets', wire_iv=b'\x00' * 16)
        self.assertIn('requires an 8-octet wire_iv', str(ctx.exception))

    def test_compute_integrity_check_value_matches_gmac_cryptodome(self):
        decryptor = self._build_decryptor()
        signed_octets = b'arbitrary signed octets for GMAC integrity'
        wire_iv = b'\x42' * 8

        result = decryptor.compute_integrity_check_value(signed_octets, wire_iv=wire_iv)

        aes_key = self._sk_ar[:16]
        salt = self._sk_ar[16:]
        reference_tag = GmacCryptodome(block_cipher=BlockCipher.AES_128).digest(
            aes_key, salt + wire_iv, signed_octets,
        )
        self.assertEqual(result, reference_tag[:16])

    def test_verify_integrity_check_value_round_trip(self):
        decryptor = self._build_decryptor()
        signed_octets = b'round trip signed octets for GMAC'
        wire_iv = b'\x24' * 8
        icv = decryptor.compute_integrity_check_value(signed_octets, wire_iv=wire_iv)
        # Round-trip should not raise.
        decryptor.verify_integrity_check_value(signed_octets, icv, wire_iv=wire_iv)

    def test_construct_rejects_hmac_primitive_alongside_gmac_integrity(self):
        # Cross-field invariant: AES-GMAC integrity has its own
        # primitive (:class:`GmacCryptodome`) and MUST NOT be
        # constructed with a stray ``hmac_primitive`` — the two
        # keying schemes differ. Fail at construction rather than
        # deferring to a runtime attribute error.
        with self.assertRaises(ValueError) as ctx:
            Ikev2SkDecryptorNonAead(
                encryption_transform=self._ENCRYPTION_TRANSFORM,
                integrity_transform=self._INTEGRITY_TRANSFORM,
                sk_er=self._sk_er,
                sk_ar=self._sk_ar,
                cipher_factory=lambda iv: None,
                hmac_primitive=HmacCryptodome(mac_algorithm=MAC.SHA2_256),
            )
        self.assertIn('must be constructed without', str(ctx.exception))

    def test_construct_base_rejects_hmac_integrity_without_hmac_primitive(self):
        # Cross-field invariant sibling of the above: HMAC / CMAC
        # integrity transforms REQUIRE an ``hmac_primitive``. Base-class
        # construction with ``hmac_primitive=None`` under a non-GMAC
        # transform must raise; the :class:`Ikev2SkDecryptorNonAeadCryptodome`
        # subclass builds one automatically so real code never hits this.
        encryption_transform = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
        )
        with self.assertRaises(ValueError) as ctx:
            Ikev2SkDecryptorNonAead(
                encryption_transform=encryption_transform,
                integrity_transform=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
                sk_er=bytes(16),
                sk_ar=bytes(32),
                cipher_factory=lambda iv: None,
                hmac_primitive=None,
            )
        self.assertIn('requires ``hmac_primitive``', str(ctx.exception))


class TestExtractIkev1NegotiatedTransforms(unittest.TestCase):
    """Sibling to ``test.ike.test_pubkeys.TestExtractIkev2NegotiatedTransforms``
    for the RFC 2409 §5 attribute-shaped IKEv1 SA payload."""

    @staticmethod
    def _build_sa(*, encr_alg, hash_alg, auth_method, dh_group, key_length=None):
        attributes = [
            Ikev1AttributeEncryptionAlgorithm(encr_alg),
            Ikev1AttributeHashAlgorithm(hash_alg),
            Ikev1AttributeAuthenticationMethod(auth_method),
            Ikev1AttributeDiffieHellmanGroup(dh_group),
        ]
        if key_length is not None:
            attributes.append(Ikev1AttributeKeyLength(key_length))
        return Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=[Ikev1PayloadProposal(
                protocol_id=Ikev1ProtocolId.ISAKMP,
                transforms=[Ikev1PayloadTransform(
                    transform_id=Ikev1TransformId.KEY_IKE,
                    attributes=attributes,
                )],
            )],
        )

    def test_returns_all_four_mandatory_attributes_plus_key_length(self):
        sa = self._build_sa(
            encr_alg=Ikev1EncryptionAlgorithm.AES_CBC,
            hash_alg=Ikev1HashAlgorithm.SHA2_256,
            auth_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            key_length=128,
        )
        transforms = _NegotiatedIkev1Transforms.from_message(sa)
        self.assertEqual(transforms.encryption_algorithm, Ikev1EncryptionAlgorithm.AES_CBC)
        self.assertEqual(transforms.hash_algorithm, Ikev1HashAlgorithm.SHA2_256)
        self.assertEqual(transforms.authentication_method, Ikev1AuthenticationMethod.RSA_SIGNATURES)
        self.assertEqual(transforms.dh_group, Ikev1DiffieHellmanGroup.MODP_2048_BIT)
        self.assertEqual(transforms.key_length, 128)

    def test_fixed_key_cipher_key_length_is_none(self):
        sa = self._build_sa(
            encr_alg=Ikev1EncryptionAlgorithm.DES3_CBC,
            hash_alg=Ikev1HashAlgorithm.MD5,
            auth_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
        )
        transforms = _NegotiatedIkev1Transforms.from_message(sa)
        self.assertIsNone(transforms.key_length)

    def test_empty_proposals_raises(self):
        sa = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC, situation=[Ikev1Situation.SIT_IDENTITY_ONLY], proposals=[],
        )
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            _NegotiatedIkev1Transforms.from_message(sa)
        self.assertIn('no proposals', str(ctx.exception))

    def test_empty_transforms_raises(self):
        sa = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=[Ikev1PayloadProposal(
                protocol_id=Ikev1ProtocolId.ISAKMP,
                transforms=[],
            )],
        )
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            _NegotiatedIkev1Transforms.from_message(sa)
        self.assertIn('no transforms', str(ctx.exception))

    def test_missing_mandatory_attribute_raises(self):
        sa = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=[Ikev1PayloadProposal(
                protocol_id=Ikev1ProtocolId.ISAKMP,
                transforms=[Ikev1PayloadTransform(
                    transform_id=Ikev1TransformId.KEY_IKE,
                    attributes=[
                        # hash / auth / dh_group deliberately omitted
                        Ikev1AttributeEncryptionAlgorithm(Ikev1EncryptionAlgorithm.AES_CBC),
                    ],
                )],
            )],
        )
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            _NegotiatedIkev1Transforms.from_message(sa)
        self.assertIn('ENCR / HASH / AUTH / DH', str(ctx.exception))


class TestComposeAndDecryptIkev2IkeAuthMessageNonAead(unittest.TestCase):
    """End-to-end test: compose an IKE_AUTH outer message via the non-AEAD
    SK envelope helper, parse it back as an :class:`IsakmpMessage`,
    HMAC-verify + CBC-decrypt the SK payload, and confirm the inner
    chain survives the round trip with the RFC 7296 §3.14 signed
    octets computed correctly from the composed bytes.

    Parallel to :class:`TestComposeAndDecryptIkev2IkeAuthMessageAead`
    (currently in ``test/ike/test_pubkeys.py``) — the CBC + HMAC
    branch is the sibling wire path to the AEAD branch."""

    _ENCRYPTION_TRANSFORM = AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
    )
    _INTEGRITY_TRANSFORM = Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128

    def setUp(self):
        encryption_parameters = Ikev2SkDecryptorNonAead.get_encryption_transform_derivation_parameters(
            self._ENCRYPTION_TRANSFORM,
        )
        self._sk_er = bytes(range(encryption_parameters.write_key_length_bytes))
        self._sk_ar = bytes(range(32, 64))
        self._decryptor = Ikev2SkDecryptorNonAeadCryptodome(
            encryption_transform=self._ENCRYPTION_TRANSFORM,
            integrity_transform=self._INTEGRITY_TRANSFORM,
            sk_er=self._sk_er,
            sk_ar=self._sk_ar,
        )
        self._initiator_spi = 0xdeadbeefcafebabe
        self._responder_spi = 0xfeedface12345678

    @staticmethod
    def _inner_payloads():
        return [
            Ikev2PayloadNonce(flags=set(), nonce_data=b'\xaa' * 32),
            Ikev2PayloadNonce(flags=set(), nonce_data=b'\xbb' * 24),
        ]

    def test_compose_round_trips_through_decrypt(self):
        inner_payloads = self._inner_payloads()
        ike_auth_bytes = Ikev2SkDecryptorNonAead.compose_ike_auth_message(
            self._decryptor, inner_payloads, self._initiator_spi, self._responder_spi,
        )

        outer_message, _ = IsakmpMessage.parse_immutable(ike_auth_bytes)
        sk_payload = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        self.assertIsInstance(sk_payload, Ikev2PayloadEncryptedAndAuthenticated)
        self.assertEqual(outer_message.exchange_type, Ikev2ExchangeType.IKE_AUTH)
        self.assertEqual(outer_message.initiator_spi, self._initiator_spi)
        self.assertEqual(outer_message.responder_spi, self._responder_spi)

        recovered = Ikev2SkDecryptorNonAead.decrypt_sk_payload(
            self._decryptor, outer_message, sk_payload, ike_auth_bytes,
        )
        self.assertEqual(len(recovered), len(inner_payloads))
        self.assertIsInstance(recovered[0], Ikev2PayloadNonce)
        self.assertEqual(bytes(recovered[0].nonce_data), b'\xaa' * 32)
        self.assertIsInstance(recovered[1], Ikev2PayloadNonce)
        self.assertEqual(bytes(recovered[1].nonce_data), b'\xbb' * 24)

    def test_compose_sets_outer_message_id_default_one(self):
        ike_auth_bytes = Ikev2SkDecryptorNonAead.compose_ike_auth_message(
            self._decryptor, self._inner_payloads(),
            self._initiator_spi, self._responder_spi,
        )
        outer_message, _ = IsakmpMessage.parse_immutable(ike_auth_bytes)
        self.assertEqual(outer_message.message_id, 1)

    def test_compose_respects_explicit_message_id(self):
        ike_auth_bytes = Ikev2SkDecryptorNonAead.compose_ike_auth_message(
            self._decryptor, self._inner_payloads(),
            self._initiator_spi, self._responder_spi, message_id=42,
        )
        outer_message, _ = IsakmpMessage.parse_immutable(ike_auth_bytes)
        self.assertEqual(outer_message.message_id, 42)

    def test_compose_pads_inner_chain_to_cipher_block_size(self):
        """RFC 7296 §3.14: inner plaintext + Padding + Pad Length aligns
        to the encryption block size (16 for AES-CBC)."""
        ike_auth_bytes = Ikev2SkDecryptorNonAead.compose_ike_auth_message(
            self._decryptor, self._inner_payloads(),
            self._initiator_spi, self._responder_spi,
        )
        outer_message, _ = IsakmpMessage.parse_immutable(ike_auth_bytes)
        sk_payload = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        # encrypted_data = on-wire IV | ciphertext | ICV; strip both to
        # measure the ciphertext length, which must be a multiple of the
        # cipher's block size (16 for AES).
        icv_length = self._decryptor.integrity_check_value_length_bytes
        iv_length = self._decryptor.record_initialization_vector_length_bytes
        ciphertext_length = len(sk_payload.encrypted_data) - iv_length - icv_length
        self.assertEqual(ciphertext_length % 16, 0)

    def _compose_ike_header_bytes(self, first_payload_type, ike_message_length):
        composer = ComposerBinary()
        composer.compose_numeric(self._initiator_spi, 8)
        composer.compose_numeric(self._responder_spi, 8)
        composer.compose_numeric_enum_coded(first_payload_type)
        composer.compose_parsable(IsakmpProtocolVersion(IkeVersion.V2, 0))
        composer.compose_numeric_enum_coded(Ikev2ExchangeType.IKE_AUTH)
        composer.compose_numeric_flags({IsakmpFlags.INITIATOR}, 1)
        composer.compose_numeric(1, 4)
        composer.compose_numeric(ike_message_length, 4)
        return composer.composed_bytes

    def test_decrypt_walks_unencrypted_payloads_before_sk_payload(self):
        """RFC 7296 §3.14: any unencrypted payload preceding SK (e.g.
        NAT_DETECTION_* / REDIRECT notifies, or a VendorId) shifts the
        SK header offset in the on-wire bytes. The SK decrypt helper
        must walk ``response_message.payloads`` up to the SK payload to
        find that offset, and include the unencrypted payload bytes in
        the signed-octets input so HMAC verification succeeds."""
        inner_payloads = self._inner_payloads()
        plaintext_padded = Ikev2SkDecryptor.pad_inner_plaintext(
            Ikev2SkDecryptor.compose_inner_payload_chain(inner_payloads), block_size=16,
        )
        cipher_with_iv = self._decryptor.encrypt(plaintext_padded)

        vendor_id_payload = Ikev2PayloadVendorId(flags=set(), vendor_id=b'\xaa' * 8)
        vendor_id_payload.next_payload = Ikev2PayloadType.SK
        vendor_id_bytes = vendor_id_payload.compose()

        sk_body_length = (
            len(cipher_with_iv) + self._decryptor.integrity_check_value_length_bytes
        )
        sk_payload = Ikev2PayloadEncryptedAndAuthenticated(flags=set(), encrypted_data=b'')
        sk_payload.next_payload = inner_payloads[0].get_payload_type()
        sk_header_bytes = sk_payload.compose_header(sk_body_length).composed_bytes

        ike_header_bytes = self._compose_ike_header_bytes(
            Ikev2PayloadType.VENDOR_ID,
            IsakmpMessage.HEADER_SIZE
            + len(vendor_id_bytes)
            + Ikev2PayloadEncryptedAndAuthenticated.HEADER_SIZE
            + sk_body_length,
        )
        icv = self._decryptor.compute_integrity_check_value(
            self._decryptor.compute_signed_octets(
                ike_header_bytes, vendor_id_bytes, sk_header_bytes, cipher_with_iv,
            ),
        )

        raw_bytes = ike_header_bytes + vendor_id_bytes + sk_header_bytes + cipher_with_iv + icv
        outer_message, _ = IsakmpMessage.parse_immutable(raw_bytes)

        recovered = Ikev2SkDecryptorNonAead.decrypt_sk_payload(
            self._decryptor, outer_message,
            outer_message.get_payload_by_type(Ikev2PayloadType.SK), raw_bytes,
        )
        self.assertEqual(len(recovered), len(inner_payloads))
        self.assertEqual(bytes(recovered[0].nonce_data), b'\xaa' * 32)
        self.assertEqual(bytes(recovered[1].nonce_data), b'\xbb' * 24)

    def test_decrypt_raises_sk_authentication_error_on_icv_tampering(self):
        """A tampered trailing ICV causes ``verify_integrity_check_value``
        to raise ``ValueError``; the SK decrypt helper wraps that in
        :class:`Ikev2SkAuthenticationError` so the outer probe catches it
        as a cryptographic failure rather than a parse error."""
        ike_auth_bytes = Ikev2SkDecryptorNonAead.compose_ike_auth_message(
            self._decryptor, self._inner_payloads(),
            self._initiator_spi, self._responder_spi,
        )
        # Flip a bit in the trailing ICV.
        tampered_bytes = bytearray(ike_auth_bytes)
        tampered_bytes[-1] ^= 0x01
        tampered = bytes(tampered_bytes)

        outer_message, _ = IsakmpMessage.parse_immutable(tampered)
        sk_payload = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        with self.assertRaises(Ikev2SkAuthenticationError):
            Ikev2SkDecryptorNonAead.decrypt_sk_payload(
                self._decryptor, outer_message, sk_payload, tampered,
            )


class TestSelectIkev2SkEnvelopeFuncs(unittest.TestCase):
    """``_select_ikev2_sk_envelope_funcs`` dispatches compose / decrypt
    helpers by decryptor kind so the pubkeys probe can drive either
    envelope shape through one code path."""

    def test_non_aead_decryptor_selects_non_aead_helpers(self):
        encryption_transform = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
        )
        decryptor = Ikev2SkDecryptorNonAeadCryptodome(
            encryption_transform=encryption_transform,
            integrity_transform=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
            sk_er=bytes(range(16)),
            sk_ar=bytes(range(32, 64)),
        )
        compose_func, decrypt_func = Ikev2SkDecryptor.select_envelope_funcs(decryptor)
        self.assertIs(compose_func, Ikev2SkDecryptorNonAead.compose_ike_auth_message)
        self.assertIs(decrypt_func, Ikev2SkDecryptorNonAead.decrypt_sk_payload)

    def test_aead_decryptor_selects_aead_helpers(self):
        encryption_transform = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
        )
        parameters = Ikev2SkDecryptorCryptodome.get_encryption_transform_derivation_parameters(
            encryption_transform,
        )
        decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=encryption_transform,
            sk_er=bytes(range(parameters.write_key_length_bytes + parameters.salt_length_bytes)),
        )
        compose_func, decrypt_func = Ikev2SkDecryptor.select_envelope_funcs(decryptor)
        self.assertIs(compose_func, Ikev2SkDecryptor.compose_ike_auth_message)
        self.assertIs(decrypt_func, Ikev2SkDecryptor.decrypt_sk_payload)


class TestResolveAeadBulkCipherDescriptor(unittest.TestCase):
    def test_returns_descriptor_for_known_transform(self):
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 128,
        )
        self.assertEqual(descriptor.bulk_cipher, BlockCipher.AES_128)
        self.assertEqual(descriptor.block_cipher_mode, BlockCipherMode.GCM)

    def test_returns_descriptor_for_fixed_key_transform(self):
        # ENCR_CHACHA20_POLY1305: fixed key, so responder omits Key
        # Length attribute (encoded as key_length_bits=None).
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            Ikev2EncryptionAlgorithm.ENCR_CHACHA20_POLY1305, None,
        )
        self.assertEqual(descriptor.bulk_cipher, BlockCipher.CHACHA20)
        self.assertIsNone(descriptor.block_cipher_mode)

    def test_raises_transform_derivation_error_for_unknown_transform(self):
        # (transform, key_length_bits) pair absent from _IKEV2_ENCR_TO_AEAD_DESCRIPTOR.
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            AeadBulkCipherDescriptor.from_encryption_algorithm(
                Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 999,
            )
        self.assertIn('No AeadBulkCipherDescriptor', str(ctx.exception))


class TestExtractIkev2NegotiatedTransforms(unittest.TestCase):
    """Direct tests for :func:`_extract_ikev2_negotiated_transforms`
    (RFC 7296 §3.3 SA payload walk). Sibling to
    :class:`TestExtractIkev1NegotiatedTransforms`."""

    @staticmethod
    def _build_sa(transforms):
        return Ikev2PayloadSecurityAssociation(flags=set(), proposals=[
            Ikev2Proposal(
                protocol_id=Ikev2ProtocolId.IKE,
                spi=b'',
                transforms=transforms,
            ),
        ])

    def _build_full_sa(self):
        return self._build_sa([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, key_length=128,
            ),
            Ikev2TransformIntegrity(
                transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
            ),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT),
        ])

    def test_returns_all_four_mandatory_transforms(self):
        transforms = _NegotiatedIkev2Transforms.from_message(self._build_full_sa())
        self.assertIsInstance(transforms, _NegotiatedIkev2Transforms)
        self.assertEqual(transforms.encryption_algorithm, Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16)
        self.assertEqual(transforms.encryption_key_length_bits, 128)
        self.assertEqual(
            transforms.integrity_algorithm, Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
        )
        self.assertEqual(transforms.prf, Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256)
        self.assertEqual(transforms.dh_group, Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT)
        self.assertEqual(transforms.encryption_descriptor.bulk_cipher, BlockCipher.AES_128)

    def test_returns_none_integrity_when_transform_absent(self):
        # AEAD (combined-mode) proposal: RFC 7296 §3.3 lets the responder
        # omit the integrity transform; ``integrity_algorithm`` becomes None.
        sa_payload = self._build_sa([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, key_length=128,
            ),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT),
        ])
        transforms = _NegotiatedIkev2Transforms.from_message(sa_payload)
        self.assertIsNone(transforms.integrity_algorithm)

    def test_raises_on_empty_proposals(self):
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            _NegotiatedIkev2Transforms.from_message(
                Ikev2PayloadSecurityAssociation(flags=set(), proposals=[]),
            )
        self.assertIn('no proposals', str(ctx.exception))

    def test_raises_when_encryption_transform_missing(self):
        sa_payload = self._build_sa([
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT),
        ])
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            _NegotiatedIkev2Transforms.from_message(sa_payload)
        self.assertIn('ENCR / PRF / DH', str(ctx.exception))

    def test_raises_when_prf_transform_missing(self):
        sa_payload = self._build_sa([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, key_length=128,
            ),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT),
        ])
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            _NegotiatedIkev2Transforms.from_message(sa_payload)
        self.assertIn('ENCR / PRF / DH', str(ctx.exception))

    def test_raises_when_dh_transform_missing(self):
        sa_payload = self._build_sa([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, key_length=128,
            ),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256),
        ])
        with self.assertRaises(Ikev2TransformDerivationError) as ctx:
            _NegotiatedIkev2Transforms.from_message(sa_payload)
        self.assertIn('ENCR / PRF / DH', str(ctx.exception))


class TestComposeAndDecryptIkev2IkeAuthMessageAead(unittest.TestCase):
    """End-to-end round-trip for the AEAD SK envelope helpers
    (:func:`_compose_ikev2_ike_auth_message_aead` +
    :func:`_decrypt_ikev2_sk_payload_aead`). Mirrors
    :class:`TestComposeAndDecryptIkev2IkeAuthMessageNonAead` for the
    AEAD branch."""

    _INITIATOR_SPI = 0x1122334455667788
    _RESPONDER_SPI = 0x99aabbccddeeff00

    def setUp(self):
        # AES-128-GCM AEAD with 16-octet tag.
        self._decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=AeadBulkCipherDescriptor(
                bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.GCM,
            ),
            sk_er=bytes(range(20)),  # 16-octet write key + 4-octet salt
        )
        self._inner_payloads = [
            Ikev2PayloadNonce(flags=set(), nonce_data=b'\xaa' * 32),
        ]

    def test_round_trip_recovers_inner_payloads(self):
        outer_bytes = Ikev2SkDecryptor.compose_ike_auth_message(
            self._decryptor,
            self._inner_payloads,
            self._INITIATOR_SPI,
            self._RESPONDER_SPI,
        )
        outer_message, parsed_length = IsakmpMessage.parse_immutable(outer_bytes)
        self.assertEqual(parsed_length, len(outer_bytes))
        self.assertEqual(outer_message.exchange_type, Ikev2ExchangeType.IKE_AUTH)
        sk_payload = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        recovered = Ikev2SkDecryptor.decrypt_sk_payload(
            self._decryptor, outer_message, sk_payload, outer_bytes,
        )
        self.assertEqual(len(recovered), len(self._inner_payloads))
        self.assertEqual(recovered[0].nonce_data, self._inner_payloads[0].nonce_data)

    def _compose_ike_header_bytes(self, first_payload_type, ike_message_length):
        composer = ComposerBinary()
        composer.compose_numeric(self._INITIATOR_SPI, 8)
        composer.compose_numeric(self._RESPONDER_SPI, 8)
        composer.compose_numeric_enum_coded(first_payload_type)
        composer.compose_parsable(IsakmpProtocolVersion(IkeVersion.V2, 0))
        composer.compose_numeric_enum_coded(Ikev2ExchangeType.IKE_AUTH)
        composer.compose_numeric_flags({IsakmpFlags.INITIATOR}, 1)
        composer.compose_numeric(1, 4)
        composer.compose_numeric(ike_message_length, 4)
        return composer.composed_bytes

    def test_decrypt_walks_payloads_to_find_sk_offset(self):
        # RFC 5282 §5.1: unencrypted payloads before SK shift the SK
        # header offset in the on-wire bytes. The decrypt helper must
        # walk ``response_message.payloads`` up to the SK payload to
        # compute the AAD-input offset — exercised here by placing a
        # VendorId ahead of the SK payload and confirming the walk +
        # decrypt still recovers the inner chain.
        vendor_id = Ikev2PayloadVendorId(flags=set(), vendor_id=b'\xbb' * 8)
        vendor_id.next_payload = Ikev2PayloadType.SK
        vendor_id_bytes = vendor_id.compose()

        plaintext_padded = Ikev2SkDecryptor.pad_inner_plaintext(
            Ikev2SkDecryptor.compose_inner_payload_chain(self._inner_payloads),
            block_size=1,
        )
        sk_body_length = (
            self._decryptor.on_wire_initialization_vector_length_bytes
            + len(plaintext_padded)
            + self._decryptor.authentication_tag_length_bytes
        )
        sk_payload_length = Ikev2PayloadEncryptedAndAuthenticated.HEADER_SIZE + sk_body_length

        ike_header_bytes = self._compose_ike_header_bytes(
            Ikev2PayloadType.VENDOR_ID,
            IsakmpMessage.HEADER_SIZE + len(vendor_id_bytes) + sk_payload_length,
        )

        sk_payload = Ikev2PayloadEncryptedAndAuthenticated(flags=set(), encrypted_data=b'')
        sk_payload.next_payload = self._inner_payloads[0].get_payload_type()
        sk_header_bytes = sk_payload.compose_header(sk_body_length).composed_bytes

        cipher_with_iv = self._decryptor.encrypt(
            plaintext_padded, ike_header_bytes + vendor_id_bytes + sk_header_bytes[:4],
        )
        raw_bytes = ike_header_bytes + vendor_id_bytes + sk_header_bytes + cipher_with_iv

        outer_message, _ = IsakmpMessage.parse_immutable(raw_bytes)
        sk_payload_parsed = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        recovered = Ikev2SkDecryptor.decrypt_sk_payload(
            self._decryptor, outer_message, sk_payload_parsed, raw_bytes,
        )
        self.assertEqual(recovered[0].nonce_data, self._inner_payloads[0].nonce_data)

    def test_decrypt_raises_sk_authentication_error_on_tampered_ciphertext(self):
        outer_bytes = Ikev2SkDecryptor.compose_ike_auth_message(
            self._decryptor,
            self._inner_payloads,
            self._INITIATOR_SPI,
            self._RESPONDER_SPI,
        )
        outer_message, _ = IsakmpMessage.parse_immutable(outer_bytes)
        sk_payload = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        # Flip one octet inside the encrypted body so the GCM tag rejects it.
        sk_payload.encrypted_data = (
            bytes([sk_payload.encrypted_data[0] ^ 0x01]) + bytes(sk_payload.encrypted_data[1:])
        )
        with self.assertRaises(Ikev2SkAuthenticationError):
            Ikev2SkDecryptor.decrypt_sk_payload(
                self._decryptor, outer_message, sk_payload, outer_bytes,
            )


class TestIkePeerKeyExchangeFromWirePrependsSec1Marker(unittest.TestCase):
    def test_weierstrass_curve_prepends_uncompressed_marker(self):
        # peer_key_exchange_from_wire prepends the SEC1 0x04
        # uncompressed marker for Weierstrass curves (P-256/P-384/P-521)
        # so PyCryptodome accepts the ``x || y`` wire form. Montgomery
        # curves + MODP groups skip the prefix; this test covers the
        # Weierstrass branch.
        raw_xy = b'\x11' * 64  # 32-byte x || 32-byte y for P-256
        result = dhe_ephemeral_material_backend.peer_key_exchange_from_wire(
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, raw_xy,
        )
        self.assertEqual(result[:1], b'\x04')
        self.assertEqual(result[1:], raw_xy)

    def test_montgomery_curve_passes_through_unchanged(self):
        # Curve25519 / Curve448 wire form has no SEC1 marker.
        raw = b'\x22' * 32
        result = dhe_ephemeral_material_backend.peer_key_exchange_from_wire(
            Ikev2DiffieHellmanGroup.CURVE25519, raw,
        )
        self.assertEqual(result, raw)


class TestIkev2IntegrityTransformDerivationParametersHmacKeyLength(unittest.TestCase):
    def test_effective_key_length_falls_back_to_digest_size_when_unset(self):
        # HMAC integrity: ``key_length_bytes`` defaults to None, so
        # ``effective_key_length_bytes`` returns MAC digest_size // 8.
        # Covers the HMAC branch of the property (GMAC / CMAC entries in
        # ``_INTEGRITY_PARAMETERS`` set ``key_length_bytes`` explicitly).
        parameters = Ikev2IntegrityTransformDerivationParameters(
            mac_algorithm=MAC.SHA2_256, integrity_check_value_length_bytes=16,
        )
        self.assertEqual(parameters.effective_key_length_bytes, 32)


class TestParseIkev2InnerPayloadChainUnknownType(unittest.TestCase):
    def test_raises_invalid_type_for_unknown_first_payload_type(self):
        # ``first_payload_type`` outside :data:`IKEV2_PAYLOAD_CLASSES_BY_TYPE`
        # (e.g. CP / Configuration — cryptoparser does not implement it,
        # so it stays absent from the inner-parser map) must raise
        # ``InvalidType`` rather than silently drop the chain.
        with self.assertRaises(InvalidType):
            Ikev2SkDecryptor.parse_inner_payload_chain(b'\x00' * 8, Ikev2PayloadType.CP)


class TestPadIkev2InnerPlaintextBlockSizeGuard(unittest.TestCase):
    def test_raises_value_error_for_block_size_less_than_one(self):
        # RFC 7296 §3.14 pad-length field is 1 octet, and the modular
        # arithmetic in ``_pad_ikev2_inner_plaintext`` divides by
        # ``block_size``; callers pass 1 (AEAD) or the AES block size
        # (16). Reject block_size < 1 loudly.
        with self.assertRaises(ValueError) as ctx:
            Ikev2SkDecryptor.pad_inner_plaintext(b'x', block_size=0)
        self.assertIn('block_size must be >= 1', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
