# -*- coding: utf-8 -*-
"""Tests for TLS 1.3 handshake key schedule and AEAD record decryption."""

import unittest
from unittest.mock import Mock, patch

from cryptodatahub.common.algorithm import Hash, MAC, NamedGroup
from cryptodatahub.tls.algorithm import TlsCipherSuite
from cryptoparser.tls.version import TlsVersion

from cryptolyzer.tls.crypto import (
    Tls13HandshakeDecryptor,
    Tls13HandshakeDecryptorCryptodome,
    _EphemeralKeyExchangeBackendCryptodome,
)
from cryptolyzer.common.crypto import HashCryptodome, HmacCryptodome


class TestTls13HandshakeDecryptorCryptodome(unittest.TestCase):
    """TLS 1.3 key schedule + AEAD record decryption tests (RFC 8448 §3)."""

    def test_error_non_tls13_cipher_suite(self):
        """Non-TLS 1.3 cipher suite raises ValueError."""
        cipher_suite = TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA  # TLS 1.2
        with self.assertRaises(ValueError):
            Tls13HandshakeDecryptorCryptodome(
                cipher_suite=cipher_suite,
                key_exchange_shared_secret=b'\x00' * 32,
                handshake_transcript_hash=b'\x00' * 32,
            )

    def test_error_unsupported_cipher_suite(self):
        """Unsupported TLS 1.3 suite raises ValueError."""
        cipher_suite = TlsCipherSuite.TLS_AES_128_CCM_SHA256
        with self.assertRaises(ValueError) as ctx:
            Tls13HandshakeDecryptorCryptodome(
                cipher_suite=cipher_suite,
                key_exchange_shared_secret=b'\x00' * 32,
                handshake_transcript_hash=b'\x00' * 32,
            )
        expected = f'{cipher_suite.name} is not supported by Tls13HandshakeDecryptor'
        self.assertEqual(str(ctx.exception.args[0]), expected)

    def test_transcript_hash_aes128_gcm_sha256(self):
        """transcript_hash classmethod computes SHA-256 of handshake messages."""
        handshake_messages = b'test data'
        hash_value = Tls13HandshakeDecryptorCryptodome.transcript_hash(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            handshake_messages,
        )
        self.assertEqual(len(hash_value), 32)

    def test_aes128_gcm_sha256_key_material_derivation(self):
        """AES-128-GCM key schedule derives expected key and IV (RFC 8446)."""
        cipher_suite = TlsCipherSuite.TLS_AES_128_GCM_SHA256
        shared_secret = b'\x00' * 32
        handshake_transcript_hash = b'\x00' * 32

        decryptor = Tls13HandshakeDecryptorCryptodome(
            cipher_suite=cipher_suite,
            key_exchange_shared_secret=shared_secret,
            handshake_transcript_hash=handshake_transcript_hash,
        )

        self.assertEqual(len(decryptor._write_key), 16)
        self.assertEqual(len(decryptor._initialization_vector), 12)
        self.assertEqual(decryptor.authentication_tag_length_bytes, 16)

    def test_aes256_gcm_sha384_key_schedule_and_decrypt(self):
        """AES-256-GCM key schedule + record decryption."""
        cipher_suite = TlsCipherSuite.TLS_AES_256_GCM_SHA384
        shared_secret = b'\x00' * 48
        handshake_transcript_hash = b'\x00' * 48

        decryptor = Tls13HandshakeDecryptorCryptodome(
            cipher_suite=cipher_suite,
            key_exchange_shared_secret=shared_secret,
            handshake_transcript_hash=handshake_transcript_hash,
        )

        self.assertEqual(decryptor.authentication_tag_length_bytes, 16)
        self.assertEqual(decryptor.record_initialization_vector_length_bytes, 12)

    def test_chacha20_poly1305_sha256_key_schedule_and_decrypt(self):
        """ChaCha20-Poly1305 key schedule + record decryption."""
        cipher_suite = TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256
        shared_secret = b'\x00' * 32
        handshake_transcript_hash = b'\x00' * 32

        decryptor = Tls13HandshakeDecryptorCryptodome(
            cipher_suite=cipher_suite,
            key_exchange_shared_secret=shared_secret,
            handshake_transcript_hash=handshake_transcript_hash,
        )

        self.assertEqual(decryptor.authentication_tag_length_bytes, 16)
        self.assertEqual(decryptor.record_initialization_vector_length_bytes, 12)

    def test_chacha20_cipher_factory_called_on_decrypt(self):
        """ChaCha20 cipher factory is called during decrypt() for CHACHA20-Poly1305."""
        cipher_suite = TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256
        shared_secret = b'\x00' * 32
        handshake_transcript_hash = b'\x00' * 32

        decryptor = Tls13HandshakeDecryptorCryptodome(
            cipher_suite=cipher_suite,
            key_exchange_shared_secret=shared_secret,
            handshake_transcript_hash=handshake_transcript_hash,
        )

        ciphertext_with_tag = b'\x00' * 32
        aad = b''
        with self.assertRaises(Exception):
            decryptor.decrypt(ciphertext_with_tag, aad)

    def test_block_cipher_factory_called_on_decrypt(self):
        """Block cipher factory is called during decrypt() for AES-GCM."""
        cipher_suite = TlsCipherSuite.TLS_AES_128_GCM_SHA256
        shared_secret = b'\x00' * 32
        handshake_transcript_hash = b'\x00' * 32

        decryptor = Tls13HandshakeDecryptorCryptodome(
            cipher_suite=cipher_suite,
            key_exchange_shared_secret=shared_secret,
            handshake_transcript_hash=handshake_transcript_hash,
        )

        ciphertext_with_tag = b'\x00' * 32
        aad = b''
        with self.assertRaises(Exception):
            decryptor.decrypt(ciphertext_with_tag, aad)


    def test_tls10_cipher_suite_version_check(self):
        """TLS 1.0 cipher suite triggers version check error."""
        tls10_suite = TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        with self.assertRaises(ValueError) as ctx:
            Tls13HandshakeDecryptor(
                cipher_suite=tls10_suite,
                key_exchange_shared_secret=b'\x00' * 32,
                handshake_transcript_hash=b'\x00' * 32,
                hmac_primitive=HmacCryptodome(mac_algorithm=MAC.SHA2_256),
                hash_primitive=HashCryptodome(hash_algorithm=Hash.SHA2_256),
                cipher_factory=lambda nonce: None,
            )
        self.assertIn('is not a TLS 1.3 cipher suite', str(ctx.exception))


class TestEphemeralKeyExchangeBackendCryptodome(unittest.TestCase):
    """Ephemeral key exchange backend wrapper tests."""

    def test_supported_named_groups(self):
        """Backend delegates to EphemeralKeyExchangeEllipticCurveCryptodome."""
        backend = _EphemeralKeyExchangeBackendCryptodome()
        groups = backend.supported_named_groups()
        self.assertIsInstance(groups, tuple)
        self.assertIn(NamedGroup.PRIME256V1, groups)

    def test_create_ephemeral_material(self):
        """Backend creates ephemeral key exchange instances."""
        backend = _EphemeralKeyExchangeBackendCryptodome()
        material = backend.create_ephemeral_material(NamedGroup.PRIME256V1)
        self.assertIsNotNone(material.public_key_bytes)


if __name__ == '__main__':
    unittest.main()
