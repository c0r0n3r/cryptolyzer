# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, Hash, MAC, NamedGroup
from cryptodatahub.common.parameter import DHParamWellKnown

from cryptolyzer.common.crypto import (
    CypherBlockCryptodome,
    CypherStreamCryptodome,
    EphemeralKeyExchangeEllipticCurveCryptodome,
    EphemeralKeyExchangeFiniteField,
    EphemeralKeyExchangeFiniteFieldCryptodome,
    HashCryptodome,
    HmacCryptodome,
)


class TestEphemeralKeyExchangeEllipticCurveCryptodome(unittest.TestCase):
    def _assert_round_trip(self, named_group):
        kex_a = EphemeralKeyExchangeEllipticCurveCryptodome(named_group=named_group)
        kex_b = EphemeralKeyExchangeEllipticCurveCryptodome(named_group=named_group)
        self.assertIsInstance(kex_a.public_key_bytes, bytes)
        self.assertGreater(len(kex_a.public_key_bytes), 0)
        self.assertNotEqual(kex_a.public_key_bytes, kex_b.public_key_bytes)
        self.assertEqual(
            kex_a.compute_shared_secret(kex_b.public_key_bytes),
            kex_b.compute_shared_secret(kex_a.public_key_bytes),
        )

    def test_error_unsupported_group(self):
        with self.assertRaises(ValueError) as ctx:
            EphemeralKeyExchangeEllipticCurveCryptodome(named_group=NamedGroup.BRAINPOOLP256R1)
        self.assertEqual(
            str(ctx.exception.args[0]),
            'brainpoolp256r1 is not supported by EphemeralKeyExchangeEllipticCurveCryptodome'
        )

    def test_p256(self):
        self._assert_round_trip(NamedGroup.PRIME256V1)

    def test_p384(self):
        self._assert_round_trip(NamedGroup.SECP384R1)

    def test_p521(self):
        self._assert_round_trip(NamedGroup.SECP521R1)

    def test_x25519(self):
        self._assert_round_trip(NamedGroup.CURVE25519)

    def test_x448(self):
        self._assert_round_trip(NamedGroup.CURVE448)

    def test_error_non_ec_named_group(self):
        with self.assertRaises(ValueError) as ctx:
            EphemeralKeyExchangeEllipticCurveCryptodome(named_group=NamedGroup.FFDHE2048)
        expected = f"{NamedGroup.FFDHE2048.value.name} is not supported by EphemeralKeyExchangeEllipticCurveCryptodome"
        self.assertEqual(str(ctx.exception.args[0]), expected)


class TestEphemeralKeyExchangeFiniteFieldBase(unittest.TestCase):
    def test_from_named_group_error_non_ff(self):
        with self.assertRaises(ValueError) as ctx:
            EphemeralKeyExchangeFiniteField.from_named_group(NamedGroup.PRIME256V1)
        expected = f"{NamedGroup.PRIME256V1.value.name} is not a finite-field NamedGroup"
        self.assertEqual(str(ctx.exception), expected)

    def test_from_named_group_ffdhe2048(self):
        kex = EphemeralKeyExchangeFiniteFieldCryptodome.from_named_group(NamedGroup.FFDHE2048)
        self.assertIsInstance(kex, EphemeralKeyExchangeFiniteFieldCryptodome)
        self.assertIsInstance(kex.public_key_bytes, bytes)
        self.assertGreater(len(kex.public_key_bytes), 0)

    def test_from_named_group_ffdhe4096(self):
        kex = EphemeralKeyExchangeFiniteFieldCryptodome.from_named_group(NamedGroup.FFDHE4096)
        self.assertIsInstance(kex, EphemeralKeyExchangeFiniteFieldCryptodome)
        self.assertIsInstance(kex.public_key_bytes, bytes)
        self.assertGreater(len(kex.public_key_bytes), 0)


class TestEphemeralKeyExchangeFiniteFieldCryptodome(unittest.TestCase):
    def _assert_round_trip(self, dh_parameters):
        kex_a = EphemeralKeyExchangeFiniteFieldCryptodome(dh_parameters=dh_parameters)
        kex_b = EphemeralKeyExchangeFiniteFieldCryptodome(dh_parameters=dh_parameters)
        self.assertIsInstance(kex_a.public_key_bytes, bytes)
        self.assertGreater(len(kex_a.public_key_bytes), 0)
        self.assertNotEqual(kex_a.public_key_bytes, kex_b.public_key_bytes)
        self.assertEqual(
            kex_a.compute_shared_secret(kex_b.public_key_bytes),
            kex_b.compute_shared_secret(kex_a.public_key_bytes),
        )

    def test_ffdhe2048(self):
        self._assert_round_trip(DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP)

    def test_ffdhe3072(self):
        self._assert_round_trip(DHParamWellKnown.RFC7919_3072_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP)

    def test_ffdhe4096(self):
        self._assert_round_trip(DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP)

    def test_public_key_bytes(self):
        kex = EphemeralKeyExchangeFiniteFieldCryptodome(
            dh_parameters=DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP
        )
        self.assertIsInstance(kex.public_key_bytes, bytes)
        self.assertGreater(len(kex.public_key_bytes), 0)
        self.assertEqual(
            len(kex.public_key_bytes),
            DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.key_size // 8,
        )


class TestHmacCryptodome(unittest.TestCase):
    def test_error_unsupported_mac(self):
        with self.assertRaises(ValueError) as ctx:
            HmacCryptodome(mac_algorithm=MAC.MD5)
        expected = f"{MAC.MD5.name} is not supported by HmacCryptodome"
        self.assertEqual(str(ctx.exception.args[0]), expected)

    def test_sha256(self):
        # Test vector from RFC 4231 §A.1 (Test Case 1)
        result = HmacCryptodome(mac_algorithm=MAC.SHA2_256).digest(
            bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
            b'Hi There',
        )
        self.assertEqual(
            result,
            bytes.fromhex('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
        )

    def test_sha384(self):
        # Test vector from RFC 4231 §A.1 (Test Case 1)
        result = HmacCryptodome(mac_algorithm=MAC.SHA2_384).digest(
            bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
            b'Hi There',
        )
        self.assertEqual(
            result,
            bytes.fromhex(
                'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c'
                'faea9ea9076ede7f4af152e8b2fa9cb6'
            ),
        )

    def test_sha512(self):
        # Test vector from RFC 4231 §A.1 (Test Case 1)
        result = HmacCryptodome(mac_algorithm=MAC.SHA2_512).digest(
            bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
            b'Hi There',
        )
        self.assertEqual(
            result,
            bytes.fromhex(
                '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde'
                'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'
            ),
        )


class TestHashCryptodome(unittest.TestCase):
    def test_error_unsupported_hash(self):
        with self.assertRaises(ValueError) as ctx:
            HashCryptodome(hash_algorithm=Hash.MD5)
        expected = f"{Hash.MD5.name} is not supported by HashCryptodome"
        self.assertEqual(str(ctx.exception.args[0]), expected)

    def test_sha256(self):
        # Test vector from NIST FIPS 180-4 Appendix B.1 (one-block message "abc")
        result = HashCryptodome(hash_algorithm=Hash.SHA2_256).digest(b'abc')
        self.assertEqual(
            result,
            bytes.fromhex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        )

    def test_sha384(self):
        # Test vector from NIST FIPS 180-4 Appendix D.1 (one-block message "abc")
        result = HashCryptodome(hash_algorithm=Hash.SHA2_384).digest(b'abc')
        self.assertEqual(
            result,
            bytes.fromhex(
                'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed'
                '8086072ba1e7cc2358baeca134c825a7'
            ),
        )

    def test_sha512(self):
        # Test vector from NIST FIPS 180-4 Appendix C.1 (one-block message "abc")
        result = HashCryptodome(hash_algorithm=Hash.SHA2_512).digest(b'abc')
        self.assertEqual(
            result,
            bytes.fromhex(
                'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
                '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
            ),
        )

    def test_digestmod_class(self):
        hash_obj = HashCryptodome(hash_algorithm=Hash.SHA2_256)
        digestmod = hash_obj.digestmod_class
        self.assertIsNotNone(digestmod)
        self.assertTrue(callable(digestmod.new))


class TestCypherBlockCryptodome(unittest.TestCase):
    def test_error_authentication_failure(self):
        # Test vector from NIST SP 800-38D Appendix D.1 (Example 3: AES-128-GCM, no AAD)
        # Modified tag to trigger authentication failure
        cipher = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf888'),
            block_cipher_mode=BlockCipherMode.GCM,
        )
        with self.assertRaises(ValueError):
            cipher.decrypt_and_verify(
                ciphertext=bytes.fromhex(
                    '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e'
                    '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985'
                ),
                tag=bytes(16),
                additional_data=b'',
            )

    def test_aes128_gcm(self):
        # Test vector from NIST SP 800-38D Appendix D.1 (Example 3: AES-128-GCM, 64-byte plaintext, no AAD)
        cipher = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf888'),
            block_cipher_mode=BlockCipherMode.GCM,
        )
        plaintext = cipher.decrypt_and_verify(
            ciphertext=bytes.fromhex(
                '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e'
                '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985'
            ),
            tag=bytes.fromhex('4d5c2af327cd64a62cf35abd2ba6fab4'),
            additional_data=b'',
        )
        self.assertEqual(
            plaintext,
            bytes.fromhex(
                'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
                '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'
            ),
        )

    def test_encrypt(self):
        # Test vector from NIST SP 800-38D Appendix D.1 (Example 3: AES-128-GCM, 64-byte plaintext, no AAD)
        cipher = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf888'),
            block_cipher_mode=BlockCipherMode.GCM,
        )
        plaintext = bytes.fromhex(
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
            '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'
        )
        ciphertext = cipher.encrypt(plaintext)
        self.assertEqual(
            ciphertext,
            bytes.fromhex(
                '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e'
                '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985'
            ),
        )

    def test_decrypt(self):
        # Test vector from NIST SP 800-38D Appendix D.1 (Example 3: AES-128-GCM, 64-byte ciphertext, no AAD)
        cipher = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf888'),
            block_cipher_mode=BlockCipherMode.GCM,
        )
        ciphertext = bytes.fromhex(
            '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e'
            '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985'
        )
        plaintext = cipher.decrypt(ciphertext)
        self.assertEqual(
            plaintext,
            bytes.fromhex(
                'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
                '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'
            ),
        )


class TestCypherStreamCryptodome(unittest.TestCase):
    def test_error_authentication_failure(self):
        # Test vector from RFC 8439 §2.8.2 (AEAD_CHACHA20_POLY1305 Decryption Example)
        # Modified tag to trigger authentication failure
        cipher = CypherStreamCryptodome(
            bulk_cipher=BlockCipher.CHACHA20,
            key=bytes.fromhex(
                '808182838485868788898a8b8c8d8e8f'
                '909192939495969798999a9b9c9d9e9f'
            ),
            nonce=bytes.fromhex('070000004041424344454647'),
        )
        with self.assertRaises(ValueError):
            cipher.decrypt_and_verify(
                ciphertext=bytes.fromhex(
                    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
                    '3dbea45e8ca9671282fafb69daaf3a8d07619207cd49032040c5e6bb78d77575'
                    'dcc6a17f236b8b8c8005adb76f'
                ),
                tag=bytes(16),
                additional_data=bytes.fromhex('50515253c0c1c2c3c4c5c6c7'),
            )

    def test_chacha20_poly1305(self):
        # Test vector from RFC 8439 §2.8.2 (AEAD_CHACHA20_POLY1305 Decryption Example)
        # Key, nonce, AAD and plaintext from RFC 8439, ciphertext and tag verified
        cipher = CypherStreamCryptodome(
            bulk_cipher=BlockCipher.CHACHA20,
            key=bytes.fromhex(
                '808182838485868788898a8b8c8d8e8f'
                '909192939495969798999a9b9c9d9e9f'
            ),
            nonce=bytes.fromhex('070000004041424344454647'),
        )
        plaintext = cipher.decrypt_and_verify(
            ciphertext=bytes.fromhex(
                'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
                '3dbea45e8ca9671282fafb69daaf3a8d07619207cd49032040c5e6bb78d77575'
                'dcc6a17f236b8b8c8005adb76f'
            ),
            tag=bytes.fromhex('5a50b43c99d86301d85c34077b499f07'),
            additional_data=bytes.fromhex('50515253c0c1c2c3c4c5c6c7'),
        )
        self.assertEqual(
            plaintext,
            b"Ladies and Gentlemen of the class of '99: "
            b"If there is no action, we are lost!",
        )


class TestEphemeralKeyExchangeEllipticCurveCryptodomeAdditional(unittest.TestCase):
    def test_supported_named_groups(self):
        supported = EphemeralKeyExchangeEllipticCurveCryptodome.supported_named_groups()
        self.assertIsInstance(supported, tuple)
        self.assertGreater(len(supported), 0)
        self.assertIn(NamedGroup.PRIME256V1, supported)
        self.assertIn(NamedGroup.SECP384R1, supported)
        self.assertIn(NamedGroup.SECP521R1, supported)
        self.assertIn(NamedGroup.CURVE25519, supported)
        self.assertIn(NamedGroup.CURVE448, supported)

    def test_montgomery_curve_public_key_bytes(self):
        kex = EphemeralKeyExchangeEllipticCurveCryptodome(named_group=NamedGroup.CURVE25519)
        self.assertIsInstance(kex.public_key_bytes, bytes)
        self.assertGreater(len(kex.public_key_bytes), 0)

    def test_montgomery_curve_roundtrip(self):
        kex_a = EphemeralKeyExchangeEllipticCurveCryptodome(named_group=NamedGroup.CURVE448)
        kex_b = EphemeralKeyExchangeEllipticCurveCryptodome(named_group=NamedGroup.CURVE448)
        self.assertEqual(
            kex_a.compute_shared_secret(kex_b.public_key_bytes),
            kex_b.compute_shared_secret(kex_a.public_key_bytes),
        )


class TestCypherBlockCryptodomeAdditional(unittest.TestCase):
    def test_error_unsupported_block_cipher(self):
        with self.assertRaises(ValueError) as ctx:
            CypherBlockCryptodome(
                bulk_cipher=BlockCipher.AES_192,
                key=bytes(16),
                nonce=bytes(12),
                block_cipher_mode=BlockCipherMode.GCM,
            )
        expected = f"{BlockCipher.AES_192.name} is not supported by CypherBlockCryptodome"
        self.assertEqual(str(ctx.exception.args[0]), expected)

    def test_error_unsupported_block_cipher_mode(self):
        with self.assertRaises(ValueError) as ctx:
            CypherBlockCryptodome(
                bulk_cipher=BlockCipher.AES_128,
                key=bytes(16),
                nonce=bytes(12),
                block_cipher_mode=BlockCipherMode.CBC,
            )
        expected = f"{BlockCipherMode.CBC.name} is not supported by CypherBlockCryptodome"
        self.assertEqual(str(ctx.exception.args[0]), expected)


class TestCypherStreamCryptodomeAdditional(unittest.TestCase):
    def test_error_unsupported_stream_cipher(self):
        with self.assertRaises(ValueError) as ctx:
            CypherStreamCryptodome(
                bulk_cipher=BlockCipher.AES_128,
                key=bytes(32),
                nonce=bytes(12),
            )
        expected = f"{BlockCipher.AES_128.name} is not supported by CypherStreamCryptodome"
        self.assertEqual(str(ctx.exception.args[0]), expected)

    def test_encrypt(self):
        # Test vector from RFC 8439 §2.8.2 (AEAD_CHACHA20_POLY1305 Decryption Example: key and nonce)
        cipher = CypherStreamCryptodome(
            bulk_cipher=BlockCipher.CHACHA20,
            key=bytes.fromhex(
                '808182838485868788898a8b8c8d8e8f'
                '909192939495969798999a9b9c9d9e9f'
            ),
            nonce=bytes.fromhex('070000004041424344454647'),
        )
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: "
            b"If there is no action, we are lost!"
        )
        ciphertext = cipher.encrypt(plaintext)
        self.assertEqual(
            ciphertext,
            bytes.fromhex(
                'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
                '3dbea45e8ca9671282fafb69daaf3a8d07619207cd49032040c5e6bb78d77575'
                'dcc6a17f236b8b8c8005adb76f'
            ),
        )

    def test_decrypt(self):
        # Test vector from RFC 8439 §2.8.2 (AEAD_CHACHA20_POLY1305 Decryption Example)
        cipher = CypherStreamCryptodome(
            bulk_cipher=BlockCipher.CHACHA20,
            key=bytes.fromhex(
                '808182838485868788898a8b8c8d8e8f'
                '909192939495969798999a9b9c9d9e9f'
            ),
            nonce=bytes.fromhex('070000004041424344454647'),
        )
        ciphertext = bytes.fromhex(
            'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
            '3dbea45e8ca9671282fafb69daaf3a8d07619207cd49032040c5e6bb78d77575'
            'dcc6a17f236b8b8c8005adb76f'
        )
        plaintext = cipher.decrypt(ciphertext)
        self.assertEqual(
            plaintext,
            b"Ladies and Gentlemen of the class of '99: "
            b"If there is no action, we are lost!",
        )
