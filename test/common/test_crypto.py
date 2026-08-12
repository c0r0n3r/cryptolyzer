
import unittest

import Crypto.Cipher.AES

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, Hash, MAC
from cryptodatahub.common.parameter import DHParamWellKnown, ECParamWellKnown
from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData, TooMuchData

from cryptolyzer.common.crypto import (
    CmacCryptodome,
    CypherBlockCryptodome,
    CypherStreamCryptodome,
    EphemeralKeyExchangeEllipticCurveCryptodome,
    EphemeralKeyExchangeFiniteFieldCryptodome,
    GmacCryptodome,
    HashCryptodome,
    HmacBase,
    HmacCryptodome,
)


class TestEphemeralKeyExchangeEllipticCurveCryptodome(unittest.TestCase):
    def _assert_round_trip(self, key_parameter):
        kex_a = EphemeralKeyExchangeEllipticCurveCryptodome(key_parameter=key_parameter)
        kex_b = EphemeralKeyExchangeEllipticCurveCryptodome(key_parameter=key_parameter)
        self.assertIsInstance(kex_a.public_key_bytes, bytes)
        self.assertGreater(len(kex_a.public_key_bytes), 0)
        self.assertNotEqual(kex_a.public_key_bytes, kex_b.public_key_bytes)
        self.assertEqual(
            kex_a.compute_shared_secret(kex_b.public_key_bytes),
            kex_b.compute_shared_secret(kex_a.public_key_bytes),
        )

    def test_error_unsupported_group(self):
        with self.assertRaises(InvalidValue) as ctx:
            EphemeralKeyExchangeEllipticCurveCryptodome(key_parameter=ECParamWellKnown.BRAINPOOLP256R1)
        self.assertEqual(ctx.exception.value, ECParamWellKnown.BRAINPOOLP256R1)

    def test_p256(self):
        self._assert_round_trip(ECParamWellKnown.PRIME256V1)

    def test_p384(self):
        self._assert_round_trip(ECParamWellKnown.SECP384R1)

    def test_p521(self):
        self._assert_round_trip(ECParamWellKnown.SECP521R1)

    def test_x25519(self):
        self._assert_round_trip(ECParamWellKnown.CURVE25519)

    def test_x448(self):
        self._assert_round_trip(ECParamWellKnown.CURVE448)

    def test_error_non_ec_key_parameter(self):
        # A group that is not an elliptic curve is rejected by the type of the
        # attribute now, rather than by a check of its own.
        with self.assertRaises(TypeError):
            EphemeralKeyExchangeEllipticCurveCryptodome(
                key_parameter=DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP
            )


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
            DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.field_size // 8,
        )


class TestHmacBaseForAlgorithm(unittest.TestCase):
    def test_returns_cmac_for_block_cipher_mac(self):
        self.assertIsInstance(HmacBase.for_algorithm(MAC.AES_CMAC_96), CmacCryptodome)
        self.assertIsInstance(HmacBase.for_algorithm(MAC.AES_CMAC_PRF_128), CmacCryptodome)

    def test_returns_hmac_for_hash_based_mac(self):
        self.assertIsInstance(HmacBase.for_algorithm(MAC.SHA2_256), HmacCryptodome)


class TestHmacCryptodome(unittest.TestCase):
    def test_error_unsupported_mac(self):
        # POLY1305 is not an HMAC construction — Poly1305 is a one-time
        # authenticator used inside ChaCha20-Poly1305 AEAD, not something
        # HmacCryptodome maps to a hash module.
        with self.assertRaises(InvalidValue) as ctx:
            HmacCryptodome(mac_algorithm=MAC.POLY1305)
        self.assertEqual(ctx.exception.value, MAC.POLY1305)

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
        with self.assertRaises(InvalidValue) as ctx:
            HashCryptodome(hash_algorithm=Hash.MD5)
        self.assertEqual(ctx.exception.value, Hash.MD5)

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

    def test_aes128_cbc_round_trip(self):
        # Test vector from NIST SP 800-38A Appendix F.2.1 (AES-128-CBC, Example 1).
        cipher = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128,
            key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
            nonce=bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
            block_cipher_mode=BlockCipherMode.CBC,
        )
        plaintext = bytes.fromhex(
            '6bc1bee22e409f96e93d7e117393172a'
            'ae2d8a571e03ac9c9eb76fac45af8e51'
            '30c81c46a35ce411e5fbc1191a0a52ef'
            'f69f2445df4f9b17ad2b417be66c3710'
        )
        expected_ciphertext = bytes.fromhex(
            '7649abac8119b246cee98e9b12e9197d'
            '5086cb9b507219ee95db113a917678b2'
            '73bed6b8e3c1743b7116e69e22229516'
            '3ff1caa1681fac09120eca307586e1a7'
        )
        self.assertEqual(cipher.encrypt(plaintext), expected_ciphertext)

        decryptor = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128,
            key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
            nonce=bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
            block_cipher_mode=BlockCipherMode.CBC,
        )
        self.assertEqual(decryptor.decrypt(expected_ciphertext), plaintext)

    def _assert_aead_round_trip(self, bulk_cipher, block_cipher_mode, key, nonce, mac_len):
        additional_data = b'\xaa' * 32
        plaintext = b'inner payload octets for AEAD variant round-trip'
        encryptor = CypherBlockCryptodome(
            bulk_cipher=bulk_cipher, key=key, nonce=nonce,
            block_cipher_mode=block_cipher_mode, mac_len=mac_len,
        )
        ciphertext, tag = encryptor.encrypt_and_digest(plaintext, additional_data)
        self.assertEqual(len(tag), mac_len)

        decryptor = CypherBlockCryptodome(
            bulk_cipher=bulk_cipher, key=key, nonce=nonce,
            block_cipher_mode=block_cipher_mode, mac_len=mac_len,
        )
        self.assertEqual(
            decryptor.decrypt_and_verify(ciphertext, tag, additional_data), plaintext,
        )

    def test_aes128_gcm_8_round_trip(self):
        # RFC 5282 §7.2 AES-GCM-8 (transform ID 18): 8-byte tag.
        self._assert_aead_round_trip(
            bulk_cipher=BlockCipher.AES_128,
            block_cipher_mode=BlockCipherMode.GCM_8,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf888'),
            mac_len=8,
        )

    def test_aes128_gcm_12_round_trip(self):
        # RFC 5282 §7.2 AES-GCM-12 (transform ID 19): 12-byte tag.
        self._assert_aead_round_trip(
            bulk_cipher=BlockCipher.AES_128,
            block_cipher_mode=BlockCipherMode.GCM_12,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf888'),
            mac_len=12,
        )

    def test_aes128_ccm_8_round_trip(self):
        # RFC 4309 §4 AES-CCM-8: 8-byte tag. CCM nonce length 7-13; RFC
        # 4309 uses 11 octets (3-octet salt + 8-octet on-wire IV).
        self._assert_aead_round_trip(
            bulk_cipher=BlockCipher.AES_128,
            block_cipher_mode=BlockCipherMode.CCM_8,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf8'),
            mac_len=8,
        )

    def test_aes128_ccm_12_round_trip(self):
        # RFC 4309 §4 AES-CCM-12: 12-byte tag.
        self._assert_aead_round_trip(
            bulk_cipher=BlockCipher.AES_128,
            block_cipher_mode=BlockCipherMode.CCM_12,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf8'),
            mac_len=12,
        )

    def test_aes128_ccm_16_round_trip(self):
        # RFC 4309 §4 AES-CCM-16: 16-byte tag.
        self._assert_aead_round_trip(
            bulk_cipher=BlockCipher.AES_128,
            block_cipher_mode=BlockCipherMode.CCM_16,
            key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            nonce=bytes.fromhex('cafebabefacedbaddecaf8'),
            mac_len=16,
        )

    def test_aes128_ctr_round_trip(self):
        # RFC 5930 AES-CTR: 12-byte nonce prefix (4-byte salt + 8-byte
        # on-wire IV), 4-byte block counter starting at 1.
        key = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
        nonce = bytes.fromhex('cafebabefacedbaddecaf888')
        plaintext = b'inner payload octets for CTR round-trip'
        encryptor = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128, key=key, nonce=nonce,
            block_cipher_mode=BlockCipherMode.CTR, initial_value=1,
        )
        ciphertext = encryptor.encrypt(plaintext)

        decryptor = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_128, key=key, nonce=nonce,
            block_cipher_mode=BlockCipherMode.CTR, initial_value=1,
        )
        self.assertEqual(decryptor.decrypt(ciphertext), plaintext)

    def test_aes192_gcm_round_trip(self):
        # Test vector from NIST SP 800-38D Appendix B.2 (AES-192-GCM, no AAD).
        key = bytes.fromhex(
            'feffe9928665731c6d6a8f9467308308'
            'feffe9928665731c'
        )
        nonce = bytes.fromhex('cafebabefacedbaddecaf888')
        plaintext = bytes.fromhex(
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
            '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'
        )
        encryptor = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_192, key=key, nonce=nonce,
            block_cipher_mode=BlockCipherMode.GCM,
        )
        ciphertext = encryptor.encrypt(plaintext)

        decryptor = CypherBlockCryptodome(
            bulk_cipher=BlockCipher.AES_192, key=key, nonce=nonce,
            block_cipher_mode=BlockCipherMode.GCM,
        )
        self.assertEqual(decryptor.decrypt(ciphertext), plaintext)


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
    def test_supported_key_parameters(self):
        supported = EphemeralKeyExchangeEllipticCurveCryptodome.supported_key_parameters()
        self.assertIsInstance(supported, tuple)
        self.assertGreater(len(supported), 0)
        self.assertIn(ECParamWellKnown.PRIME256V1, supported)
        self.assertIn(ECParamWellKnown.SECP384R1, supported)
        self.assertIn(ECParamWellKnown.SECP521R1, supported)
        self.assertIn(ECParamWellKnown.CURVE25519, supported)
        self.assertIn(ECParamWellKnown.CURVE448, supported)

    def test_montgomery_curve_public_key_bytes(self):
        kex = EphemeralKeyExchangeEllipticCurveCryptodome(key_parameter=ECParamWellKnown.CURVE25519)
        self.assertIsInstance(kex.public_key_bytes, bytes)
        self.assertGreater(len(kex.public_key_bytes), 0)

    def test_montgomery_curve_roundtrip(self):
        kex_a = EphemeralKeyExchangeEllipticCurveCryptodome(key_parameter=ECParamWellKnown.CURVE448)
        kex_b = EphemeralKeyExchangeEllipticCurveCryptodome(key_parameter=ECParamWellKnown.CURVE448)
        self.assertEqual(
            kex_a.compute_shared_secret(kex_b.public_key_bytes),
            kex_b.compute_shared_secret(kex_a.public_key_bytes),
        )


class TestCypherBlockCryptodomeAdditional(unittest.TestCase):
    def test_error_unsupported_block_cipher(self):
        # CHACHA20 is a stream cipher — never a block cipher in this class.
        with self.assertRaises(InvalidValue) as ctx:
            CypherBlockCryptodome(
                bulk_cipher=BlockCipher.CHACHA20,
                key=bytes(32),
                nonce=bytes(12),
                block_cipher_mode=BlockCipherMode.GCM,
            )
        self.assertEqual(ctx.exception.value, BlockCipher.CHACHA20)

    def test_error_unsupported_block_cipher_mode(self):
        # CCM is unsupported (added under §6.8a only CBC + the pre-existing GCM).
        with self.assertRaises(InvalidValue) as ctx:
            CypherBlockCryptodome(
                bulk_cipher=BlockCipher.AES_128,
                key=bytes(16),
                nonce=bytes(12),
                block_cipher_mode=BlockCipherMode.CCM,
            )
        self.assertEqual(ctx.exception.value, BlockCipherMode.CCM)

    def test_error_wrong_nonce_length_for_cbc(self):
        # CBC binds the IV to the block size (16 for AES) — an 8-octet
        # nonce must be rejected rather than silently accepted by
        # PyCryptodome with implementation-defined padding/truncation.
        with self.assertRaises(NotEnoughData) as ctx:
            CypherBlockCryptodome(
                bulk_cipher=BlockCipher.AES_128,
                key=bytes(16),
                nonce=bytes(8),
                block_cipher_mode=BlockCipherMode.CBC,
            )
        self.assertEqual(ctx.exception.bytes_needed, 8)

    def test_error_too_long_nonce_for_cbc(self):
        with self.assertRaises(TooMuchData) as ctx:
            CypherBlockCryptodome(
                bulk_cipher=BlockCipher.AES_128,
                key=bytes(16),
                nonce=bytes(24),
                block_cipher_mode=BlockCipherMode.CBC,
            )
        self.assertEqual(ctx.exception.bytes_needed, 8)


class TestCypherStreamCryptodomeAdditional(unittest.TestCase):
    def test_error_unsupported_stream_cipher(self):
        with self.assertRaises(InvalidValue) as ctx:
            CypherStreamCryptodome(
                bulk_cipher=BlockCipher.AES_128,
                key=bytes(32),
                nonce=bytes(12),
            )
        self.assertEqual(ctx.exception.value, BlockCipher.AES_128)

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

    def test_encrypt_and_digest(self):
        # RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 Encryption Example.
        # Key, nonce, and AAD taken from the RFC's example; ciphertext
        # and tag are the RFC's expected values (Appendix A / §2.8.2
        # trailing hex dump — 114-octet ciphertext + 16-octet tag).
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
            b"If I could offer you only one tip for the future, "
            b"sunscreen would be it."
        )
        ciphertext, tag = cipher.encrypt_and_digest(plaintext, bytes.fromhex('50515253c0c1c2c3c4c5c6c7'))
        self.assertEqual(
            ciphertext,
            bytes.fromhex(
                'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
                '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36'
                '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc'
                '3ff4def08e4b7a9de576d26586cec64b6116'
            ),
        )
        self.assertEqual(tag, bytes.fromhex('1ae10b594f09e26a7e902ecbd0600691'))


class TestCmacCryptodome(unittest.TestCase):
    """PyCryptodome-backed AES-CMAC (RFC 4493 core, RFC 4494 AES-CMAC-96, RFC 4615 AES-CMAC-PRF-128) — the
    block-cipher-MAC sibling of :class:`HmacCryptodome`."""

    def test_error_unsupported_mac(self):
        with self.assertRaises(InvalidValue) as ctx:
            CmacCryptodome(mac_algorithm=MAC.SHA2_256)
        self.assertEqual(ctx.exception.value, MAC.SHA2_256)

    def test_aes_cmac_96_rfc4494_test_vector(self):
        # RFC 4494 §5 Test Case 1 (len=0), shared with the NIST CMAC
        # test vectors: AES-CMAC-96 truncates the full 128-bit AES-CMAC
        # tag to the leading 96 bits (12 octets).
        result = CmacCryptodome(mac_algorithm=MAC.AES_CMAC_96).digest(
            bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'), b'',
        )
        self.assertEqual(result[:12], bytes.fromhex('bb1d6929e95937287fa37d12'))

    def test_aes_cmac_96_error_too_long_key(self):
        # RFC 4494 §2 pins AES-CMAC-96 to a 16-octet AES-128 key.
        with self.assertRaises(TooMuchData) as ctx:
            CmacCryptodome(mac_algorithm=MAC.AES_CMAC_96).digest(bytes(24), b'data')
        self.assertEqual(ctx.exception.bytes_needed, 8)

    def test_aes_cmac_96_error_too_short_key(self):
        with self.assertRaises(NotEnoughData) as ctx:
            CmacCryptodome(mac_algorithm=MAC.AES_CMAC_96).digest(bytes(8), b'data')
        self.assertEqual(ctx.exception.bytes_needed, 8)

    def test_aes_cmac_prf_128_with_16_octet_key_rfc4615_test_vector(self):
        # RFC 4615 §4 Test Case (Key Length 16): already 16 octets, so
        # ``digest`` skips the K-normalization pre-step and runs
        # AES-CMAC directly over the message.
        result = CmacCryptodome(mac_algorithm=MAC.AES_CMAC_PRF_128).digest(
            bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
            bytes.fromhex('000102030405060708090a0b0c0d0e0f10111213'),
        )
        self.assertEqual(result, bytes.fromhex('980ae87b5f4c9c5214f5b6a8455e4c2d'))

    def test_aes_cmac_prf_128_with_18_octet_key_normalizes_via_rfc4615(self):
        # RFC 4615 §4 Test Case (Key Length 18): VariableKey is not 16
        # octets, so ``digest`` derives K = AES-CMAC(0^128, VariableKey)
        # before running the outer AES-CMAC over the message.
        result = CmacCryptodome(mac_algorithm=MAC.AES_CMAC_PRF_128).digest(
            bytes.fromhex('000102030405060708090a0b0c0d0e0fedcb'),
            bytes.fromhex('000102030405060708090a0b0c0d0e0f10111213'),
        )
        self.assertEqual(result, bytes.fromhex('84a348a4a45d235babfffc0d2b4da09a'))

    def test_aes_cmac_prf_128_with_10_octet_key_normalizes_via_rfc4615(self):
        # RFC 4615 §4 Test Case (Key Length 10): VariableKey is shorter
        # than 16 octets; K-normalization pads via
        # ``K = AES-CMAC(0^128, VariableKey)`` before the outer CMAC.
        result = CmacCryptodome(mac_algorithm=MAC.AES_CMAC_PRF_128).digest(
            bytes.fromhex('00010203040506070809'),
            bytes.fromhex('000102030405060708090a0b0c0d0e0f10111213'),
        )
        self.assertEqual(result, bytes.fromhex('290d9e112edb09ee141fcf64c0b72f3d'))

    def test_aes_cmac_96_rfc4494_test_case_2_multi_block(self):
        # RFC 4494 §5 Test Case 2 (len=16, 1 block) — exercises
        # PyCryptodome's ``CMAC.update()`` composition alongside the
        # AES-CMAC-96 truncation, on top of the len=0 Test Case 1 above.
        result = CmacCryptodome(mac_algorithm=MAC.AES_CMAC_96).digest(
            bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
            bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'),
        )
        self.assertEqual(result[:12], bytes.fromhex('070a16b46b4d4144f79bdd9d'))

    def test_aes_cmac_96_rfc4494_test_case_3_multi_block(self):
        # RFC 4494 §5 Test Case 3 (len=40, 2 blocks + partial) — proves
        # the ``update()``-then-``digest()`` composition works under
        # 96-bit truncation for messages spanning multiple AES blocks.
        result = CmacCryptodome(mac_algorithm=MAC.AES_CMAC_96).digest(
            bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
            bytes.fromhex(
                '6bc1bee22e409f96e93d7e117393172a'
                'ae2d8a571e03ac9c9eb76fac45af8e51'
                '30c81c46a35ce411'
            ),
        )
        self.assertEqual(result[:12], bytes.fromhex('dfa66747de9ae63030ca3261'))


class TestGmacCryptodome(unittest.TestCase):
    """PyCryptodome-backed AES-GMAC (RFC 4543) — GCM run with empty plaintext, AAD as the authenticated-only message."""

    def test_error_unsupported_block_cipher(self):
        with self.assertRaises(InvalidValue) as ctx:
            GmacCryptodome(block_cipher=BlockCipher.CHACHA20)
        self.assertEqual(ctx.exception.value, BlockCipher.CHACHA20)

    def test_digest_matches_pycryptodome_gcm_empty_plaintext_self_consistency(self):
        # RFC 4543 §3 defines AES-GMAC as AES-GCM run with empty
        # plaintext + AAD as the authenticated-only message.
        # GmacCryptodome.digest is a thin wrapper around exactly that
        # PyCryptodome call sequence, so this is a self-consistency
        # smoke test (proves the wrapper composes update() +
        # encrypt_and_digest(b'') correctly), NOT an RFC-conformance
        # vector — see test_matches_rfc4543_appendix_a_vector below for
        # a published vector cross-check. Key + nonce are borrowed from
        # NIST SP 800-38D Appendix D.1 for readability only.
        key = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
        nonce = bytes.fromhex('cafebabefacedbaddecaf888')
        aad = b'\xaa' * 32

        result = GmacCryptodome(block_cipher=BlockCipher.AES_128).digest(key, nonce, aad)

        reference_cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_GCM, nonce=nonce)
        reference_cipher.update(aad)
        _, reference_tag = reference_cipher.encrypt_and_digest(b'')
        self.assertEqual(result, reference_tag)
        self.assertEqual(len(result), 16)

    def test_digest_matches_nist_gcm_appendix_b_test_case_2(self):
        # NIST GCM test vector — Test Case 2 (empty plaintext, empty AAD)
        # from the McGrew/Viega GCM specification paper (which NIST SP
        # 800-38D references) / dworkin appendix B (AES-128, key = zero,
        # IV = zero, PT = "", AAD = ""). Expected tag comes from the
        # widely-published Test Case 2 result.
        key = bytes.fromhex('00000000000000000000000000000000')
        nonce = bytes.fromhex('000000000000000000000000')
        aad = b''

        result = GmacCryptodome(block_cipher=BlockCipher.AES_128).digest(key, nonce, aad)

        self.assertEqual(result, bytes.fromhex('58e2fccefa7e3061367f1d57a4e7455a'))

    def test_digest_error_too_short_nonce(self):
        key = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
        with self.assertRaises(NotEnoughData) as ctx:
            GmacCryptodome(block_cipher=BlockCipher.AES_128).digest(key, b'\x00' * 8, b'aad')
        self.assertEqual(ctx.exception.bytes_needed, 4)

    def test_digest_error_too_long_nonce(self):
        key = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
        with self.assertRaises(TooMuchData) as ctx:
            GmacCryptodome(block_cipher=BlockCipher.AES_128).digest(key, b'\x00' * 16, b'aad')
        self.assertEqual(ctx.exception.bytes_needed, 4)
