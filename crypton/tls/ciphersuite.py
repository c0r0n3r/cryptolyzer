#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum
import collections

from crypton.common.algorithm import Authentication, BlockCipher, BlockCipherMode, KeyExchange, MAC
from crypton.common.parse import ParsableBase, Parser, Composer
from crypton.common.base import TwoByteEnumComposer, TwoByteEnumParsable

CipherSuiteParams = collections.namedtuple(
    'TlsCipherSuiteParams',
    [
        'code',
        'key_exchange',
        'authentication', 
        'block_cipher',
        'block_cipher_mode',
        'mac',
    ]
)


class TlsCipherSuiteFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsCipherSuite


class TlsCipherSuite(TwoByteEnumComposer, enum.Enum):
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc012,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_NULL_WITH_NULL_NULL = CipherSuiteParams(
         code=0x0000,
         key_exchange=None,
         authentication=None,
         block_cipher=None,
         block_cipher_mode=None,
         mac=None,
    )
    TLS_RSA_WITH_NULL_MD5 = CipherSuiteParams(
         code=0x0001,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.MD5,
    )
    TLS_RSA_WITH_NULL_SHA = CipherSuiteParams(
         code=0x0002,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = CipherSuiteParams(
         code=0x0003,
         key_exchange=KeyExchange.RSA_EXPORT,
         authentication=Authentication.RSA_EXPORT,
         block_cipher=BlockCipher.RC4_40,
         block_cipher_mode=None,
         mac=MAC.MD5,
    )
    TLS_RSA_WITH_RC4_128_MD5 = CipherSuiteParams(
         code=0x0004,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.MD5,
    )
    TLS_RSA_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0x0005,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = CipherSuiteParams(
         code=0x0006,
         key_exchange=KeyExchange.RSA_EXPORT,
         authentication=Authentication.RSA_EXPORT,
         block_cipher=BlockCipher.RC2_40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.MD5,
    )
    TLS_RSA_WITH_IDEA_CBC_SHA = CipherSuiteParams(
         code=0x0007,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.IDEA,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
         code=0x0008,
         key_exchange=KeyExchange.RSA_EXPORT,
         authentication=Authentication.RSA_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_WITH_DES_CBC_SHA = CipherSuiteParams(
         code=0x0009,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x000a,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
         code=0x000b,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_WITH_DES_CBC_SHA = CipherSuiteParams(
         code=0x000c,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x000d,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
         code=0x000e,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_WITH_DES_CBC_SHA = CipherSuiteParams(
         code=0x000f,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x0010,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
         code=0x0011,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_WITH_DES_CBC_SHA = CipherSuiteParams(
         code=0x0012,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x0013,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
         code=0x0014,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_DES_CBC_SHA = CipherSuiteParams(
         code=0x0015,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x0016,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = CipherSuiteParams(
         code=0x0017,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.anon_EXPORT,
         block_cipher=BlockCipher.RC4_40,
         block_cipher_mode=None,
         mac=MAC.MD5,
    )
    TLS_DH_anon_WITH_RC4_128_MD5 = CipherSuiteParams(
         code=0x0018,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.MD5,
    )
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
         code=0x0019,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.anon_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_WITH_DES_CBC_SHA = CipherSuiteParams(
         code=0x001a,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x001b,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_KRB5_WITH_DES_CBC_SHA = CipherSuiteParams(
         code=0x001e,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x001f,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_KRB5_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0x0020,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_KRB5_WITH_IDEA_CBC_SHA = CipherSuiteParams(
         code=0x0021,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.IDEA,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_KRB5_WITH_DES_CBC_MD5 = CipherSuiteParams(
         code=0x0022,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.DES,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.MD5,
    )
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = CipherSuiteParams(
         code=0x0023,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.MD5,
    )
    TLS_KRB5_WITH_RC4_128_MD5 = CipherSuiteParams(
         code=0x0024,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.MD5,
    )
    TLS_KRB5_WITH_IDEA_CBC_MD5 = CipherSuiteParams(
         code=0x0025,
         key_exchange=KeyExchange.KRB5,
         authentication=Authentication.KRB5,
         block_cipher=BlockCipher.IDEA,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.MD5,
    )
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = CipherSuiteParams(
         code=0x0026,
         key_exchange=KeyExchange.KRB5_EXPORT,
         authentication=Authentication.KRB5_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = CipherSuiteParams(
         code=0x0027,
         key_exchange=KeyExchange.KRB5_EXPORT,
         authentication=Authentication.KRB5_EXPORT,
         block_cipher=BlockCipher.RC2_40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA = CipherSuiteParams(
         code=0x0028,
         key_exchange=KeyExchange.KRB5_EXPORT,
         authentication=Authentication.KRB5_EXPORT,
         block_cipher=BlockCipher.RC4_40,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = CipherSuiteParams(
         code=0x0029,
         key_exchange=KeyExchange.KRB5_EXPORT,
         authentication=Authentication.KRB5_EXPORT,
         block_cipher=BlockCipher.DES40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.MD5,
    )
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = CipherSuiteParams(
         code=0x002a,
         key_exchange=KeyExchange.KRB5_EXPORT,
         authentication=Authentication.KRB5_EXPORT,
         block_cipher=BlockCipher.RC2_40,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.MD5,
    )
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = CipherSuiteParams(
         code=0x002b,
         key_exchange=KeyExchange.KRB5_EXPORT,
         authentication=Authentication.KRB5_EXPORT,
         block_cipher=BlockCipher.RC4_40,
         block_cipher_mode=None,
         mac=MAC.MD5,
    )
    TLS_PSK_WITH_NULL_SHA = CipherSuiteParams(
         code=0x002c,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_DHE_PSK_WITH_NULL_SHA = CipherSuiteParams(
         code=0x002d,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_RSA_PSK_WITH_NULL_SHA = CipherSuiteParams(
         code=0x002e,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x002f,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x0030,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x0031,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x0032,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x0033,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x0034,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x0035,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x0036,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x0037,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x0038,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x0039,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x003a,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_WITH_NULL_SHA256 = CipherSuiteParams(
         code=0x003b,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x003c,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
         code=0x003d,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x003e,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x003f,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x0040,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
         code=0x0041,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
         code=0x0042,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
         code=0x0043,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
         code=0x0044,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
         code=0x0045,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
         code=0x0046,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x0067,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
         code=0x0068,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
         code=0x0069,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
         code=0x006a,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
         code=0x006b,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x006c,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
         code=0x006d,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
         code=0x0084,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
         code=0x0085,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
         code=0x0086,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
         code=0x0087,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
         code=0x0088,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
         code=0x0089,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0x008a,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x008b,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x008c,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x008d,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0x008e,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x008f,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x0090,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x0091,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0x0092,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0x0093,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0x0094,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0x0095,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_WITH_SEED_CBC_SHA = CipherSuiteParams(
         code=0x0096,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.SEED,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_DSS_WITH_SEED_CBC_SHA = CipherSuiteParams(
         code=0x0097,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.SEED,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_RSA_WITH_SEED_CBC_SHA = CipherSuiteParams(
         code=0x0098,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.SEED,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_DSS_WITH_SEED_CBC_SHA = CipherSuiteParams(
         code=0x0099,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.SEED,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = CipherSuiteParams(
         code=0x009a,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.SEED,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_DH_anon_WITH_SEED_CBC_SHA = CipherSuiteParams(
         code=0x009b,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.SEED,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x009c,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x009d,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x009e,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x009f,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x00a0,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x00a1,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x00a2,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x00a3,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x00a4,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x00a5,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_anon_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x00a6,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x00a7,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_PSK_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x00a8,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x00a9,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x00aa,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x00ab,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0x00ac,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0x00ad,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00ae,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0x00af,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
         code=0x00b0,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
         code=0x00b1,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA384,
    )
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00b2,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0x00b3,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DHE_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
         code=0x00b4,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
         code=0x00b5,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA384,
    )
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00b6,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0x00b7,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_RSA_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
         code=0x00b8,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
         code=0x00b9,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA384,
    )
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00ba,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00bb,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00bc,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00bd,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00be,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0x00bf,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
         code=0x00c0,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
         code=0x00c1,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
         code=0x00c2,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
         code=0x00c3,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
         code=0x00c4,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
         code=0x00c5,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDH_ECDSA_WITH_NULL_SHA = CipherSuiteParams(
         code=0xc001,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0xc002,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc003,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc004,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc005,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = CipherSuiteParams(
         code=0xc006,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0xc007,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc008,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc009,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc00a,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_RSA_WITH_NULL_SHA = CipherSuiteParams(
         code=0xc00b,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDH_RSA_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0xc00c,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc00d,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc00e,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc00f,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_RSA_WITH_NULL_SHA = CipherSuiteParams(
         code=0xc010,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0xc011,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc013,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc014,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_anon_WITH_NULL_SHA = CipherSuiteParams(
         code=0xc015,
         key_exchange=KeyExchange.ECDH,
         authentication=None,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDH_anon_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0xc016,
         key_exchange=KeyExchange.ECDH,
         authentication=None,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc017,
         key_exchange=KeyExchange.ECDH,
         authentication=None,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc018,
         key_exchange=KeyExchange.ECDH,
         authentication=None,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc019,
         key_exchange=KeyExchange.ECDH,
         authentication=None,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc01a,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.SRP,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc01b,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc01c,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc01d,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.SRP,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc01e,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_DSS_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc01f,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc020,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.SRP,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc021,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_SRP_DSS_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc022,
         key_exchange=KeyExchange.SRP,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc023,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc024,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc025,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc026,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc027,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc028,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc029,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc02a,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc02b,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc02c,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc02d,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc02e,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc02f,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc030,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc031,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc032,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
         code=0xc033,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.RC4_128,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
         code=0xc034,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.TRIPLE_DES_EDE,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
         code=0xc035,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
         code=0xc036,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA,
    )
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc037,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc038,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_PSK_WITH_NULL_SHA = CipherSuiteParams(
         code=0xc039,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA,
    )
    TLS_ECDHE_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
         code=0xc03a,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
         code=0xc03b,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=None,
         block_cipher_mode=None,
         mac=MAC.SHA384,
    )
    TLS_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc03c,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc03d,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc03e,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc03f,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc040,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc041,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc042,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc043,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc044,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc045,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc046,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc047,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc048,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc049,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc04a,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc04b,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc04c,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc04d,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc04e,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc04f,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc050,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc051,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc052,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc053,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc054,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc055,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc056,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc057,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc058,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc059,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc05a,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc05b,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc05c,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc05d,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc05e,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc05f,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc060,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc061,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc062,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc063,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc064,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc065,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc066,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc067,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc068,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc069,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc06a,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc06b,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc06c,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc06d,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc06e,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc06f,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc070,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc071,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.ARIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc072,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc073,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc074,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc075,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc076,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc077,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc078,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc079,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc07a,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc07b,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc07c,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc07d,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc07e,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc07f,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc080,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc081,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc082,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc083,
         key_exchange=KeyExchange.DH,
         authentication=Authentication.DSS,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc084,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc085,
         key_exchange=KeyExchange.DH,
         authentication=None,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc086,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc087,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc088,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc089,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc08a,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc08b,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc08c,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc08d,
         key_exchange=KeyExchange.ECDH,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc08e,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc08f,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc090,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc091,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
         code=0xc092,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
         code=0xc093,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.GCM,
         mac=MAC.SHA384,
    )
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc094,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc095,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc096,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc097,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc098,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc099,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
         code=0xc09a,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_128,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
         code=0xc09b,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CAMELLIA_256,
         block_cipher_mode=BlockCipherMode.CBC,
         mac=MAC.SHA384,
    )
    TLS_RSA_WITH_AES_128_CCM = CipherSuiteParams(
         code=0xc09c,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_RSA_WITH_AES_256_CCM = CipherSuiteParams(
         code=0xc09d,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_DHE_RSA_WITH_AES_128_CCM = CipherSuiteParams(
         code=0xc09e,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_DHE_RSA_WITH_AES_256_CCM = CipherSuiteParams(
         code=0xc09f,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_RSA_WITH_AES_128_CCM_8 = CipherSuiteParams(
         code=0xc0a0,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_RSA_WITH_AES_256_CCM_8 = CipherSuiteParams(
         code=0xc0a1,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = CipherSuiteParams(
         code=0xc0a2,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = CipherSuiteParams(
         code=0xc0a3,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_PSK_WITH_AES_128_CCM = CipherSuiteParams(
         code=0xc0a4,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_PSK_WITH_AES_256_CCM = CipherSuiteParams(
         code=0xc0a5,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_DHE_PSK_WITH_AES_128_CCM = CipherSuiteParams(
         code=0xc0a6,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_DHE_PSK_WITH_AES_256_CCM = CipherSuiteParams(
         code=0xc0a7,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_PSK_WITH_AES_128_CCM_8 = CipherSuiteParams(
         code=0xc0a8,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_PSK_WITH_AES_256_CCM_8 = CipherSuiteParams(
         code=0xc0a9,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_DHE_PSK_WITH_AES_128_CCM_8 = CipherSuiteParams(
         code=0xc0aa,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_DHE_PSK_WITH_AES_256_CCM_8 = CipherSuiteParams(
         code=0xc0ab,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = CipherSuiteParams(
         code=0xc0ac,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = CipherSuiteParams(
         code=0xc0ad,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM,
         mac=None,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = CipherSuiteParams(
         code=0xc0ae,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_128,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = CipherSuiteParams(
         code=0xc0af,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.AES_256,
         block_cipher_mode=BlockCipherMode.CCM_8,
         mac=None,
    )
    OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xcc13,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xcc14,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xcc15,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xcca8,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xcca9,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.ECDSA,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xccaa,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.RSA,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xccab,
         key_exchange=KeyExchange.PSK,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xccac,
         key_exchange=KeyExchange.ECDHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xccad,
         key_exchange=KeyExchange.DHE,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
         code=0xccae,
         key_exchange=KeyExchange.RSA,
         authentication=Authentication.PSK,
         block_cipher=BlockCipher.CHACHA20,
         block_cipher_mode=BlockCipherMode.POLY1305,
         mac=MAC.SHA256,
    )
