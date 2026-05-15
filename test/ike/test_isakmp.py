# SPDX-License-Identifier: MPL-2.0

import collections
import unittest

from cryptodatahub.ike.algorithm import Ikev1ExchangeType, Ikev1PayloadType, Ikev2ExchangeType
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.ike.ikev1 import Ikev1PayloadUnparsed

from cryptolyzer.ike.isakmp import parse_ike_message


class TestParseIkeMessage(unittest.TestCase):
    def test_ikev1_encryption_flag_body_kept_opaque(self):
        # RFC 2408 §3.1: an IKEv1 message with the ``ENCRYPTION`` flag
        # set has its payload chain encrypted under SKEYID_e (e.g.
        # strongSwan emits ``INFORMATIONAL_V1 [ HASH N(AUTH_FAILED) ]``
        # this way when it rejects an Aggressive-Mode probe's auth
        # method). Walking that ciphertext as plaintext misreads the
        # payload-length field and raises ``NotEnoughData``;
        # ``parse_ike_message`` must instead return the message with a
        # single opaque :class:`Ikev1PayloadUnparsed` carrying the
        # ciphertext verbatim so the caller can still inspect
        # ``exchange_type`` and ``flags``.
        ciphertext = b'\xde\xad\xbe\xef' * 20  # 80 bytes
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x08'),  # HASH — plaintext walk would demand more bytes
            ('protocol_version', b'\x10'),  # ISAKMP v1.0
            ('exchange_type', b'\x05'),  # INFORMATIONAL
            ('flags', b'\x01'),  # ENCRYPTION
            ('message_id', b'\x93\xb7\x5d\xd1'),
            ('length', b'\x00\x00\x00\x6c'),  # 28 header + 80 ciphertext
        ])
        wire_bytes = b''.join(header_dict.values()) + ciphertext
        message, parsed_length = parse_ike_message(wire_bytes)
        self.assertEqual(parsed_length, len(wire_bytes))
        self.assertEqual(message.version.major, IkeVersion.V1)
        self.assertEqual(message.exchange_type, Ikev1ExchangeType.INFORMATIONAL)
        self.assertEqual(len(message.payloads), 1)
        self.assertIsInstance(message.payloads[0], Ikev1PayloadUnparsed)
        self.assertEqual(message.payloads[0].payload_data, ciphertext)
        self.assertEqual(message.payloads[0].payload_type, Ikev1PayloadType.HASH)

    def test_ikev1_plaintext_message_walks_chain(self):
        # Baseline: an IKEv1 message with the ENCRYPTION flag cleared
        # goes through the standard plaintext payload-chain walk.
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x00'),  # NONE — empty chain
            ('protocol_version', b'\x11'),  # ISAKMP v1.1
            ('exchange_type', b'\x01'),  # BASE
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1c'),  # 28 bytes header only
        ])
        header_bytes = b''.join(header_dict.values())
        message, parsed_length = parse_ike_message(header_bytes)
        self.assertEqual(parsed_length, len(header_bytes))
        self.assertEqual(message.version.major, IkeVersion.V1)
        self.assertEqual(message.exchange_type, Ikev1ExchangeType.BASE)
        self.assertEqual(message.payloads, [])

    def test_ikev1_encryption_flag_empty_body_walks_chain(self):
        # ENCRYPTION flag set but no body → nothing to wrap; the
        # standard chain walk (which yields an empty payload list)
        # applies.
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x00'),  # NONE
            ('protocol_version', b'\x10'),  # ISAKMP v1.0
            ('exchange_type', b'\x05'),  # INFORMATIONAL
            ('flags', b'\x01'),  # ENCRYPTION
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1c'),  # 28 bytes header only
        ])
        header_bytes = b''.join(header_dict.values())
        message, parsed_length = parse_ike_message(header_bytes)
        self.assertEqual(parsed_length, len(header_bytes))
        self.assertEqual(message.payloads, [])

    def test_ikev2_encryption_flag_ignored(self):
        # IsakmpFlags.ENCRYPTION also has a value in the IKEv2 flags
        # octet (0x01 is IANA "IKEv2 Header Flag Bit 0" = X, reserved
        # by RFC 7296 §3.1 in that direction) but IKEv2 does not use
        # header-level encryption; the SK payload type (RFC 7296
        # §3.14) carries the encrypted inner payload chain instead.
        # ``parse_ike_message`` must NOT trigger the opaque wrap for
        # IKEv2 even when the low bit happens to be set.
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x00'),  # NONE — empty chain, so no body
            ('protocol_version', b'\x20'),  # ISAKMP v2.0
            ('exchange_type', b'\x22'),  # IKE_SA_INIT
            ('flags', b'\x01'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1c'),  # 28 bytes header only
        ])
        header_bytes = b''.join(header_dict.values())
        message, parsed_length = parse_ike_message(header_bytes)
        self.assertEqual(parsed_length, len(header_bytes))
        self.assertEqual(message.version.major, IkeVersion.V2)
        self.assertEqual(message.exchange_type, Ikev2ExchangeType.IKE_SA_INIT)
        self.assertEqual(message.payloads, [])
