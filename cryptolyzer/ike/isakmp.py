# SPDX-License-Identifier: MPL-2.0

import typing

from cryptodatahub.ike.version import IkeVersion

from cryptoparser.ike.ikev1 import Ikev1PayloadUnparsed
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage


def parse_ike_message(parsable: typing.Union[bytes, bytearray]) -> tuple[IsakmpMessage, int]:
    """Parse a single :class:`IsakmpMessage`, handling the IKEv1
    ``ENCRYPTION`` header flag (RFC 2408 §3.1).

    For IKEv1 messages with ``IsakmpFlags.ENCRYPTION`` set and a non-empty body, the payload chain is ciphertext under
    ``SKEYID_e``; the body is wrapped as a single opaque :class:`cryptoparser.ike.ikev1.Ikev1PayloadUnparsed` so the
    caller can still inspect ``exchange_type`` and header ``flags`` (an IKEv1 INFORMATIONAL rejection is signal enough
    for probe callers).

    All other messages (IKEv2, or IKEv1 without ENCRYPTION) go through the standard plaintext payload-chain walk in
    :meth:`IsakmpMessage.parse_payload_chain`. Signature matches :meth:`IsakmpMessage.parse_immutable` so it can replace
    it at callsites directly.
    """
    header, body_bytes, next_payload = IsakmpMessage.parse_header_and_body(parsable)
    if (
            header['version'].major == IkeVersion.V1
            and IsakmpFlags.ENCRYPTION in header['flags']
            and body_bytes
    ):
        opaque = Ikev1PayloadUnparsed(payload_data=body_bytes)
        opaque.payload_type = next_payload
        payloads = [opaque]
        consumed_length = len(body_bytes)
    else:
        payloads, consumed_length = IsakmpMessage.parse_payload_chain(
            header['version'], body_bytes, next_payload,
        )
    return IsakmpMessage(payloads=payloads, **header), IsakmpMessage.HEADER_SIZE + consumed_length
