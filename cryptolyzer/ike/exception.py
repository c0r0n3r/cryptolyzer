# SPDX-License-Identifier: MPL-2.0
import typing

import attr

from cryptodatahub.ike.algorithm import Ikev1NotifyType, Ikev2NotifyType

from cryptoparser.ike.ikev1 import Ikev1PayloadNotification
from cryptoparser.ike.ikev2 import Ikev2PayloadNotifyBase


@attr.s
class IsakmpNotify(ValueError):
    notify: typing.Union[Ikev1NotifyType, Ikev2NotifyType] = attr.ib(
        validator=attr.validators.instance_of((Ikev1NotifyType, Ikev2NotifyType))
    )
    payload: typing.Optional[typing.Union[Ikev1PayloadNotification, Ikev2PayloadNotifyBase]] = attr.ib(default=None)

    def __str__(self):
        return self.__repr__()


class Ikev2SkAuthenticationError(ValueError):
    """SK envelope authentication failure (AEAD tag mismatch, HMAC ICV
    mismatch, or ciphertext shorter than the required IV + tag).
    Distinct from generic parse errors so callers can log the failure
    as a cryptographic authentication issue rather than a malformed
    payload chain."""


class Ikev2TransformDerivationError(ValueError):
    """Responder-negotiated transform cannot be mapped to a supported
    cryptographic descriptor (unknown ENCR / PRF / INTEG / DH id, or
    key length that no descriptor covers). Raised from the transform
    resolution helpers so the outer probe can log it as an unsupported
    proposal rather than a protocol parse error."""
