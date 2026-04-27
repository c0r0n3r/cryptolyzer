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
