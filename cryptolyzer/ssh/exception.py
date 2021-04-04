# -*- coding: utf-8 -*-

import attr
import six

from cryptoparser.ssh.subprotocol import SshReasonCode


@attr.s
class SshDisconnect(ValueError):
    reason = attr.ib(validator=attr.validators.instance_of(SshReasonCode))
    description = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def __str__(self):
        return self.__repr__()
