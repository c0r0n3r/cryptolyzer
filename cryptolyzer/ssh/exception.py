# -*- coding: utf-8 -*-

import attr

from cryptoparser.ssh.subprotocol import SshReasonCode


@attr.s
class SshDisconnect(ValueError):
    reason = attr.ib(validator=attr.validators.instance_of(SshReasonCode))
    description = attr.ib(validator=attr.validators.instance_of(str))

    def __str__(self):
        return self.__repr__()
