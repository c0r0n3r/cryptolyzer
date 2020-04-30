# -*- coding: utf-8 -*-

import attr

from cryptoparser.tls.subprotocol import TlsAlertDescription


@attr.s
class TlsAlert(ValueError):
    description = attr.ib(validator=attr.validators.in_(TlsAlertDescription))

    def __str__(self):
        return self.__repr__()
