# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import attr

from cryptoparser.tls.subprotocol import TlsAlertDescription

from cryptolyzer.common.exception import UnexpectedError


@attr.s
class TlsAlert(ValueError):
    description = attr.ib(validator=attr.validators.in_(TlsAlertDescription))

    def __str__(self):
        return self.__repr__()


class UnexpectedAlertError(UnexpectedError):
    def __init__(self, alert_description):
        super().__init__(f'alert message received ({alert_description.name.lower()})')
