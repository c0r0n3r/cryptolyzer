# -*- coding: utf-8 -*-

import enum
import attr


class NetworkErrorType(enum.IntEnum):
    NO_CONNECTION = 0
    NO_RESPONSE = 1
    NO_ADDRESS = 2


@attr.s
class NetworkError(IOError):
    error = attr.ib()


class SecurityErrorType(enum.IntEnum):
    PLAIN_TEXT_MESSAGE = 1
    UNPARSABLE_MESSAGE = 2
    UNSUPPORTED_SECURITY = 3


@attr.s
class SecurityError(ValueError):
    error = attr.ib()


@attr.s
class ResponseError(ValueError):
    error = attr.ib()
