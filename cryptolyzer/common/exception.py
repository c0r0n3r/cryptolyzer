# -*- coding: utf-8 -*-

import enum


class NetworkErrorType(enum.IntEnum):
    NO_CONNECTION = 0
    NO_RESPONSE = 1
    NO_ADDRESS = 2


class NetworkError(IOError):
    def __init__(self, error):
        super(NetworkError, self).__init__()

        self.error = error


class ResponseErrorType(enum.IntEnum):
    PLAIN_TEXT_RESPONSE = 1
    UNPARSABLE_RESPONSE = 2
    UNSUPPORTED_SECURITY = 3


class ResponseError(ValueError):
    def __init__(self, error):
        super(ResponseError, self).__init__()

        self.error = error
