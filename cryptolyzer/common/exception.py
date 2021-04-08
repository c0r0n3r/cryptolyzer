# -*- coding: utf-8 -*-

import enum
import attr


class NetworkErrorType(enum.Enum):
    NO_CONNECTION = 'connection to target cannot be established'
    NO_RESPONSE = 'no response received from target'
    NO_ADDRESS = 'address of the target cannot be resolved'


@attr.s
class NetworkError(IOError):
    error = attr.ib(validator=attr.validators.in_(NetworkErrorType))

    def __str__(self):
        return self.error.value


class SecurityErrorType(enum.Enum):
    PLAIN_TEXT_MESSAGE = 'plain text response reveived instead of binary from target'
    UNPARSABLE_MESSAGE = 'unparsable message received from target'
    UNSUPPORTED_SECURITY = 'target does not support secure communication'


@attr.s
class SecurityError(ValueError):
    error = attr.ib(validator=attr.validators.in_(SecurityErrorType))

    def __str__(self):
        return self.error.value
