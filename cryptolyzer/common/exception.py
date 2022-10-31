# -*- coding: utf-8 -*-

import enum

import six

import attr


@attr.s
class ErrorParams(object):
    short_description = attr.ib(validator=attr.validators.instance_of(six.string_types))
    long_description = attr.ib(validator=attr.validators.instance_of(six.string_types))


class NetworkErrorType(enum.Enum):
    NO_CONNECTION = ErrorParams(
        short_description='no connection',
        long_description='connection to target cannot be established',
    )
    NO_RESPONSE = ErrorParams(
        short_description='no response',
        long_description='no response received from target',
    )
    NO_ADDRESS = ErrorParams(
        short_description='no address',
        long_description='address of the target cannot be resolved',
    )


@attr.s(frozen=True)
class NetworkError(IOError):
    error = attr.ib(validator=attr.validators.in_(NetworkErrorType))

    def __str__(self):
        return self.error.value.long_description


class SecurityErrorType(enum.Enum):
    PLAIN_TEXT_MESSAGE = ErrorParams(
        short_description='plain text reponse',
        long_description='plain text response reveived instead of binary from target',
    )
    UNPARSABLE_MESSAGE = ErrorParams(
        short_description='unparsable response',
        long_description='unparsable message received from target',
    )
    UNSUPPORTED_SECURITY = ErrorParams(
        short_description='no encryption support',
        long_description='target does not support secure communication',
    )
    UNKNOWN_ERROR = ErrorParams(
        short_description='unknown error',
        long_description='unknown error happened during the handshake with the target',
    )
    NO_SHARED_CIPHER = ErrorParams(
        short_description='no shared cipher',
        long_description='target does not support cipher shared with the client',
    )
    NO_SHARED_VERSION = ErrorParams(
        short_description='no shared version',
        long_description='target does not support version shared with the client',
    )


@attr.s
class SecurityError(ValueError):
    error = attr.ib(validator=attr.validators.in_(SecurityErrorType))

    def __str__(self):
        return self.error.value.long_description
