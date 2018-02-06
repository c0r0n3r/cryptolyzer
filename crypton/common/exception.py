#!/usr/bin/env python
# -*- coding: utf-8 -*-


class InvalidDataLength(ValueError):
    def __init__(self, bytes_needed=None):
        super(InvalidDataLength, self).__init__()

        self.bytes_needed = bytes_needed


class NotEnoughData(InvalidDataLength):
    pass


class TooMuchData(InvalidDataLength):
    pass


class InvalidValue(ValueError):
    def __init__(self, value, type_class, class_member=None):
        message = hex(value) if isinstance(value, int) else '{}'.format(value)
        message = '{} is not a valid {}'.format(message, type_class.__name__)
        if class_member is not None:
            message = '{} {} value'.format(message, class_member)

        super(InvalidValue, self).__init__(message)

        self.value = value
