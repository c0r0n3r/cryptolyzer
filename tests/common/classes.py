#!/usr/bin/env python
# -*- coding: utf-8 -*-

from crypton.common.parse import Parser, ParsableBase, Composer

class NByteParsable(ParsableBase):
    def __init__(self, value):
        if value < 0 or value >= 2 ** (8 * self.BYTE_SIZE):
            raise ValueError

        self.value = value

    def __int__(self):
        return self.value

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('value', cls.BYTE_SIZE)

        return cls(parser['value']), cls.BYTE_SIZE

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.value, self.BYTE_SIZE)

        return composer.composed_bytes

    def __repr__(self):
        return '{0:#0{1}x}'.format(self.value, self.BYTE_SIZE * 2 + 2)

    def __eq__(self, other):
        return self.BYTE_SIZE == other.BYTE_SIZE and self.value == other.value


class OneByteParsable(NByteParsable):
    BYTE_SIZE = 1


class TwoByteParsable(NByteParsable):
    BYTE_SIZE = 2
