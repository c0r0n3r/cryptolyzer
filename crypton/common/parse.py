#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import struct

import six

from crypton.common.exception import NotEnoughData, TooMuchData, InvalidValue


@six.add_metaclass(abc.ABCMeta)
class ParsableBase(object):
    @classmethod
    def parse_mutable_bytes(cls, parsable_bytes):
        parsed_object, parsed_byte_num = cls._parse(parsable_bytes)
        del parsable_bytes[:parsed_byte_num]
        return parsed_object

    @classmethod
    def parse_immutable_bytes(cls, parsable_bytes):
        parsed_object, parsed_byte_num = cls._parse(parsable_bytes)
        unparsed_bytes = parsable_bytes[parsed_byte_num:]
        return parsed_object, unparsed_bytes

    @classmethod
    def parse_exact_bytes(cls, parsable_bytes):
        parsed_object, parsed_byte_num = cls._parse(parsable_bytes)
        if len(parsable_bytes) > parsed_byte_num:
            raise TooMuchData(parsed_byte_num)

        return parsed_object

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable_bytes):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class Parser(object):
    __INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
    }

    def __init__(self, parsable_bytes):
        self._parsable_bytes = parsable_bytes
        self._parsed_byte_num = 0
        self._parsed_values = dict()

    def __getitem__(self, key):
        return self._parsed_values[key]

    @property
    def parsed_byte_num(self):
        return self._parsed_byte_num

    @property
    def unparsed_byte_num(self):
        return len(self._parsable_bytes) - self._parsed_byte_num

    def _parse_numeric_array(self, name, item_num, item_size, item_numeric_class):
        if self._parsed_byte_num + (item_num * item_size) > len(self._parsable_bytes):
            raise NotEnoughData(bytes_needed=(item_num * item_size) - self.unparsed_byte_num)

        if item_size in self.__INT_FORMATER_BY_SIZE:
            value = list()
            for item_offset in range(self._parsed_byte_num, self._parsed_byte_num + (item_num * item_size), item_size):
                item_bytes = self._parsable_bytes[item_offset:item_offset + item_size]
                if item_size == 3:
                    item_bytes = b'\x00' + item_bytes

                item = struct.unpack(
                    self.__INT_FORMATER_BY_SIZE[item_size],
                    item_bytes
                )[0]
                try:
                    value.append(item_numeric_class(item))
                except ValueError:
                    raise InvalidValue(item, item_numeric_class)
        else:
            raise NotImplementedError()

        self._parsed_byte_num += item_num * item_size
        self._parsed_values[name] = value

    def parse_numeric(self, name, size, numeric_class=int):
        self._parse_numeric_array(name, 1, size, numeric_class)
        self._parsed_values[name] = self._parsed_values[name][0]

    def parse_numeric_array(self, name, item_num, item_size, numeric_class=int):
        self._parse_numeric_array(name, item_num, item_size, numeric_class)

    def parse_bytes(self, name, size):
        if self.unparsed_byte_num < size:
            raise NotEnoughData(bytes_needed=self._parsed_byte_num + size)

        self._parsed_values[name] = self._parsable_bytes[self._parsed_byte_num: self._parsed_byte_num + size]
        self._parsed_byte_num += size

    def parse_parsable(self, name, parsable_class):
        parsed_object, unparsed_bytes = parsable_class.parse_immutable_bytes(
            self._parsable_bytes[self._parsed_byte_num:]
        )
        self._parsed_byte_num += len(self._parsable_bytes) - self._parsed_byte_num - len(unparsed_bytes)
        self._parsed_values[name] = parsed_object


class Composer(object):
    __INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
    }

    def __init__(self):
        self._composed_bytes = bytearray()

    def _compose_numeric_array(self, values, item_size):
        composed_bytes = bytearray()

        for value in values:
            try:
                composed_bytes += struct.pack(
                    self.__INT_FORMATER_BY_SIZE[item_size],
                    value
                )

                if item_size == 3:
                    del composed_bytes[-4]

            except struct.error as e:
                raise InvalidValue(value, int)

        self._composed_bytes += composed_bytes

    def compose_numeric(self, value, size):
        self._compose_numeric_array([value, ], size)

    def compose_numeric_array(self, values, item_size):
        self._compose_numeric_array(values, item_size)

    def compose_parsable(self, value):
        self._composed_bytes += value.compose()

    def compose_bytes(self, value):
        self._composed_bytes += value

    @property
    def composed_bytes(self):
        return bytearray(self._composed_bytes)

    @property
    def composed_byte_num(self):
        return len(self._composed_bytes)
