#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from crypton.common.exception import NotEnoughData, TooMuchData, InvalidValue
from crypton.common.parse import Parser, ParsableBase, Composer

from tests.common.classes import OneByteParsable, TwoByteParsable, ConditionalParsable


class TestParsable(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(TooMuchData) as context_manager:
            OneByteParsable.parse_exact_bytes(b'\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(NotEnoughData) as context_manager:
            OneByteParsable.parse_immutable_bytes(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(TypeError):
            # pylint: disable=protected-access,abstract-class-instantiated
            ParsableBase()._parse(b'')

        with self.assertRaises(TypeError):
            # pylint: disable=abstract-class-instantiated
            ParsableBase().compose()

    def test_parse(self):
        _, unparsed_bytes = OneByteParsable.parse_immutable_bytes(b'\x01\x02')
        self.assertEqual(unparsed_bytes, b'\x02')

        parsable_bytes = bytearray([0x01, 0x02])
        OneByteParsable.parse_mutable_bytes(parsable_bytes)
        self.assertEqual(parsable_bytes, b'\x02')


class TestParser(unittest.TestCase):
    def test_error(self):
        parser = Parser(b'\x00')
        parser.parse_numeric('one_byte', 1)
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_numeric('one_byte', 1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        parser = Parser(b'\x00\x00\x00\x00')
        parser.parse_numeric('one_byte', 1)
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_numeric_array('four_byte_array', item_num=2, item_size=3)
        self.assertEqual(context_manager.exception.bytes_needed, 3)

        parser = Parser(b'\x00\x00\x00\x00')
        parser.parse_numeric('one_byte', 1)
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_bytes('four_byte_array', 4)
        self.assertEqual(context_manager.exception.bytes_needed, 5)

        parser = Parser(b'\x00\x00\x00\x00\x00')
        with self.assertRaises(NotImplementedError):
            parser.parse_numeric('five_byte_numeric', 5)

        parser = Parser(b'\xff\xff')
        with self.assertRaises(InvalidValue):
            parser.parse_numeric('two_byte_numeric', 2, OneByteParsable)

    def test_parse_numeric(self):
        parser = Parser(b'\x01\x02')
        parser.parse_numeric('first_byte', 1)
        parser.parse_numeric('second_byte', 1)
        self.assertEqual(parser['first_byte'], 0x01)
        self.assertEqual(parser['second_byte'], 0x02)

        parser = Parser(b'\x01\x02')
        parser.parse_numeric('first_two_bytes', 2)
        self.assertEqual(parser['first_two_bytes'], 0x0102)

        parser = Parser(b'\x01\x02\x03')
        parser.parse_numeric('first_two_bytes', 3)
        self.assertEqual(parser['first_two_bytes'], 0x010203)

        parser = Parser(b'\x01\x02\x03\x04')
        parser.parse_numeric('first_four_bytes', 4)
        self.assertEqual(parser['first_four_bytes'], 0x01020304)

    def test_parse_numeric_array(self):
        parser = Parser(b'\x01\x02')
        parser.parse_numeric_array('one_byte_array', item_num=2, item_size=1)
        self.assertEqual(parser['one_byte_array'], [1, 2])

        parser = Parser(b'\x00\x01\x00\x02')
        parser.parse_numeric_array('two_byte_array', item_num=2, item_size=2)
        self.assertEqual(parser['two_byte_array'], [1, 2])

        parser = Parser(b'\x00\x00\x01\x00\x00\x02')
        parser.parse_numeric_array('three_byte_array', item_num=2, item_size=3)
        self.assertEqual(parser['three_byte_array'], [1, 2])

        parser = Parser(b'\x00\x00\x00\x01\x00\x00\x00\x02')
        parser.parse_numeric_array('four_byte_array', item_num=2, item_size=4)
        self.assertEqual(parser['four_byte_array'], [1, 2])

    def test_parse_byte_array(self):
        parser = Parser(b'\x01\x02')
        parser.parse_bytes('two_byte_array', size=2)
        self.assertEqual(parser['two_byte_array'], b'\x01\x02')

    def test_parse_parsable(self):
        parser = Parser(b'\x01\x02\x03\x04')

        parser.parse_parsable('first_byte', OneByteParsable)
        self.assertEqual(
            b'\x01',
            parser['first_byte'].compose()
        )

        parser.parse_parsable('second_byte', OneByteParsable)
        self.assertEqual(
            b'\x02',
            parser['second_byte'].compose()
        )

    def test_parse_parsable_array(self):
        parser = Parser(b'\x01\x02\x03\x04')
        parser.parse_parsable_array('array', items_size=4, item_class=OneByteParsable)
        self.assertEqual(
            [0x01, 0x02, 0x03, 0x04],
            list(map(int, parser['array']))
        )

        parser = Parser(b'\x01\x02\x03\x04')
        parser.parse_parsable_array('array', items_size=4, item_class=TwoByteParsable)
        self.assertEqual(
            [0x0102, 0x0304],
            list(map(int, parser['array']))
        )

    def test_parse_parsable_derived_array(self):
        parser = Parser(b'\x01\x02\x00')
        parser.parse_parsable_derived_array(
            'array',
            items_size=3,
            item_base_class=ConditionalParsable,
            fallback_class=None
        )
        self.assertEqual(
            [0x01, 0x0200],
            list(map(int, parser['array']))
        )
        self.assertEqual(parser.unparsed_bytes, b'')

        parser = Parser(b'\x00\x01')
        with self.assertRaises(InvalidValue):
            parser.parse_parsable_derived_array(
                'array',
                items_size=2,
                item_base_class=ConditionalParsable,
                fallback_class=None
            )

        parser = Parser(b'\x00\x01')
        parser.parse_parsable_derived_array(
            'array',
            items_size=2,
            item_base_class=ConditionalParsable,
            fallback_class=TwoByteParsable
        )
        self.assertEqual(
            [0x01, ],
            list(map(int, parser['array']))
        )
        self.assertEqual(parser.unparsed_bytes, b'')


class TestComposer(unittest.TestCase):
    def test_error(self):
        composer = Composer()

        for size in (1, 2, 4):
            min_value = 0
            max_value = 2 ** (size * 8)

            with self.assertRaises(InvalidValue) as context_manager:
                composer.compose_numeric(max_value + 1, size)
            self.assertEqual(context_manager.exception.value, max_value + 1)

            with self.assertRaises(InvalidValue) as context_manager:
                composer.compose_numeric(min_value - 1, size)
            self.assertEqual(context_manager.exception.value, min_value - 1)

    def test_compose_numeric_to_right_size(self):
        composer = Composer()
        composer.compose_numeric(0x01, 1)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer = Composer()
        composer.compose_numeric(0x01, 2)
        self.assertEqual(composer.composed_bytes, b'\x00\x01')

        composer = Composer()
        composer.compose_numeric(0x01, 3)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x01')

        composer = Composer()
        composer.compose_numeric(0x01, 4)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x01')

    def test_compose_numeric_to_rigth_order(self):
        composer = Composer()
        composer.compose_numeric(0x01, 1)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer = Composer()
        composer.compose_numeric(0x0102, 2)
        self.assertEqual(composer.composed_bytes, b'\x01\x02')

        composer = Composer()
        composer.compose_numeric(0x010203, 3)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03')

        composer = Composer()
        composer.compose_numeric(0x01020304, 4)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

    def test_compose_numeric_array(self):
        composer = Composer()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=1)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

        composer = Composer()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=2)
        self.assertEqual(composer.composed_bytes, b'\x00\x01\x00\x02\x00\x03\x00\x04')

        composer = Composer()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=3)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x01\x00\x00\x02\x00\x00\x03\x00\x00\x04')

        composer = Composer()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=4)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04')

    def test_compose_bytes(self):
        composer = Composer()

        composer.compose_bytes(b'\x01\x02\x03\x04')

        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

    def test_compose_multiple(self):
        composer = Composer()

        one_byte_parsable = OneByteParsable(0x01)
        composer.compose_parsable(one_byte_parsable)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer.compose_numeric(0x02, 1)
        self.assertEqual(composer.composed_bytes, b'\x01\x02')
        self.assertEqual(composer.composed_byte_num, 2)

        composer.compose_numeric(0x0304, 2)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')
        self.assertEqual(composer.composed_byte_num, 4)

        composer.compose_numeric(0x050607, 3)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04\x05\x06\x07')
        self.assertEqual(composer.composed_byte_num, 7)

        composer.compose_numeric(0x08090a0b, 4)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b')
        self.assertEqual(composer.composed_byte_num, 11)

    def test_compose_parsable_array(self):
        composer = Composer()
        parsable_array = [OneByteParsable(0x01), TwoByteParsable(0x0203), ]
        composer.compose_parsable_array(parsable_array)

        self.assertEqual(
            b'\x01\x02\x03',
            composer.composed_bytes
        )
