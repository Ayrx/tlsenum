from __future__ import absolute_import, division, print_function

import pytest

from construct.core import Construct
from pretend import stub

from tlsenum.utils import _UBInt24


@pytest.mark.parametrize("byte,number", [
    (b"\x00\x00\xFF", 255),
    (b"\x00\xFF\xFF", 65535),
    (b"\xFF\xFF\xFF", 16777215)
])
class TestUBInt24(object):
    def test_encode(self, byte, number):
        ubint24 = _UBInt24(Construct(name="test"))
        assert ubint24._encode(number, context=stub()) == byte

    def test_decode(self, byte, number):
        ubint24 = _UBInt24(Construct(name="test"))
        assert ubint24._decode(byte, context=stub()) == number
