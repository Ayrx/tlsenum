from tlsenum import int_to_hex_octet


def test_int_to_hex_octet():
    assert int_to_hex_octet(255) == (0x00, 0xff)
    assert int_to_hex_octet(1024) == (0x04, 0x00)
