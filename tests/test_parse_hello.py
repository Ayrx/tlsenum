import pytest

from tlsenum.parse_hello import ClientHello


@pytest.mark.parametrize("version_string,protocol_minor", [
    ("3.0", 0), ("1.0", 1), ("1.1", 2), ("1.2", 3)
])
def test_protocol_version(version_string, protocol_minor):
    msg = ClientHello()
    msg.protocol_version = version_string
    assert msg._protocol_minor == protocol_minor
    assert msg.protocol_version == version_string


@pytest.mark.parametrize("deflate,result", [
    (True, [1, 0]), (False, [0])
])
def test_compression_method(deflate, result):
    msg = ClientHello()
    msg.deflate = deflate
    assert msg._compression_method == result
    assert msg.deflate is deflate
