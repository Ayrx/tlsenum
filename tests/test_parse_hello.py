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
