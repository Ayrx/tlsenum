import pytest

from tlsenum.parse_hello import ClientHello, Extensions


class TestClientHello(object):
    @pytest.mark.parametrize("version_string,protocol_minor", [
        ("3.0", 0), ("1.0", 1), ("1.1", 2), ("1.2", 3)
    ])
    def test_protocol_version(self, version_string, protocol_minor):
        msg = ClientHello()
        msg.protocol_version = version_string
        assert msg._protocol_minor == protocol_minor
        assert msg.protocol_version == version_string

    @pytest.mark.parametrize("deflate,result", [
        (True, [1, 0]), (False, [0])
    ])
    def test_compression_method(self, deflate, result):
        msg = ClientHello()
        msg.deflate = deflate
        assert msg._compression_method == result
        assert msg.deflate is deflate

    def test_cipher_suites(self):
        msg = ClientHello()
        msg.cipher_suites = ["TLS_NULL_WITH_NULL_NULL"]
        assert msg.cipher_suites == ["TLS_NULL_WITH_NULL_NULL"]

    def test_get_bytes_from_cipher_suites(self):
        msg = ClientHello()
        assert msg._get_bytes_from_cipher_suites(
            ["TLS_NULL_WITH_NULL_NULL", "TLS_RSA_WITH_NULL_MD5"]
        ) == [0, 1]


class TestExtensions(object):
    def test_ec_point_format(self):
        extension = Extensions()
        extension.ec_point_format = [
            "ansiX962_compressed_prime",
            "uncompressed",
            "ansiX962_compressed_char2"
        ]

        assert extension.ec_point_format == [
            "ansiX962_compressed_prime",
            "uncompressed",
            "ansiX962_compressed_char2"
        ]

        assert extension.build() == b"\x00\x0B\x00\x04\x03\x01\x00\x02"

    def test_get_bytes_from_ec_point_format(self):
        extension = Extensions()
        assert extension._get_bytes_from_ec_point_format([
            "ansiX962_compressed_prime",
            "uncompressed",
            "ansiX962_compressed_char2"
        ]) == [1, 0, 2]
