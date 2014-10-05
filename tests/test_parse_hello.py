import pytest

from tlsenum.parse_hello import (
    ClientHello, Extensions, HandshakeFailure, ServerHello
)


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

    def test_extensions(self):
        msg = ClientHello()
        msg.extensions = b"mock"
        assert msg.extensions == b"mock"

    def test_build(self, monkeypatch):
        def mock_urandom(len):
            return (
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )

        monkeypatch.setattr("time.time", lambda: 0)
        monkeypatch.setattr("os.urandom", mock_urandom)

        msg = ClientHello()
        msg.protocol_version = "1.2"
        msg.deflate = False
        msg.cipher_suites = ["TLS_RSA_WITH_NULL_MD5"]
        msg.extensions = b""

        assert msg.build() == (
            b"\x16"
            b"\x03\x03"
            b"\x00\x2F"
            b"\x01"
            b"\x00\x00\x2B"
            b"\x03\x03"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00"
            b"\x00\x02\x00\x01"
            b"\x01\x00"
            b"\x00\x00"
        )


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

    def test_ec_curves(self):
        extension = Extensions()
        extension.ec_curves = ["sect163k1", "sect163r1", "sect163r2"]
        assert extension.ec_curves == ["sect163k1", "sect163r1", "sect163r2"]
        assert extension.build() == (
            b"\x00\x0A\x00\x08\x00\x06\x00\x01\x00\x02\x00\x03"
        )

    def test_get_bytes_from_ec_curves(self):
        extension = Extensions()
        assert extension._get_bytes_from_ec_curves([
            "sect163k1", "sect163r1", "sect163r2"
        ]) == [1, 2, 3]

    def test_sni_extension(self):
        extension = Extensions()
        extension.sni = "ayrx.me"
        assert extension.sni == "ayrx.me"
        assert extension.build() == (
            b"\x00\x00\x00\x0C\x00\x0A\x00\x00\x07\x61\x79\x72\x78\x2E\x6D\x65"
        )


class TestServerHello(object):
    def test_parse_server_hello(self):
        deflate_no = (
            b"\x16\x03\x03\x00\x2A\x02\x00\x00\x26\x03\x03\xB5\xA4\x22\x01\x18"
            b"\xC5\x71\x41\x97\x6D\xC7\x06\x14\xC0\xE5\x78\x7A\xF3\x1D\x4E\x56"
            b"\x98\xCC\x7A\x37\xAE\x6F\x1D\xC6\xF0\x78\x68\x00\xC0\x2F\x00"
        )

        server_hello = ServerHello.parse_server_hello(deflate_no)
        assert server_hello.protocol_version == "1.2"
        assert server_hello.deflate is False
        assert server_hello.cipher_suite == (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        )

        deflate_yes = (
            b"\x16\x03\x03\x00\x2A\x02\x00\x00\x26\x03\x03\xB5\xA4\x22\x01\x18"
            b"\xC5\x71\x41\x97\x6D\xC7\x06\x14\xC0\xE5\x78\x7A\xF3\x1D\x4E\x56"
            b"\x98\xCC\x7A\x37\xAE\x6F\x1D\xC6\xF0\x78\x68\x00\xC0\x2F\x01"
        )

        server_hello = ServerHello.parse_server_hello(deflate_yes)
        assert server_hello.protocol_version == "1.2"
        assert server_hello.deflate is True
        assert server_hello.cipher_suite == (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        )

    def test_parse_alert(self):
        handshake_failure_alert_msg = b"\x15\x03\x03\x00\x02\x02\x28"
        with pytest.raises(HandshakeFailure):
            ServerHello.parse_server_hello(handshake_failure_alert_msg)

        close_notify_alert_msg = b"\x15\x03\x03\x00\x02\x02\x00"
        with pytest.raises(ValueError):
            ServerHello.parse_server_hello(close_notify_alert_msg)
