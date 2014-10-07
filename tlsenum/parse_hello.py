from __future__ import absolute_import, division, print_function

import time
import os

import construct
import idna

from tlsenum import hello_constructs
from tlsenum.mappings import (
    CipherSuites, ECCurves, ECPointFormat, TLSProtocolVersion
)


class ClientHello(object):

    @property
    def protocol_version(self):
        return self._protocol_version

    @protocol_version.setter
    def protocol_version(self, protocol_version):
        assert protocol_version in ["3.0", "1.0", "1.1", "1.2"]

        self._protocol_version = protocol_version
        self._protocol_minor = TLSProtocolVersion.index(protocol_version)

    @property
    def cipher_suites(self):
        return self._cipher_suites

    @cipher_suites.setter
    def cipher_suites(self, cipher_suites):
        self._cipher_suites = cipher_suites

    @property
    def deflate(self):
        return self._deflate

    @deflate.setter
    def deflate(self, deflate):
        self._deflate = deflate
        if deflate:
            self._compression_method = [1, 0]
        else:
            self._compression_method = [0]

    @property
    def extensions(self):
        return self._extensions

    @extensions.setter
    def extensions(self, value):
        self._extensions = value

    def build(self):
        protocol_version = construct.Container(
            major=3, minor=self._protocol_minor
        )

        random = construct.Container(
            gmt_unix_time=int(time.time()), random_bytes=os.urandom(28)
        )

        session_id = construct.Container(
            length=0, session_id=b""
        )

        ciphers = construct.Container(
            length=len(self._cipher_suites) * 2,
            cipher_suites=self._get_bytes_from_cipher_suites(
                self._cipher_suites
            )
        )

        compression_method = construct.Container(
            length=len(self._compression_method),
            compression_methods=self._compression_method
        )

        client_hello = construct.Container(
            version=protocol_version, random=random, session_id=session_id,
            cipher_suites=ciphers, compression_methods=compression_method,
            extensions_length=len(self._extensions),
            extensions_bytes=self._extensions
        )

        handshake = construct.Container(
            handshake_type=1,
            length=len(hello_constructs.ClientHello.build(client_hello)),
            handshake_struct=client_hello
        )

        return hello_constructs.TLSPlaintext.build(
            construct.Container(
                content_type=0x16, version=protocol_version,
                length=len(hello_constructs.Handshake.build(handshake)),
                content=handshake
            )
        )

    def _get_bytes_from_cipher_suites(self, cipher_suites):
        return [CipherSuites[i].value for i in cipher_suites]


class Extensions(object):

    def __init__(self):
        self._ec_point_format = None
        self._ec_curves = None
        self._hostname = None

    @property
    def ec_point_format(self):
        return self._ec_point_format

    @ec_point_format.setter
    def ec_point_format(self, formats):
        self._ec_point_format = formats

    @property
    def ec_curves(self):
        return self._ec_curves

    @ec_curves.setter
    def ec_curves(self, curves):
        self._ec_curves = curves

    @property
    def sni(self):
        return self._hostname

    @sni.setter
    def sni(self, hostname):
        self._hostname = hostname

    def build(self):
        ret = b""

        if self._ec_point_format is not None:
            ec_point_format_struct = construct.Container(
                ec_point_format_length=len(self._ec_point_format),
                ec_point_format=self._get_bytes_from_ec_point_format(
                    self._ec_point_format
                )
            )
            ret += hello_constructs.Extension.build(
                construct.Container(
                    extension_type=11,
                    extension_length=len(hello_constructs.ECPointFormat.build(
                        ec_point_format_struct
                    )),
                    extension_struct=ec_point_format_struct
                )
            )

        if self._ec_curves is not None:
            ec_curves_struct = construct.Container(
                ec_curves_length=len(self._ec_curves) * 2,
                named_curves=self._get_bytes_from_ec_curves(
                    self._ec_curves
                )
            )
            ret += hello_constructs.Extension.build(
                construct.Container(
                    extension_type=10,
                    extension_length=len(hello_constructs.ECCurves.build(
                        ec_curves_struct
                    )),
                    extension_struct=ec_curves_struct
                )
            )

        if self._hostname is not None:
            encoded_hostname = idna.encode(self._hostname)
            sni_struct = construct.Container(
                server_name_list_length=len(encoded_hostname) + 3,
                name_type=0,
                server_name_length=len(encoded_hostname),
                server_name=encoded_hostname
            )
            ret += hello_constructs.Extension.build(
                construct.Container(
                    extension_type=0,
                    extension_length=len(hello_constructs.ServerName.build(
                        sni_struct
                    )),
                    extension_struct=sni_struct
                )
            )

        return ret

    def _get_bytes_from_ec_point_format(self, ec_point_format):
        return [ECPointFormat[i].value for i in ec_point_format]

    def _get_bytes_from_ec_curves(self, ec_curves):
        return [ECCurves[i].value for i in ec_curves]


class ServerHello(object):

    def __init__(self, protocol_version, cipher_suite, deflate):
        self._protocol_version = protocol_version
        self._cipher_suite = cipher_suite
        self._deflate = deflate

    @property
    def protocol_version(self):
        return self._protocol_version

    @property
    def cipher_suite(self):
        return self._cipher_suite

    @property
    def deflate(self):
        return self._deflate

    @classmethod
    def parse_server_hello(cls, data):
        server_hello = hello_constructs.TLSPlaintext.parse(data)

        if server_hello.content_type == 21:
            if server_hello.content.alert_description == 40:
                raise HandshakeFailure()

            else:
                raise ValueError("Unknown TLS Alert, type {0}".format(
                    server_hello.content.alert_description
                ))

        protocol_minor = server_hello.content.handshake_struct.version.minor

        protocol_version = TLSProtocolVersion[protocol_minor]

        cipher_suite = CipherSuites(
            server_hello.content.handshake_struct.cipher_suite
        ).name

        if server_hello.content.handshake_struct.compression_method == 1:
            deflate = True
        else:
            deflate = False

        return cls(protocol_version, cipher_suite, deflate)


class HandshakeFailure(Exception):
    pass


def construct_sslv2_client_hello():  # pragma: no cover
    """
    Returns a SSLv2 ClientHello message in bytes.

    This is a quick and dirty function to return a SSLv2 ClientHello with all
    7 specified cipher suites. I don't really want to enumerate the supported
    SSLv2 cipher suites so this doesn't have to be flexible...

    This function does not require test coverage because I am simply returning
    bytes constructed from a fix list.

    """
    return bytes([
        0x80, 0x2e,         # Length of record
        0x01,               # Handshake Type (0x01 for ClientHello)
        0x00, 0x02,         # SSL Version Identifier (0x0002 for SSLv2)
        0x00, 0x15,         # Length of cipher suites list
        0x00, 0x00,         # Session ID Length
        0x00, 0x10,         # Challenge Length
        # Cipher suites list
        0x01, 0x00, 0x80,
        0x02, 0x00, 0x80,
        0x03, 0x00, 0x80,
        0x04, 0x00, 0x80,
        0x05, 0x00, 0x80,
        0x06, 0x00, 0x40,
        0x07, 0x00, 0xc0,
        # Challenge
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
        0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
    ])
