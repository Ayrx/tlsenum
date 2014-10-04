import time
import os

import construct
import idna

from tlsenum import hello_constructs
from tlsenum.mappings import CipherSuites, ECCurves, ECPointFormat


class ClientHello(object):

    @property
    def protocol_version(self):
        return self._protocol_version

    @protocol_version.setter
    def protocol_version(self, protocol_version):
        assert protocol_version in ["3.0", "1.0", "1.1", "1.2"]

        self._protocol_version = protocol_version

        if protocol_version == "3.0":
            self._protocol_minor = 0
        elif protocol_version == "1.0":
            self._protocol_minor = 1
        elif protocol_version == "1.1":
            self._protocol_minor = 2
        elif protocol_version == "1.2":
            self._protocol_minor = 3

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
            extensions_length=0, extensions_bytes=b""
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
                handshake=handshake
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

        protocol_minor = server_hello.handshake.handshake_struct.version.minor
        if protocol_minor == 0:
            protocol_version = "3.0"
        elif protocol_minor == 1:
            protocol_version = "1.0"
        elif protocol_minor == 2:
            protocol_version = "1.1"
        elif protocol_minor == 3:
            protocol_version = "1.2"

        cipher_suite = CipherSuites(
            server_hello.handshake.handshake_struct.cipher_suite
        ).name

        if server_hello.handshake.handshake_struct.compression_method == 1:
            deflate = True
        else:
            deflate = False

        return cls(protocol_version, cipher_suite, deflate)
