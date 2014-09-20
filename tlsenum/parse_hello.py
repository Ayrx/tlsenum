import time
import os

import construct

from tlsenum import hello_constructs
from tlsenum.cipher_suites import CipherSuites


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

        return hello_constructs.ClientHello.build(
            construct.Container(
                version=protocol_version, random=random, session_id=session_id,
                cipher_suites=ciphers, compression_methods=compression_method,
                extensions_length=0, extensions_bytes=b""
            )
        )

    def _get_bytes_from_cipher_suites(self, cipher_suites):
        return [CipherSuites[i].value for i in cipher_suites]
