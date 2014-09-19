import construct

from tlsenum import hello_constructs


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


    def build(self):
        return hello_constructs.ProtocolVersion.build(
            construct.Container(major=3, minor=self._protocol_minor)
        )
