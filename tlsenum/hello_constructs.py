from construct import Array, Bytes, Struct, Switch, UBInt16, UBInt32, UBInt8

from tlsenum.utils import UBInt24


ProtocolVersion = Struct(
    "version",
    UBInt8("major"),
    UBInt8("minor")
)

Random = Struct(
    "random",
    UBInt32("gmt_unix_time"),
    Bytes("random_bytes", 28)
)

SessionID = Struct(
    "session_id",
    UBInt8("length"),
    Bytes("session_id", lambda ctx: ctx.length)
)

CipherSuites = Struct(
    "cipher_suites",
    UBInt16("length"),
    Array(lambda ctx: ctx.length / 2, UBInt16("cipher_suites"))
)

CompressionMethods = Struct(
    "compression_methods",
    UBInt8("length"),
    Array(lambda ctx: ctx.length, UBInt8("compression_methods"))
)

ClientHello = Struct(
    "ClientHello",
    ProtocolVersion,
    Random,
    SessionID,
    CipherSuites,
    CompressionMethods,
    UBInt16("extensions_length"),
    Bytes("extensions_bytes", lambda ctx: ctx.extensions_length),
)

Handshake = Struct(
    "handshake",
    UBInt8("handshake_type"),
    UBInt24("length"),
    Switch("handshake_struct", lambda ctx: ctx.handshake_type, {
        0x01: ClientHello
    })
)

TLSPlaintext = Struct(
    "TLSPlaintext",
    UBInt8("content_type"),
    ProtocolVersion,
    UBInt16("length"),
    Handshake
)

ECPointFormat = Struct(
    "extension",
    UBInt16("extension_type"),
    UBInt16("extension_length"),
    UBInt8("ec_point_format_length"),
    Array(lambda ctx: ctx.ec_point_format_length, UBInt8("ec_point_format"))
)
