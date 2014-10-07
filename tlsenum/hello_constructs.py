from __future__ import absolute_import, division, print_function

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
    Array(lambda ctx: ctx.length // 2, UBInt16("cipher_suites"))
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

ServerHello = Struct(
    "ServerHello",
    ProtocolVersion,
    Random,
    SessionID,
    UBInt16("cipher_suite"),
    UBInt8("compression_method")
)

Handshake = Struct(
    "handshake",
    UBInt8("handshake_type"),
    UBInt24("length"),
    Switch("handshake_struct", lambda ctx: ctx.handshake_type, {
        1: ClientHello,
        2: ServerHello
    })
)

Alert = Struct(
    "alert",
    UBInt8("alert_level"),
    UBInt8("alert_description")
)

TLSPlaintext = Struct(
    "TLSPlaintext",
    UBInt8("content_type"),
    ProtocolVersion,
    UBInt16("length"),
    Switch("content", lambda ctx: ctx.content_type, {
        21: Alert,
        22: Handshake
    })
)

ECPointFormat = Struct(
    "ec_point_format",
    UBInt8("ec_point_format_length"),
    Array(lambda ctx: ctx.ec_point_format_length, UBInt8("ec_point_format"))
)

ECCurves = Struct(
    "ec_curves",
    UBInt16("ec_curves_length"),
    Array(lambda ctx: ctx.ec_curves_length // 2, UBInt16("named_curves"))
)

ServerName = Struct(
    "server_name",
    UBInt16("server_name_list_length"),
    UBInt8("name_type"),
    UBInt16("server_name_length"),
    Bytes("server_name", lambda ctx: ctx.server_name_length)
)

Extension = Struct(
    "extension",
    UBInt16("extension_type"),
    UBInt16("extension_length"),
    Switch("extension_struct", lambda ctx: ctx.extension_type, {
        0: ServerName,
        10: ECCurves,
        11: ECPointFormat
    })
)
