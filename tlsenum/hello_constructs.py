from construct import Array, Bytes, Struct, UBInt16, UBInt32, UBInt8


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
    Array(lambda ctx: ctx.length, UBInt8("cipher_suites"))
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
