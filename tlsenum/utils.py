import construct


class _UBInt24(construct.Adapter):
    def _encode(self, obj, context):
        return (
            bytes([(obj & 0xFF0000) >> 16]) +
            bytes([(obj & 0x00FF00) >> 8]) +
            bytes([obj & 0x0000FF])
        )

    def _decode(self, obj, context):
        return (obj[0] << 16 | obj[1] << 8 | obj[2])


def UBInt24(name):
    return _UBInt24(construct.Bytes(name, 3))
