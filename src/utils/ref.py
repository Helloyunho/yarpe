__all__ = ["refbytearray", "refbytes", "get_ref_addr"]


BYTES_HEADER_LEN = type(b"").__sizeof__(b"") - 1


def refbytearray(data):
    from unsafe import readuint

    # NOTE: take care your object doesn't get GC'd and leave a dangling reference!
    assert isinstance(data, bytearray)
    addr = id(data)
    a = readuint(addr + 8 * 5, 8)  # read the pointer to the underlying buffer
    return a


def refbytes(data):
    # get the address of the internal buffer of a bytes object
    return id(data) + BYTES_HEADER_LEN


def get_ref_addr(obj):
    from structure import StructureInstance

    if isinstance(obj, bytearray):
        return refbytearray(obj)
    elif isinstance(obj, str):
        return refbytes(obj)
    elif isinstance(obj, unicode):
        utf8data = obj.encode("utf-8") + b"\0"
        return refbytes(utf8data)
    elif isinstance(obj, StructureInstance):
        return refbytearray(obj.buf)
    elif isinstance(obj, int):
        return obj
    else:
        raise Exception("Unsupported object type for get_ref_addr")
