from etc import bytes

__all__ = ["u64", "u64_to_i64", "u32_to_i32", "get_cstring"]


# technically this can unpack an int of any size
# py2-compatible equivalent of int.from_bytes(n, "little")
def u64(buf):
    n = 0
    for c in reversed(buf):
        n <<= 8
        n += c
    return n


def u64_to_i64(n):
    n = n & 0xFFFFFFFFFFFFFFFF
    if n >= (1 << 63):
        n -= 1 << 64
    return n


def u32_to_i32(n):
    n = n & 0xFFFFFFFF
    if n >= (1 << 31):
        n -= 1 << 32
    return n


def get_cstring(data, addr=0):
    name = []
    name_addr = addr
    while True:
        c = data[name_addr]
        if c == 0 or c == b"\0":
            break
        name.append(c)
        name_addr += 1
    name = bytes(name)
    return name
