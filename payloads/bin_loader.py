import math
import struct
from errors.socket import SocketError
from structure import Structure
from sc import sc
from utils.conversion import u64_to_i64
from utils.etc import alloc
from utils.ref import get_ref_addr
from utils.rp import log
from utils.unsafe import readbuf, readuint, writebuf
from constants import SYSCALL, LIBC_OFFSETS

WRITING = False
if WRITING:
    AF_INET = 0
    SOCK_STREAM = 0
    SOL_SOCKET = 0
    SO_REUSEADDR = 0

    port = 0
    s = 0
    sockaddr_in = bytearray()
    len_buf = bytearray()

LIBC_OFFSETS["A YEAR OF SPRINGS"]["PS4"]["Thrd_create"] = 0x4D150
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS4"]["Thrd_create"] = 0x4D150
LIBC_OFFSETS["A YEAR OF SPRINGS"]["PS4"]["Thrd_join"] = 0x4CF50
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS4"]["Thrd_join"] = 0x4CF50

SYSCALL["mmap"] = 477
SYSCALL["munmap"] = 0x49
SYSCALL["getuid"] = 0x18
SYSCALL["is_in_sandbox"] = 0x249


PAGE_SIZE = 0x1000
MAX_PAYLOAD_SIZE = 4 * 1024 * 1024  # 4MB
READ_CHUNK = 4096
ELF_MAGIC = "\x7fELF"

MAP_PRIVATE = 0x2
MAP_ANONYMOUS = 0x1000
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

ELF_HEADER_STRUCT = Structure(
    [
        ("magic", 4),
        ("skip1", 0x14),
        ("e_entry", 8),
        ("e_phoff", 8),
        ("skip2", 0xE),
        ("e_phentsize", 2),
        ("e_phnum", 2),
    ]
)

ELF_SEGMENT_STRUCT = Structure(
    [
        ("p_type", 4),
        ("skip1", 4),
        ("p_offset", 8),
        ("p_vaddr", 8),
        ("skip1", 8),
        ("p_filesz", 8),
        ("p_memsz", 8),
    ]
)


def is_jailbroken():
    return sc.syscalls.getuid() == 0 and sc.syscalls.is_in_sandbox() == 0


def round_up(x, base):
    return math.floor((x + base - 1) / base) * base


def read_elf_header(buf_addr):
    elf_header = ELF_HEADER_STRUCT.from_address(buf_addr)
    return elf_header


def load_elf_segment(buf_addr, base_addr):
    elf = read_elf_header(buf_addr)
    for i in range(len(elf.e_phnum)):
        segment_offset = elf.e_phoff + i * elf.e_phentsize
        segment = ELF_SEGMENT_STRUCT.from_address(buf_addr + segment_offset)

        if segment.p_type == 1 and segment.p_memsz > 0:
            seg_addr = base_addr + (segment.p_vaddr % 0x1000000)
            writebuf(
                seg_addr,
                readbuf(buf_addr + segment.p_offset, segment.p_filesz),
            )

    return base_addr + (elf.e_entry % 0x1000000)


class BinLoader:
    def __init__(self, data):
        self.bin_data = data

        mmap_size = round_up(len(self.bin_data), PAGE_SIZE)
        MAP_COMBINED = MAP_PRIVATE | MAP_ANONYMOUS
        PROT_COMBINED = PROT_READ | PROT_WRITE | PROT_EXEC

        ret = u64_to_i64(
            sc.syscalls.mmap(
                0,
                mmap_size,
                PROT_COMBINED,
                MAP_COMBINED,
                0xFFFFFFFFFFFFFFFF,
                0,
            )
        )
        if ret < 0:
            raise Exception(
                "mmap failed with return value %d, errno: %d"
                % (ret, sc.syscalls.mmap.errno)
            )

        self.mmap_base = ret
        self.mmap_size = mmap_size

        log("mmap() allocated at: 0x%x", self.mmap_base)

        buf_addr = get_ref_addr(self.bin_data)

        # Check ELF magic using raw memory
        magic = readuint(buf_addr, 4)
        if magic == 0x464C457F:
            log("Detected ELF binary, parsing headers...")
            self.bin_entry_point = load_elf_segment(buf_addr, self.mmap_base)
        else:
            log("Non-ELF binary, treating as raw shellcode")
            writebuf(self.mmap_base, self.bin_data)
            self.bin_entry_point = self.mmap_base

        log("Entry point: 0x%x", self.bin_entry_point)

    def run(self):
        thr_handle = alloc(8)

        log("spawning payload")
        sc.send_notification("Spawning payload...")

        # spawn elf in new thread
        ret = sc.functions.Thrd_create(thr_handle, self.bin_entry_point)
        if ret != 0:
            raise Exception("Thrd_create failed with return value %x" % ret)

        self.thr_handle = struct.unpack("<Q", thr_handle)[0]

    def join(self):
        ret = sc.functions.Thrd_join(self.thr_handle, 0)
        if ret != 0:
            raise Exception("Thrd_join failed with return value %x" % ret)

        if (
            u64_to_i64(
                sc.syscalls.munmap(
                    self.mmap_base,
                    self.mmap_size,
                )
            )
            < 0
        ):
            log(
                "munmap failed with return value %d, errno: %d"
                % (ret, sc.syscalls.munmap.errno)
            )


def main():
    if sc.platform != "ps4":
        log("This payload is only for PS4.")
        return

    if not is_jailbroken():
        log("Console is not jailbroken, cannot proceed.")
        return

    buf = alloc(4096)
    payload_data = b""

    ip = sc.get_current_ip()
    if ip is None:
        log("Send payload to port %d" % (port))
    else:
        log("Send payload to %s:%d" % (ip, port))

    client_sock = u64_to_i64(
        sc.syscalls.accept(
            s,
            sockaddr_in,
            len_buf,
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

    log("Client connected on socket %d" % client_sock)

    read_size = -1
    while read_size != 0:
        read_size = u64_to_i64(
            sc.syscalls.read(
                client_sock,
                buf,
                4096,
            )
        )
        payload_data += buf[:read_size]
        if read_size < 0:
            raise SocketError(
                "read failed with return value %d, error %d\n%s"
                % (
                    read_size,
                    sc.syscalls.read.errno,
                    sc.syscalls.read.get_error_string(),
                )
            )

    payload_size = len(payload_data)
    log("Received %d bytes" % payload_size)

    bin = BinLoader(payload_data)
    bin.run()
    bin.join()

    sc.syscalls.close(client_sock)


main()
