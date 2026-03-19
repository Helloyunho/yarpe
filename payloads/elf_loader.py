import struct
import traceback
import os
import pygame_sdl2
from pygame_sdl2 import CONTROLLER_BUTTON_A
from constants import CONSOLE_KIND, SHARED_VARS, SYSCALL
from offsets import LIBC_OFFSETS
from sc import sc
from utils.conversion import u64_to_i64
from utils.etc import alloc
from utils.ref import get_ref_addr
from structure import Structure
from utils.rp import log, log_exc
from utils.tcp import (
    accept_client,
    close_socket,
    create_tcp_server,
    get_socket_name,
    read_all_from_socket,
)
from utils.unsafe import readbuf, writebuf

# Port of https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/elf_loader.lua

PORT = 9021

c = pygame_sdl2.controller.Controller(0)
c.init()
FORCE_SOCKET = c.get_button(CONTROLLER_BUTTON_A) == 1
c.quit()

KERNEL_OFFSETS = {
    "PROC_COMM": 0xFFFFFFFFFFFFFFFF,  # -1
    "PROC_SYSENT": 0xFFFFFFFFFFFFFFFF,  # -1
}

LIBC_OFFSETS["A YEAR OF SPRINGS"]["PS4"]["Thrd_create"] = 0x4D150
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS4"]["Thrd_create"] = 0x4D150
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS5"]["Thrd_create"] = 0x4BF0
LIBC_OFFSETS["A YEAR OF SPRINGS"]["PS4"]["Thrd_join"] = 0x4CF50
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS4"]["Thrd_join"] = 0x4CF50
LIBC_OFFSETS["Arcade Spirits: The New Challengers"]["PS5"]["Thrd_join"] = 0x49F0

SYSCALL["mmap"] = 477
SYSCALL["jitshm_create"] = 0x215
SYSCALL["jitshm_alias"] = 0x216
SYSCALL["dlsym"] = 0x24F

PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

ELF_HEADER_STRUCT = Structure(
    [
        ("magic", 4),
        ("skip1", 0x14),
        ("e_entry", 8),
        ("e_phoff", 8),
        ("e_shoff", 8),
        ("skip2", 8),
        ("e_phnum", 2),
        ("skip3", 2),
        ("e_shnum", 2),
    ]
)

PROGRAM_HEADER_STRUCT = Structure(
    [
        ("p_type", 4),
        ("p_flags", 4),
        ("p_offset", 8),
        ("p_vaddr", 8),
        ("skip1", 8),
        ("p_filesz", 8),
        ("p_memsz", 8),
    ]
)

SECTION_HEADER_STRUCT = Structure(
    [
        ("sh_name", 4),
        ("sh_type", 4),
        ("skip1", 0x10),
        ("sh_offset", 8),
        ("sh_size", 8),
    ]
)

RELA_STRUCT = Structure(
    [
        ("r_offset", 8),
        ("r_info", 8),
        ("r_addend", 8),
    ]
)


def find_proc_offsets():
    kernel = SHARED_VARS["kernel"]
    proc_data = kernel.read_buffer(kernel.curproc_addr, 0x1000)

    p_comm_pattern = [0xCE, 0xFA, 0xEF, 0xBE, 0xCC, 0xBB]
    p_comm_sign = 0
    limit = len(proc_data) - len(p_comm_pattern) + 1
    for idx in range(limit):
        for off, val in enumerate(p_comm_pattern):
            if val is not None and proc_data[idx + off] != val:
                break
        else:
            p_comm_sign = idx
            break
    p_sysent_pattern = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]
    p_sysent_sign = 0
    limit = len(proc_data) - len(p_sysent_pattern) + 1
    for idx in range(limit):
        for off, val in enumerate(p_sysent_pattern):
            if val is not None and proc_data[idx + off] != val:
                break
        else:
            p_sysent_sign = idx
            break

    if p_comm_sign == 0:
        raise Exception("failed to find offset for PROC_COMM")
    if p_sysent_sign == 0:
        raise Exception("failed to find offset for PROC_SYSENT")

    p_comm_offset = p_comm_sign + 0x8
    p_sysent_offset = p_sysent_sign - 0x10

    return p_comm_offset, p_sysent_offset


def find_additional_offsets():
    PROC_COMM, PROC_SYSENT = find_proc_offsets()

    KERNEL_OFFSETS["PROC_COMM"] = PROC_COMM
    KERNEL_OFFSETS["PROC_SYSENT"] = PROC_SYSENT


find_additional_offsets()


def find_proc_by_name(name):
    kernel = SHARED_VARS["kernel"]
    proc = kernel.read_qword(kernel.allproc_addr)
    while proc != 0:
        proc_name = kernel.read_null_terminated_string(
            proc + KERNEL_OFFSETS["PROC_COMM"]
        )
        if proc_name == name:
            return proc

        proc = kernel.read_qword(proc)

    return 0


DLSYM_OFFSETS = {
    "4.03": 0x317D0,
    "4.50": 0x317D0,
    "4.51": 0x317D0,
    "5.00": 0x32160,
    "5.02": 0x32160,
    "5.10": 0x32160,
    "5.50": 0x32230,
    "6.00": 0x330A0,
    "6.02": 0x330A0,
    "6.50": 0x33110,
    "7.00": 0x33E90,
    "7.01": 0x33E90,
    "7.20": 0x33ED0,
    "7.40": 0x33ED0,
    "7.60": 0x33ED0,
    "7.61": 0x33ED0,
    "8.00": 0x342E0,
    "8.20": 0x342E0,
    "8.40": 0x342E0,
    "8.60": 0x342E0,
    "9.00": 0x350E0,
    "9.05": 0x350E0,
    "9.20": 0x350E0,
    "9.40": 0x350E0,
    "9.60": 0x350E0,
    "10.00": 0x349C0,
    "10.01": 0x349C0,
}


def dangerous_dlsym(handle, symbol):
    out_buf = alloc(8)

    if sc.platform == "ps5":
        fw = sc.version
        if fw not in DLSYM_OFFSETS:
            raise Exception("sceKernelDlsym offset not known for firmware %s" % fw)
        dlsym_func = sc.make_function_if_needed(
            "sceKernelDlsym", sc.libkernel_addr + DLSYM_OFFSETS[fw]
        )
        if u64_to_i64(dlsym_func(handle, symbol, out_buf)) == -1:
            raise Exception(
                "dlsym error: %d\n%s"
                % (dlsym_func.errno, dlsym_func.get_error_string())
            )
    else:
        if u64_to_i64(sc.syscalls.dlsym(handle, symbol, out_buf)) == -1:
            raise Exception(
                "dlsym error: %d\n%s"
                % (sc.syscalls.dlsym.errno, sc.syscalls.dlsym.get_error_string())
            )

    return struct.unpack("<Q", out_buf[0:8])[0]


def run_with_ps5_syscall_enabled(func):
    if CONSOLE_KIND != "PS5":
        kernel = SHARED_VARS["kernel"]
        target_proc_name = "SceGameLiveStreaming"
        target_proc = find_proc_by_name(target_proc_name)

        cur_sysent = kernel.read_qword(
            kernel.curproc_addr + KERNEL_OFFSETS["PROC_SYSENT"]
        )  # struct sysentvec
        target_sysent = kernel.read_qword(target_proc + KERNEL_OFFSETS["PROC_SYSENT"])

        cur_table_size = kernel.read_dword(cur_sysent)  # sv_size
        target_table_size = kernel.read_dword(target_sysent)

        cur_table = kernel.read_qword(cur_sysent + 0x8)  # sv_table
        target_table = kernel.read_qword(target_sysent + 0x8)

        # replace with target sysent
        kernel.write_dword(cur_sysent, target_table_size)
        kernel.write_qword(cur_sysent + 0x8, target_table)

        # catch error so we can restore sysent
        try:
            func()
        except:
            log_exc(traceback.format_exc())

        # restore back
        kernel.write_dword(cur_sysent, cur_table_size)
        kernel.write_qword(cur_sysent + 0x8, cur_table)
    else:
        # we can already use ps5 syscalls directly
        try:
            func()
        except:
            log_exc(traceback.format_exc())


class ElfLoader:
    def __init__(self, data):
        self.elf_data = data

        self.shadow_mapping_addr = 0x920100000
        self.mapping_addr = 0x926100000

        self.parse()

    def parse(self):
        SHT_RELA = 4
        RELA_ENTSIZE = 0x18

        PF_X = 1

        ELF_PT_LOAD = 1
        ELF_R_AMD64_RELATIVE = 8

        elf_store = get_ref_addr(self.elf_data)

        elf_header = ELF_HEADER_STRUCT.from_address(elf_store)

        elf_entry = elf_header.e_entry
        self.elf_entry_point = self.mapping_addr + elf_entry

        elf_program_headers_offset = elf_header.e_phoff
        elf_program_header_num = elf_header.e_phnum

        elf_section_headers_offset = elf_header.e_shoff
        elf_section_header_num = elf_header.e_shnum

        executable_start = 0
        executable_end = 0

        for i in range(elf_program_header_num):
            ph_offset = elf_program_headers_offset + i * 0x38
            program_header = PROGRAM_HEADER_STRUCT.from_address(elf_store + ph_offset)
            aligned_memsz = (program_header.p_memsz + 0x3FFF) & 0xFFFFC000

            if program_header.p_type == ELF_PT_LOAD:
                PROT_RW = PROT_READ | PROT_WRITE
                PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC

                if program_header.p_flags & PF_X == PF_X:
                    executable_start = program_header.p_vaddr
                    executable_end = program_header.p_vaddr + program_header.p_memsz

                    # create shm with exec permission
                    exec_handle = sc.syscalls.jitshm_create(0, aligned_memsz, 0x7)

                    # create shm alias with write permission
                    write_handle = sc.syscalls.jitshm_alias(exec_handle, 0x3)

                    # map shadow mapping and write into it
                    sc.syscalls.mmap(
                        self.shadow_mapping_addr,
                        aligned_memsz,
                        PROT_RW,
                        0x11,
                        write_handle,
                        0,
                    )
                    writebuf(
                        self.shadow_mapping_addr,
                        readbuf(
                            elf_store + program_header.p_offset, program_header.p_memsz
                        ),
                    )

                    # map executable segment
                    sc.syscalls.mmap(
                        self.mapping_addr + program_header.p_vaddr,
                        aligned_memsz,
                        PROT_RWX,
                        0x11,
                        exec_handle,
                        0,
                    )
                else:
                    # copy regular data segment
                    sc.syscalls.mmap(
                        self.mapping_addr + program_header.p_vaddr,
                        aligned_memsz,
                        PROT_RW,
                        0x1012,
                        0xFFFFFFFF,
                        0,
                    )
                    writebuf(
                        self.mapping_addr + program_header.p_vaddr,
                        readbuf(
                            elf_store + program_header.p_offset, program_header.p_memsz
                        ),
                    )

        # apply relocations
        for i in range(elf_section_header_num):
            shdr_offset = elf_section_headers_offset + i * 0x40
            section_header = SECTION_HEADER_STRUCT.from_address(elf_store + shdr_offset)

            if section_header.sh_type == SHT_RELA:
                rela_table_count = section_header.sh_size // RELA_ENTSIZE

                # Parse relocs and apply them
                for i in range(rela_table_count):
                    rela_offset = section_header.sh_offset + i * RELA_ENTSIZE
                    rela_entry = RELA_STRUCT.from_address(elf_store + rela_offset)

                    if rela_entry.r_info & 0xFF == ELF_R_AMD64_RELATIVE:
                        reloc_addr = self.mapping_addr + rela_entry.r_offset
                        reloc_value = self.mapping_addr + rela_entry.r_addend

                        # If the relocation falls in the executable section, we need to redirect the write to the
                        # writable shadow mapping or we'll crash
                        if executable_start <= rela_entry.r_offset < executable_end:
                            reloc_addr = self.shadow_mapping_addr + rela_entry.r_offset

                        writebuf(reloc_addr, struct.pack("<Q", reloc_value))

    def run(self):
        rwpipe = alloc(8)
        rwpair = alloc(8)
        args = alloc(0x30)
        thr_handle = alloc(8)

        rwpipe[0:4] = struct.pack(
            "<I", SHARED_VARS["ipv6_kernel_rw_data"]["pipe_read_fd"]
        )
        rwpipe[4:8] = struct.pack(
            "<I", SHARED_VARS["ipv6_kernel_rw_data"]["pipe_write_fd"]
        )

        rwpair[0:4] = struct.pack(
            "<I", SHARED_VARS["ipv6_kernel_rw_data"]["master_sock"]
        )
        rwpair[4:8] = struct.pack(
            "<I", SHARED_VARS["ipv6_kernel_rw_data"]["victim_sock"]
        )
        syscall_wrapper = dangerous_dlsym(0x2001, "getpid")

        self.payloadout = alloc(4)

        args[0:8] = struct.pack("<Q", syscall_wrapper)
        args[8:0x10] = struct.pack("<Q", get_ref_addr(rwpipe))
        args[0x10:0x18] = struct.pack("<Q", get_ref_addr(rwpair))
        args[0x18:0x20] = struct.pack(
            "<Q", SHARED_VARS["ipv6_kernel_rw_data"]["pipe_addr"]
        )
        args[0x20:0x28] = struct.pack("<Q", SHARED_VARS["kernel"].data_base)
        args[0x28:0x30] = struct.pack("<Q", get_ref_addr(self.payloadout))
        # spawn elf in new thread
        log("Spawning ELF loader thread...")
        ret = sc.functions.Thrd_create(thr_handle, self.elf_entry_point, args)
        if ret != 0:
            raise Exception("Thrd_create failed with return value %x" % ret)

        self.thr_handle = struct.unpack("<Q", thr_handle[0:8])[0]

    def join(self):
        ret = sc.functions.Thrd_join(self.thr_handle, 0)
        if ret != 0:
            raise Exception("Thrd_join failed with return value %x" % ret)

        out = struct.unpack("<I", self.payloadout[0:4])[0]
        log("out = %x" % out)


def main():
    if sc.platform != "ps5":
        log("This payload is only for PS5.")
        return

    if not sc.is_jailbroken:
        log("Console is not jailbroken, cannot proceed.")
        return

    payload_data = b""

    if os.path.exists("/saves/yarpe/elfldr-ps5.elf") and not FORCE_SOCKET:
        log("Found elfldr-ps5.elf in /saves/yarpe/. Loading from save...")
        log(
            "You can force network transfer by holding X button when launching the payload."
        )
        with open("/saves/yarpe/elfldr-ps5.elf", "rb") as f:
            payload_data = f.read()
    else:
        log(
            "elfldr-ps5.elf not found in /saves/yarpe/ or X button pressed... Will wait for network transfer."
        )

        s, _ = create_tcp_server(PORT)
        _, port = get_socket_name(s)

        ip = sc.get_current_ip()
        if ip is None:
            log("Send payload to port %d" % (port))
        else:
            log("Send payload to %s:%d" % (ip, port))

        client_sock = accept_client(s)

        log("Client connected on socket %d" % client_sock)

        payload_data = read_all_from_socket(client_sock)

        payload_size = len(payload_data)
        log("Received %d bytes" % payload_size)

        close_socket(client_sock)
        close_socket(s)

    def run_elf_loader():
        elf = ElfLoader(payload_data)
        elf.run()
        elf.join()

    run_with_ps5_syscall_enabled(run_elf_loader)

    if not SHARED_VARS.get("AUTO_LOAD", False):
        log("Done, killing game...")
        sc.kill_game()
    else:
        log("Done, returning to autoloader...")


main()
