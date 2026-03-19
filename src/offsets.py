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
            "add rsp, 0x1b8; ret": 0x8774C6,
            "pop rax; ret": 0x5C52C,
            "pop rcx; ret": 0x7788B,
            "pop rdx; ret": 0x2BBF32,
            "pop rsi; ret": 0x83F82,
            "pop rdi; ret": 0x2FC0FD,
            "pop r8; ret": 0x804111,
            "mov [rsi], rax; ret": 0x7FE05A,
            "mov rsp, rbp; pop rbp; ret": 0x114,
            "push rbp; mov rbp, rsp; xor esi, esi; call [rdi + 0x130]": 0x38BC50,
            "add [r8 - 0x7d], rcx; ret": 0x7A3735,
            "ret": 0x32,
            "mov [rcx], rdx; ret": 0x8AB2C0,
            "mov r9, [rax+rsi+0x18]; xor eax, eax; mov [r8], r9; ret": 0x78D202,
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
            "sceKernelGetModuleInfoFromAddr": 0x113C08,
            "gettimeofday": 0x113B18,
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
            "strcmp": 0xB96F28,
        },
    },
}
