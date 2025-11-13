import zipfile
import io
import re
import os
import struct

from utils.conversion import u64_to_i64
from utils.etc import alloc
from utils.rp import log
from errors.socket import SocketError
from sc import sc
from constants import SYSCALL

WRITING = False

if WRITING:  # dummy objects for writing code
    AF_INET = 0
    SOCK_STREAM = 0
    SOL_SOCKET = 0
    SO_REUSEADDR = 0

    port = 0
    s = 0
    sockaddr_in = bytearray()
    len_buf = bytearray()


UPDATE_SIZE = 1024 * 1024 * 1  # 1 MB
UPDATE_BUF = alloc(UPDATE_SIZE)

SYSCALL["getpid"] = 20
SYSCALL["kill"] = 37

SIGKILL = 9


def kill_game():
    pid = u64_to_i64(sc.syscalls.getpid())
    if pid < 0:
        raise Exception(
            "getpid failed with return value %d, error %d\n%s"
            % (
                pid,
                sc.syscalls.getpid.errno,
                sc.syscalls.getpid.get_error_string(),
            )
        )

    ret = u64_to_i64(sc.syscalls.kill(pid, SIGKILL))
    if ret < 0:
        raise SocketError(
            "kill failed with return value %d, error %d\n%s"
            % (
                ret,
                sc.syscalls.kill.errno,
                sc.syscalls.kill.get_error_string(),
            )
        )


ip = sc.get_current_ip()

if ip is None:
    log("Send new save.zip to port %d" % (port))
else:
    log("Send new save.zip to %s:%d" % (ip, port))

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
update_file = b""
while read_size != 0:
    read_size = u64_to_i64(
        sc.syscalls.read(
            client_sock,
            UPDATE_BUF,
            UPDATE_SIZE,
        )
    )
    update_file += UPDATE_BUF[:read_size]
    if read_size < 0:
        raise SocketError(
            "read failed with return value %d, error %d\n%s"
            % (
                read_size,
                sc.syscalls.read.errno,
                sc.syscalls.read.get_error_string(),
            )
        )

log("Received save.zip, size %d bytes" % len(update_file))
sc.syscalls.close(client_sock)


# the game changes path like `foo/bar/baz` to `_foo__bar_baz`
# since the zip already has converted name, we need to reverse that
def filename_converter(name):
    pattern = re.compile(r"_([a-zA-Z0-9]+)_")
    paths = pattern.split(name)
    return "/".join(paths)


def save_index_parser(data):
    files = {}
    count = struct.unpack("<I", data[0:4])[0]
    offset = 4
    for _ in range(count):
        skip = struct.unpack("<Q", data[offset : offset + 8])[0]
        offset += 8
        name_len = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        name = data[offset : offset + name_len].decode("utf-8")
        offset += name_len + 1  # null terminator
        split_path = name[7:].split("/")  # remove leading /saves/
        files[
            "".join(
                [
                    ("_%s_" % x) if i != len(split_path) - 1 else x
                    for i, x in enumerate(split_path)
                ]
            )
        ] = name

    return files


with zipfile.ZipFile(io.BytesIO(update_file), "r") as zipf:
    save_index = save_index_parser(zipf.read("-saveindex"))
    for fileinfo in zipf.infolist():
        if fileinfo.filename == "-saveindex":
            continue
        new_path = save_index.get(fileinfo.filename, fileinfo.filename)
        log("Extracting %s (%d bytes)" % (new_path, fileinfo.file_size))
        if not os.path.exists(os.path.dirname(new_path)):
            os.makedirs(os.path.dirname(new_path))
        with open(new_path, "wb") as f:
            f.write(zipf.read(fileinfo.filename))

log("Successfully updated save files.")
log("Press X(or O) to exit the game.{w}")
kill_game()
