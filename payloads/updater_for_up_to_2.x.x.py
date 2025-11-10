import zipfile
import io
import re
import os

WRITING = False

if WRITING:  # dummy objects for writing code
    nogc = []

    class Container:
        def __getattribute__(self, name):
            return Executable()

    class sc:
        mem = bytearray()
        version = ""
        platform = ""
        errno = 0
        libkernel_addr = 0
        libc_addr = 0
        exec_addr = 0

        syscalls = Container()
        functions = Container()

        @staticmethod
        def make_function_if_needed(name, addr):
            return Executable()

        @staticmethod
        def get_current_ip():
            return ""

    class ROPChain:
        def __init__(self, *args, **kwargs):
            pass

        def push_syscall(self, *args, **kwargs):
            pass

        def push_write_into_memory(self, *args, **kwargs):
            pass

        def append(self, *args, **kwargs):
            pass

        def reset(self):
            pass

    class Executable:
        errno = 0
        chain = ROPChain(sc)

        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, *args, **kwargs):
            return 0

        def get_error_string(self):
            return ""

        def setup_front_chain(self):
            pass

        def setup_syscall_chain(self, *args, **kwargs):
            pass

        def setup_post_chain(self):
            pass

        def setup_back_chain(self):
            pass

        def execute(self):
            return 0

    SYSCALL = {}
    LIBC_OFFSETS = {}
    SELECTED_LIBC = {}

    def alloc(size):
        return bytearray(size)

    def readuint(addr, size):
        return 0

    def get_ref_addr(data):
        return 0

    def readbuf(addr, size):
        return bytearray(size)

    def get_cstring(data, addr=0):
        return ""

    def u64_to_i64(value):
        return value

    class SocketError(Exception):
        pass

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
    print("Send new save.zip to port %d" % (port))
else:
    print("Send new save.zip to %s:%d" % (ip, port))

print("Waiting for client connection...")
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

print("Client connected on socket %d" % client_sock)

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

print("Received save.zip, size %d bytes" % len(update_file))
sc.syscalls.close(client_sock)

# the game changes path like `foo/bar/baz` to `_foo__bar_baz`
# since the zip already has converted name, we need to reverse that


def filename_converter(name):
    pattern = re.compile(r"_([a-zA-Z0-9]+)_")
    paths = pattern.split(name)
    return "/".join(paths)


with zipfile.ZipFile(io.BytesIO(update_file), "r") as zipf:
    for fileinfo in zipf.infolist():
        if fileinfo.filename == "-saveindex":
            continue
        new_name = filename_converter(fileinfo.filename)
        if len(new_name.split("/")[1:]) != 0:
            paths = new_name.split("/")[1:-1]
            curr_path = "/saves"
            for path in paths:
                curr_path += "/" + path
                if not os.path.exists(curr_path):
                    os.mkdir(curr_path)
        new_name = new_name if new_name.startswith("/") else "/" + new_name
        print("Extracting %s (%d bytes)" % (new_name, fileinfo.file_size))
        filedata = zipf.read(fileinfo.filename)
        with open("/saves" + new_name, "wb") as f:
            f.write(filedata)

print("Successfully updated save files.")
print("Press X(or O) to exit the game.{w}")
kill_game()
