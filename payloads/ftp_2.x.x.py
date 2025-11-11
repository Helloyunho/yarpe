# ===== FTP Stage 2 =====
import sys
import struct

# --- Ensure required syscalls exist (Stage-1 exposes SYSCALL + SyscallContainer) ---
NEEDED_SYSCALLS = {
    "recvfrom": 29,      # used for socket recv
    "connect": 98,
    "rename": 128,
    "sendto": 133,       # used for socket send
    "mkdir": 136,
    "rmdir": 137,
    "stat": 188,
    "getdents": 272,
    "lseek": 478,
    "unlink": 10,
    "chmod": 15,
}

# Update the global SYSCALL mapping from Stage-1 so sc.syscalls.<name> works lazily.
try:
    SYSCALL.update(NEEDED_SYSCALLS)
except NameError:
    # If SYSCALL not visible for any reason, we can still create instances manually.
    pass

# Convenience aliases to syscalls (creation will be lazy via SyscallContainer)
recvfrom = sc.syscalls.recvfrom
sendto = sc.syscalls.sendto
connect_ = sc.syscalls.connect
rename_ = sc.syscalls.rename
mkdir_ = sc.syscalls.mkdir
rmdir_ = sc.syscalls.rmdir
stat_ = sc.syscalls.stat
getdents_ = sc.syscalls.getdents
lseek_ = sc.syscalls.lseek
unlink_ = sc.syscalls.unlink
chmod_ = sc.syscalls.chmod

open_ = sc.syscalls.open
close_ = sc.syscalls.close
read_ = sc.syscalls.read
write_ = sc.syscalls.write
socket_ = sc.syscalls.socket
bind_ = sc.syscalls.bind
listen_ = sc.syscalls.listen
accept_ = sc.syscalls.accept
getsockname_ = sc.syscalls.getsockname
setsockopt_ = sc.syscalls.setsockopt

# --- Constants ---
AF_INET = 2
SOCK_STREAM = 1
SOL_SOCKET   = 0xFFFF
SO_REUSEADDR = 4
# Avoid SO_REUSEPORT on PS4/FreeBSD – can trigger ENOPROTOOPT

# Reusable structures for setsockopt
Enable4 = Structure([("v",4)]).create()
Enable4.v = 1
Len16 = Structure([("len",4)]).create()  # handy 16-len holder

INADDR_ANY = 0
O_RDONLY   = 0x0000
O_WRONLY   = 0x0001
O_RDWR     = 0x0002
O_APPEND   = 0x0008
O_CREAT    = 0x0200
O_TRUNC    = 0x0400

# Stat bits (FreeBSD-like)
S_IFMT  = 0o170000
S_IFSOCK= 0o140000
S_IFLNK = 0o120000
S_IFREG = 0o100000
S_IFBLK = 0o060000
S_IFDIR = 0o040000
S_IFCHR = 0o020000
S_IFIFO = 0o010000

def S_ISDIR(m):  return (m & S_IFMT) == S_IFDIR
def S_ISCHR(m):  return (m & S_IFMT) == S_IFCHR
def S_ISBLK(m):  return (m & S_IFMT) == S_IFBLK
def S_ISREG(m):  return (m & S_IFMT) == S_IFREG
def S_ISFIFO(m): return (m & S_IFMT) == S_IFIFO
def S_ISLNK(m):  return (m & S_IFMT) == S_IFLNK
def S_ISSOCK(m): return (m & S_IFMT) == S_IFSOCK

# sockaddr_in is already defined in Stage-1 as Structure([...]).create()
SockAddrIn = Structure([
    ("sin_len", 1),
    ("sin_family", 1),
    ("sin_port", 2),
    ("sin_addr", 4),
    ("sin_zero", 8),
])

# ---- helpers: read sin_port directly as big-endian, plus optional hexdump ----
def _be16_from_sockaddr(sa):
    # always read 2 bytes as a raw string
    raw = sa.get_field_raw("sin_port")
    rb = str(raw) if not isinstance(raw, bytes) else raw
    return struct.unpack(">H", rb)[0] if len(rb) >= 2 else 0

def _hexdump_sockaddr(label, sa):
    raw = sa.buf[:]  # 16 bytes
    if not raw:
        print("[dbg] %s sockaddr empty" % label)
        return
    try:
        # in Py2 bytearray iteration yields ints
        line = ":".join("%02x" % b for b in raw)
    except Exception:
        # fallback for weird buffer types
        s = str(raw)
        line = ":".join("%02x" % ord(ch) for ch in s)
    print("[dbg] %s sockaddr = %s" % (label, line))

# Helper: htons/htonl without depending on libc
def htons(n):
    return struct.unpack(">H", struct.pack("<H", n & 0xFFFF))[0]

def htonl(n):
    return struct.unpack(">I", struct.pack("<I", n & 0xFFFFFFFF))[0]

def ntohs(n):
    return struct.unpack("<H", struct.pack(">H", n & 0xFFFF))[0]

def ntohl(n):
    return struct.unpack(">I", struct.pack("<I", n & 0xFFFFFFFF))[0]

def inet_aton(ipstr):
    a,b,c,d = [int(x) & 0xFF for x in ipstr.split(".")]
    return (a<<24) | (b<<16) | (c<<8) | d

def inet_ntoa(n):
    return ".".join(str((n>>s) & 0xFF) for s in (24,16,8,0))

STAT_SIZE = 120
STAT_OFF_MODE  = 8      # 16-bit
STAT_OFF_MTIME = 56     # points/contains time_t (we'll just ignore formatting details)
STAT_OFF_SIZE  = 72     # 64-bit

# d_reclen at +0x4 (1 byte used in your script), name at +0x8 (64 bytes window)
DIRENT_NAME_OFF = 0x8
DIRENT_RECLEN_OFF = 0x4
DIRENT_TMP_NAME_MAX = 64

MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

def read_u8(buf, off):
    return buf[off]

def read_u16_le(buf, off):
    return struct.unpack_from("<H", buf, off)[0]

def read_u64_le(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]

def unix_mode_string(mode):
    def bit(on): return "rwx"[on]
    # file type char
    if   S_ISDIR(mode):  t='d'
    elif S_ISCHR(mode):  t='c'
    elif S_ISBLK(mode):  t='b'
    elif S_ISREG(mode):  t='-'
    elif S_ISFIFO(mode): t='p'
    elif S_ISSOCK(mode): t='s'
    elif S_ISLNK(mode):  t='l'
    else:                t=' '
    out = [t]
    perms = [(0o400,0o200,0o100),(0o040,0o020,0o010),(0o004,0o002,0o001)]
    for r,w,x in perms:
        out.append('r' if mode & r else '-')
        out.append('w' if mode & w else '-')
        out.append('x' if mode & x else '-')
    return "".join(out)

def sanitize_path(cur, to):
    if to is None or to == "":
        return cur
    # drop directories from "to"
    if "/" in to:
        to = to.split("/")[-1]
    if cur == "/":
        return "/" + to
    return cur + "/" + to

def dir_up(path):
    if path == "/": return "/"
    if "/" not in path: return "/"
    parent = path.rsplit("/",1)[0]
    return parent if parent else "/"

# --- FTP core ---
class FTPState:
    def __init__(self):
        self.root_path = "/"
        self.cur_path = "/"
        self.conn_type = "none" # "active" / "passive" / "none"
        self.transfer_type = "I" # "I" binary, "A" ascii
        self.restore_point = -1
        self.is_connected = False
        self.rname = None

        self.ctrl_sock = None
        self.data_sock = None
        self.pasv_listen_sock = None
        self.pasv_accepted_sock = None

        # Sockaddrs
        self.ctrl_addr = SockAddrIn.create()
        self.data_addr = SockAddrIn.create()
        self.pasv_addr = SockAddrIn.create()

        # len buffers
        self.ctrl_addrlen = Structure([("len",4)]).create()
        self.pasv_addrlen = Structure([("len",4)]).create()
        self.ctrl_addrlen.len = 16
        self.pasv_addrlen.len = 16

class FTPServer:
    def __init__(self, ip=None, port=1337):
        self.ip = ip or sc.get_current_ip() or "127.0.0.1"
        self.port = port
        self.listen_sock = None
        self.state = FTPState()
        self.running = True

    # --- socket helpers ---
    def make_tcp_socket(self):
        s = u64_to_i64(socket_(AF_INET, SOCK_STREAM, 0))
        if s < 0:
            raise Exception("socket failed: %d errno=%d" % (s, socket_.errno))
        # SO_REUSEADDR
        en = Structure([("enable",4)]).create()
        en.enable = 1
        setsockopt_(s, SOL_SOCKET, SO_REUSEADDR, en, 4)
        return s

    def bind_listen(self, s, port):
        sa = SockAddrIn.create()
        sa.sin_len = 16  # BSD requires length set
        sa.sin_family = AF_INET
        sa.sin_port = htons(port)  # 0 means "pick any free port"
        sa.sin_addr = 0  # INADDR_ANY
        # MUST set reuse options BEFORE bind() on BSD
        setsockopt_(s, SOL_SOCKET, SO_REUSEADDR, Enable4, 4)
        ret = u64_to_i64(bind_(s, sa, 16))
        print("[dbg] bind rc=%d errno=%d" % (ret, bind_.errno))
        sys.stdout.flush()
        if ret != 0:
            # if requested port is busy, retry once with ephemeral port
            if port != 0 and bind_.errno == 48:  # EADDRINUSE
                sa.sin_port = htons(0)
                ret = u64_to_i64(bind_(s, sa, 16))
                print("[dbg] bind(retry-ephemeral) rc=%d errno=%d" % (ret, bind_.errno))
                sys.stdout.flush()
            if ret != 0:
                raise Exception("bind failed: %d errno=%d" % (ret, bind_.errno))
        ret = u64_to_i64(listen_(s, 128))
        print("[dbg] listen rc=%d errno=%d" % (ret, listen_.errno))
        sys.stdout.flush()
        if ret != 0:
            raise Exception("listen failed: %d errno=%d" % (ret, listen_.errno))

    def send_sock(self, sock, data):
        # sockets are fine with write()
        data_ba = data.encode("utf-8") if isinstance(data, str) else data
        total = 0
        while total < len(data_ba):
            n = u64_to_i64(write_(sock, data_ba[total:], len(data_ba)-total))
            if n <= 0:
                break
            total += n

    def recv_line(self, sock, maxlen=2048):
        """
        Read until CRLF, return line without CRLF.
        Read in one syscall chunks into a persistent bytearray to avoid slices.
        """
        if not hasattr(self, "_recv_buf"):
            self._recv_buf = bytearray()    # persistent across calls

        while True:
            # check if there's already a full line
            idx = self._recv_buf.find(b"\r\n")
            if idx != -1:
                line = self._recv_buf[:idx]
                # remove consumed bytes (+2 for CRLF)
                self._recv_buf = self._recv_buf[idx+2:]
                try:
                    return line.decode("utf-8", "ignore")
                except:
                    return line.decode("latin-1", "ignore")

            # no complete line yet -> read a chunk
            tmp = bytearray(512)
            n = u64_to_i64(read_(sock, tmp, len(tmp)))
            if n is None or n <= 0:
                # socket closed or no data
                if len(self._recv_buf) == 0:
                    return None
                # return whatever we have (no CRLF)
                try:
                    line = self._recv_buf
                    self._recv_buf = bytearray()
                    return line.decode("utf-8", "ignore")
                except:
                    return line.decode("latin-1", "ignore")

            # append received bytes to the persistent buffer
            self._recv_buf += tmp[:n]
            # if buffer gets too large, trim to maxlen to avoid memory problems
            if len(self._recv_buf) > maxlen:
                # return what we have as a fallback
                line = self._recv_buf[:maxlen]
                self._recv_buf = self._recv_buf[maxlen:]
                try:
                    return line.decode("utf-8", "ignore")
                except:
                    return line.decode("latin-1", "ignore")

    def ftp_send_ctrl(self, msg):
        self.send_sock(self.state.ctrl_sock, msg)

    def ftp_open_data(self):
        st = self.state
        if st.conn_type == "active":
            ret = u64_to_i64(connect_(st.data_sock, st.data_addr, 16))
            if ret != 0:
                self.ftp_send_ctrl("425 Can't open data connection\r\n")
                return False
            return True
        if st.conn_type == "passive":
            ln = Structure([("len",4)]).create()
            ln.len = 16
            addr = SockAddrIn.create()
            st.pasv_accepted_sock = u64_to_i64(accept_(st.pasv_listen_sock, addr, ln))
            if st.pasv_accepted_sock < 0:
                self.ftp_send_ctrl("425 Can't open data connection\r\n")
                return False
            # close the listener now that we have a data socket
            try: close_(st.pasv_listen_sock)
            except: pass
            st.pasv_listen_sock = None
            return True
        self.ftp_send_ctrl("425 Use PASV or PORT first\r\n")
        return False

    def ftp_send_data(self, data):
        st = self.state
        if st.conn_type == "active":
            self.send_sock(st.data_sock, data)
        else:
            self.send_sock(st.pasv_accepted_sock, data)

    def ftp_close_data(self):
        st = self.state
        if st.data_sock is not None:
            close_(st.data_sock)
        if st.pasv_accepted_sock is not None:
            close_(st.pasv_accepted_sock)
        if st.pasv_listen_sock is not None:
            close_(st.pasv_listen_sock)
        st.data_sock = None
        st.pasv_accepted_sock = None
        st.pasv_listen_sock = None
        st.conn_type = "none"

    # --- command handlers ---
    def handle_USER(self, _):
        self.ftp_send_ctrl("331 Anonymous login accepted, send your email as password\r\n")

    def handle_PASS(self, _):
        self.ftp_send_ctrl("230 User logged in\r\n")

    def handle_NOOP(self, _):
        self.ftp_send_ctrl("200 No operation\r\n")

    def handle_PWD(self, _):
        self.ftp_send_ctrl('257 "{}" is the current directory\r\n'.format(self.state.cur_path))

    def handle_TYPE(self, line):
        if line.strip() == "TYPE I":
            self.state.transfer_type = "I"
            self.ftp_send_ctrl("200 Switching to Binary mode\r\n")
        elif line.strip() == "TYPE A":
            self.state.transfer_type = "A"
            self.ftp_send_ctrl("200 Switching to ASCII mode\r\n")
        else:
            self.ftp_send_ctrl("504 Command not implemented for that parameter\r\n")

    def handle_SYST(self, _):
        self.ftp_send_ctrl("215 UNIX Type: L8\r\n")

    def handle_FEAT(self, _):
        self.ftp_send_ctrl("211-extensions\r\n")
        self.ftp_send_ctrl(" REST STREAM\r\n")
        self.ftp_send_ctrl("211 end\r\n")

    def handle_CWD(self, line):
        arg = line[4:].strip() if len(line) > 4 else None
        if not arg:
            self.ftp_send_ctrl("500 Syntax error, command unrecognized.\r\n")
            return
        if arg == "/":
            self.state.cur_path = "/"
            self.ftp_send_ctrl("250 Requested file action okay, completed.\r\n")
            return
        if arg == "..":
            self.state.cur_path = dir_up(self.state.cur_path)
            if self.state.cur_path != "/":
                self.state.cur_path = "/"
            self.ftp_send_ctrl("250 Requested file action okay, completed.\r\n")
            return
        # Absolute vs relative
        if arg.startswith("/"):
            newp = arg
        else:
            newp = (self.state.cur_path + ("" if self.state.cur_path.endswith("/") else "/") + arg) if self.state.cur_path != "/" else "/" + arg
        # Test it exists (open dir)
        fd = u64_to_i64(open_(newp.encode("utf-8")+b"\0", O_RDONLY, 0))
        if fd < 0:
            self.ftp_send_ctrl("550 Invalid directory.\r\n")
            return
        close_(fd)
        self.state.cur_path = newp
        self.ftp_send_ctrl("250 Requested file action okay, completed.\r\n")

    def handle_CDUP(self, _):
        if not self.state.cur_path:
            self.state.cur_path = "/"
        if self.state.cur_path != "/":
            self.state.cur_path = dir_up(self.state.cur_path)
        self.ftp_send_ctrl("200 Command okay\r\n")

    def handle_PORT(self, line):
        # PORT h1,h2,h3,h4,p1,p2
        try:
            args = line.split()[1]
            parts = [int(x) for x in args.split(",")]
            ip = "{}.{}.{}.{}".format(*parts[:4])
            port = parts[4]*256 + parts[5]
        except Exception:
            self.ftp_send_ctrl("501 Syntax error in parameters\r\n")
            return
        st = self.state
        st.data_sock = u64_to_i64(socket_(AF_INET, SOCK_STREAM, 0))
        if st.data_sock < 0:
            self.ftp_send_ctrl("425 Can't build data socket\r\n")
            return
        # prepare sockaddr to connect later
        sa = SockAddrIn.create()
        sa.sin_family = AF_INET
        sa.sin_port = htons(port)
        sa.sin_addr = ntohl(inet_aton(ip))
        st.data_addr = sa
        st.conn_type = "active"
        self.ftp_send_ctrl("200 PORT command ok\r\n")

    def handle_PASV(self, _):
        st = self.state
        # create a fresh passive listener on an ephemeral port
        st.pasv_listen_sock = u64_to_i64(socket_(AF_INET, SOCK_STREAM, 0))
        if st.pasv_listen_sock < 0:
            self.ftp_send_ctrl("425 Can't open passive connection\r\n")
            return
        sa = SockAddrIn.create()
        sa.sin_len = 16  # set length!
        sa.sin_family = AF_INET
        sa.sin_port = htons(0)  # let the kernel choose a free port
        sa.sin_addr = 0  # INADDR_ANY
        # allow fast rebinding, avoid EADDRINUSE/TIME_WAIT issues
        setsockopt_(st.pasv_listen_sock, SOL_SOCKET, SO_REUSEADDR, Enable4, 4)
        rc = u64_to_i64(bind_(st.pasv_listen_sock, sa, 16))
        print("[dbg] bind rc=%d errno=%d" % (rc, bind_.errno))
        sys.stdout.flush()
        if rc != 0:
            self.ftp_send_ctrl("425 Can't bind passive socket\r\n")
            try: close_(st.pasv_listen_sock)
            except: pass
            st.pasv_listen_sock = None
            return
        rc = u64_to_i64(listen_(st.pasv_listen_sock, 1))
        print("[dbg] listen rc=%d errno=%d" % (rc, listen_.errno))
        sys.stdout.flush()
        if rc != 0:
            self.ftp_send_ctrl("425 Can't listen on passive socket\r\n")
            try: close_(st.pasv_listen_sock)
            except: pass
            st.pasv_listen_sock = None
            return
        # get the actual picked port
        picked = SockAddrIn.create()
        picked.sin_len = 16  # not strictly required for output, harmless
        ln = Structure([("len",4)]).create()
        ln.len = 16
        rc = u64_to_i64(getsockname_(st.pasv_listen_sock, picked, ln))
        print("[dbg] getsockname rc=%d errno=%d" % (rc, getsockname_.errno))
        if rc < 0:
            print("[dbg] getsockname rc=-1 errno=%d" % (getsockname_.errno))
        print("[dbg] getsockname_(PASV) rc=%d ln=%d" % (rc, ln.len)); sys.stdout.flush()
        # DEBUG: peek raw content and extract port robustly
        _hexdump_sockaddr("PASV picked", picked)
        port = _be16_from_sockaddr(picked)
        print("[dbg] PASV sin_port raw=0x%04x decoded=%d" % (picked.sin_port & 0xFFFF, port))
        sys.stdout.flush()
        # reply with h1,h2,h3,h4,p1,p2
        a,b,c,d = [int(x) for x in self.ip.split(".")]
        p1, p2 = (port // 256), (port % 256)
        self.ftp_send_ctrl("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n" % (a,b,c,d,p1,p2))
        st.conn_type = "passive"
        st.pasv_accepted_sock = None

    def _list_directory(self, path):
        fd = u64_to_i64(open_(path.encode("utf-8")+b"\0", O_RDONLY, 0))
        if fd < 0:
            return None, "550 Invalid directory. Got {}\r\n".format(path)
        out_lines = []
        seen = set()
        buf = bytearray(4096)
        while True:
            nread = u64_to_i64(getdents_(fd, buf, 4096))
            if nread <= 0:
                break
            off = 0
            end = nread
            while off < end:
                reclen = buf[off + DIRENT_RECLEN_OFF]
                if reclen == 0:
                    break
                name_bytes = bytes(buf[off + DIRENT_NAME_OFF: off + DIRENT_NAME_OFF + DIRENT_TMP_NAME_MAX])
                # strip at first \0
                name = name_bytes.split(b"\0",1)[0].decode("utf-8","ignore")
                if name not in (".","..","") and name not in seen:
                    seen.add(name)
                    full = (path if path != "/" else "") + "/" + name if path != "/" else "/" + name
                    stbuf = bytearray(STAT_SIZE)
                    if u64_to_i64(stat_(full.encode("utf-8")+b"\0", stbuf)) >= 0:
                        mode = read_u16_le(stbuf, STAT_OFF_MODE)
                        size = read_u64_le(stbuf, STAT_OFF_SIZE)
                        line = "{} 1 ps4 ps4 {:d} {} {:2d} {:02d}:{:02d} {}\r\n".format(
                            unix_mode_string(mode), size, MONTHS[0], 1, 0, 0, name
                        )
                        out_lines.append(line)
                off += reclen
        close_(fd)
        return "".join(out_lines), None

    def handle_LIST(self, line):
        st = self.state
        path = st.cur_path
        self.ftp_send_ctrl("150 Opening ASCII mode data transfer for LIST.\r\n")
        if not self.ftp_open_data():
            return
        listing, err = self._list_directory(path)
        if listing is None:
            self.ftp_send_ctrl(err)
            self.ftp_close_data()
            return
        self.ftp_send_data(listing.encode("utf-8"))
        self.ftp_close_data()
        self.ftp_send_ctrl("226 Transfer complete\r\n")

    def handle_SIZE(self, line):
        stbuf = bytearray(STAT_SIZE)
        if u64_to_i64(stat_(self.state.cur_path.encode("utf-8")+b"\0", stbuf)) < 0:
            self.ftp_send_ctrl("550 The file doesn't exist\r\n")
            return
        size = read_u64_le(stbuf, STAT_OFF_SIZE)
        self.ftp_send_ctrl("213 {:d}\r\n".format(size))

    def _open_for_send(self, full_path):
        fd = u64_to_i64(open_(full_path.encode("utf-8")+b"\0", O_RDONLY, 0))
        return fd

    def _open_for_recv(self, full_path, append=False):
        mode = O_CREAT | O_RDWR
        mode |= O_APPEND if append else O_TRUNC
        fd = u64_to_i64(open_(full_path.encode("utf-8")+b"\0", mode, 0o777))
        return fd

    def _send_file(self, full_path):
        fd = self._open_for_send(full_path)
        if fd < 0:
            self.ftp_send_ctrl("550 File not found\r\n")
            return
        if self.state.restore_point and self.state.restore_point >= 0:
            lseek_(fd, self.state.restore_point, 0)  # SEEK_SET=0
        chunk = bytearray(8192)
        self.ftp_send_ctrl("150 Opening Image mode data transfer\r\n")
        if not self.ftp_open_data():
            close_(fd); return
        while True:
            n = u64_to_i64(read_(fd, chunk, len(chunk)))
            if n <= 0:
                break
            self.ftp_send_data(chunk[:n])
        self.ftp_close_data()
        close_(fd)
        self.ftp_send_ctrl("226 Transfer completed\r\n")

    def _recv_file(self, full_path, append=False):
        fd = self._open_for_recv(full_path, append=append)
        if fd < 0:
            self.ftp_send_ctrl("500 Error opening file\r\n")
            return
        self.ftp_send_ctrl("150 Opening Image mode data transfer\r\n")
        if not self.ftp_open_data():
            close_(fd); return
        chunk = bytearray(8192)
        while True:
            # read from data connection into chunk
            if self.state.conn_type == "active":
                n = u64_to_i64(read_(self.state.data_sock, chunk, len(chunk)))
            else:
                n = u64_to_i64(read_(self.state.pasv_accepted_sock, chunk, len(chunk)))
            if n <= 0:
                break
            w = u64_to_i64(write_(fd, chunk[:n], n))
            if w < n:
                self.ftp_send_ctrl("550 File write error\r\n")
                break
        self.ftp_close_data()
        close_(fd)
        self.ftp_send_ctrl("226 Transfer completed\r\n")

    def handle_RETR(self, line):
        arg = line[5:].strip()
        full = (self.state.cur_path if self.state.cur_path != "/" else "") + "/" + arg if not arg.startswith("/") else arg
        self._send_file(full)

    def handle_STOR(self, line):
        arg = line[5:].strip()
        full = sanitize_path(self.state.cur_path, arg)
        self._recv_file(full, append=False)

    def handle_APPE(self, line):
        arg = line[5:].strip()
        full = sanitize_path(self.state.cur_path, arg)
        self.state.restore_point = -1
        self._recv_file(full, append=True)

    def handle_REST(self, line):
        try:
            off = int(line.split()[1])
        except Exception:
            self.ftp_send_ctrl("501 Invalid REST parameter\r\n")
            return
        self.state.restore_point = off
        self.ftp_send_ctrl("350 Resuming at {}\r\n".format(off))

    def handle_MKD(self, line):
        arg = line[4:].strip()
        full = sanitize_path(self.state.cur_path, arg)
        # if already exists as file/dir?
        fd = u64_to_i64(open_(full.encode("utf-8")+b"\0", O_RDONLY, 0))
        if fd >= 0:
            close_(fd)
            self.ftp_send_ctrl("550 Requested action not taken. Folder already exists.\r\n")
            return
        ret = u64_to_i64(mkdir_(full.encode("utf-8")+b"\0", 0o755))
        if ret < 0:
            self.ftp_send_ctrl("501 Syntax error. Not privileged.\r\n")
        else:
            self.ftp_send_ctrl('257 "{}" created.\r\n'.format(arg))

    def handle_RMD(self, line):
        arg = line[4:].strip()
        full = sanitize_path(self.state.cur_path, arg)
        # ensure exists
        fd = u64_to_i64(open_(full.encode("utf-8")+b"\0", O_RDONLY, 0))
        if fd >= 0:
            close_(fd)
            ret = u64_to_i64(rmdir_(full.encode("utf-8")+b"\0"))
            if ret < 0:
                self.ftp_send_ctrl("550 Directory not found or permission denied\r\n")
            else:
                self.ftp_send_ctrl('250 "{}" has been removed\r\n'.format(arg))
        else:
            self.ftp_send_ctrl("500 Directory doesn't exist\r\n")

    def handle_DELE(self, line):
        arg = line[5:].strip()
        full = sanitize_path(self.state.cur_path, arg)
        ret = u64_to_i64(unlink_(full.encode("utf-8")+b"\0"))
        if ret < 0:
            self.ftp_send_ctrl("550 Could not delete the file\r\n")
        else:
            self.ftp_send_ctrl("226 File deleted\r\n")

    def handle_RNFR(self, line):
        arg = line[5:].strip()
        full = sanitize_path(self.state.cur_path, arg)
        stbuf = bytearray(STAT_SIZE)
        if u64_to_i64(stat_(full.encode("utf-8")+b"\0", stbuf)) >= 0:
            self.state.rname = arg
            self.ftp_send_ctrl("350 Remembered filename\r\n")
        else:
            self.ftp_send_ctrl("550 The file doesn't exist\r\n")

    def handle_RNTO(self, line):
        arg = line[5:].strip()
        if not self.state.rname:
            self.ftp_send_ctrl("503 Bad sequence of commands\r\n")
            return
        old_full = sanitize_path(self.state.cur_path, self.state.rname)
        new_full = sanitize_path(self.state.cur_path, arg)
        ret = u64_to_i64(rename_(old_full.encode("utf-8")+b"\0", new_full.encode("utf-8")+b"\0"))
        if ret < 0:
            self.ftp_send_ctrl("550 Error renaming file\r\n")
        else:
            self.ftp_send_ctrl("226 Renamed file\r\n")

    def handle_SITE(self, line):
        # support: SITE CHMOD <mode> <path>
        # and:     SITE SHUTDOWN
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1].upper() == "SHUTDOWN":
            # Admin shutdown: close listener and mark server to stop accepting
            self.ftp_send_ctrl("200 Shutting down server\r\n")
            try:
                close_(self.listen_sock)
            except:
                pass
            self.running = False
            print("FTP server payload stopped!")
            return

        # existing CHMOD behavior
        if len(parts) >= 4 and parts[1].upper() == "CHMOD":
            try:
                rule = int(parts[2], 10)
            except Exception:
                self.ftp_send_ctrl("550 Permission denied\r\n")
                return
            path = " ".join(parts[3:])
            full = sanitize_path(self.state.cur_path, path)
            mode = int("{:04d}".format(rule), 8)
            ret = u64_to_i64(chmod_(full.encode("utf-8")+b"\0", mode))
            if ret < 0:
                self.ftp_send_ctrl("550 Permission denied\r\n")
            else:
                self.ftp_send_ctrl("200 OK\r\n")
            return

        # unknown SITE subcommand
        self.ftp_send_ctrl("550 Syntax error, command unrecognized\r\n")

    # --- main client loop ---
    def serve_one(self, ctrl_sock):
        self.state.ctrl_sock = ctrl_sock
        self.state.is_connected = True
        self.ftp_send_ctrl("220 RLL FTP Server\r\n")
        handlers = {
            "USER": self.handle_USER,
            "PASS": self.handle_PASS,
            "NOOP": self.handle_NOOP,
            "PWD":  self.handle_PWD,
            "TYPE": self.handle_TYPE,
            "PASV": self.handle_PASV,
            "LIST": self.handle_LIST,
            "CWD":  self.handle_CWD,
            "CDUP": self.handle_CDUP,
            "PORT": self.handle_PORT,
            "SYST": self.handle_SYST,
            "FEAT": self.handle_FEAT,
            "MKD":  self.handle_MKD,
            "RMD":  self.handle_RMD,
            "SIZE": self.handle_SIZE,
            "DELE": self.handle_DELE,
            "RNFR": self.handle_RNFR,
            "RNTO": self.handle_RNTO,
            "RETR": self.handle_RETR,
            "STOR": self.handle_STOR,
            "APPE": self.handle_APPE,
            "REST": self.handle_REST,
            "SITE": self.handle_SITE,
        }
        while True:
            line = self.recv_line(ctrl_sock)
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            cmd = line.split()[0].upper()
            if cmd == "QUIT":
                self.ftp_send_ctrl("221 Goodbye\r\n")
                break
            handler = handlers.get(cmd, None)
            if handler is None:
                self.ftp_send_ctrl("500 Syntax error, command unrecognized.\r\n")
                continue
            try:
                handler(line)
            except Exception as e:
                # Best-effort robustness
                self.ftp_send_ctrl("550 Internal server error\r\n")

        # cleanup
        try:
            close_(ctrl_sock)
        except:
            pass
        try:
            self.ftp_close_data()
        except:
            pass
        if self.listen_sock is not None:
            # we keep the listener to accept next client
            pass

    def run(self):
        self.listen_sock = u64_to_i64(socket_(AF_INET, SOCK_STREAM, 0))
        if self.listen_sock < 0:
            raise Exception("socket() failed, errno=%d" % socket_.errno)
        # reuseaddr before bind (BSD)
        setsockopt_(self.listen_sock, SOL_SOCKET, SO_REUSEADDR, Enable4, 4)

        # bind to configured FTP port (e.g., 1337)
        sa = SockAddrIn.create()
        sa.sin_len    = 16
        sa.sin_family = AF_INET
        sa.sin_port   = htons(self.port)   # fixed port for control channel
        sa.sin_addr   = 0                  # INADDR_ANY
        rc = u64_to_i64(bind_(self.listen_sock, sa, 16))
        if rc != 0:
            raise Exception("bind() failed rc=%d errno=%d" % (rc, bind_.errno))
        rc = u64_to_i64(listen_(self.listen_sock, 128))
        if rc != 0:
            raise Exception("listen() failed rc=%d errno=%d" % (rc, listen_.errno))

        ip_disp = self.ip or sc.get_current_ip() or "0.0.0.0"
        print("[*] FTP server running on %s:%d" % (ip_disp, self.port))
        sys.stdout.flush()
        try:
            sc.send_notification("FTP Server listening on %s:%d" % (ip_disp, self.port))
        except Exception:
            pass

        # Accept loop
        while self.running:
            addr = SockAddrIn.create()
            ln = Structure([("len",4)]).create()
            ln.len = 16
            cs = u64_to_i64(accept_(self.listen_sock, addr, ln))
            if cs < 0:
                if not self.running:
                    break
                continue
            self.serve_one(cs)
        try: close_(self.listen_sock)
        except: pass

# ===== Run the server =====
FTPServer(port=1337).run()
