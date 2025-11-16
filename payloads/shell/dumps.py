from sc import sc
from utils.unsafe import readbuf

global client_sock

# Transfers
def xfer_begin(x_type, name, size=-1):
    hdr  = "__XFER_BEGIN__\n"
    hdr += "TYPE:%s\n"  % x_type
    hdr += "NAME:%s\n"  % name
    hdr += "SIZE:%d\n"  % size
    hdr += "__XFER_START__\n"
    sc.syscalls.write(client_sock, hdr, len(hdr))

def xfer_data(data):
    # data must be a byte string (safe)
    sc.syscalls.write(client_sock, data, len(data))

def xfer_end():
    tail = "__XFER_END__\n"
    sc.syscalls.write(client_sock, tail, len(tail))

# Dumps
def memdump(addr, length):
    xfer_begin("BIN", "mem_%x" % addr, length)
    buf = readbuf(addr, length)
    xfer_data(buf)
    xfer_end()

def dump_dict(d):
    xfer_begin("KV", "dict_dump", -1)
    for k, v in d.items():
        line = "KEY:%r VAL:%r\n" % (k, v)
        xfer_data(line)
    xfer_end()
