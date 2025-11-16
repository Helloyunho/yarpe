import sys
import traceback
from StringIO import StringIO
from constants import SYSCALL
from errors.socket import SocketError
from utils.conversion import u64_to_i64
from utils.etc import alloc
from utils.rp import log
from sc import sc

WRITING = False

if WRITING:
    port = 0
    s = 0
    sockaddr_in = bytearray()
    len_buf = bytearray()

PROMPT = "ps> "
END_MARKER = "\n<<<END_OF_RESULT>>>\n"

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


# CLI related
def handle_special_commands(cmd, ctx):
    """
    Special commands
    """
    stripped = cmd.strip()

    if stripped in (".exit", "exit()", "quit()", ".quit"):
        log("Exit requested.")
        raise SystemExit

    if stripped.startswith(".load "):
        name = stripped[6:].strip()

        # Ask client to send the addon payload
        request = "__LOAD_REQUEST__:%s\n" % name
        sc.syscalls.write(client_sock, request, len(request))

        # Do NOT produce output now, client will respond with code
        return "", ""

    if stripped == ".kill":
        kill_game()
        return "", ""

    if stripped == ".syscalls":
        names = sorted(SYSCALL.keys())
        out = "Defined syscalls:\n" + ", ".join(names) + "\n"
        return out, ""

    # .vars -> mostrar keys de ctx
    if stripped == ".vars":
        names = sorted(ctx.keys())
        out = "Context variables:\n" + ", ".join(names) + "\n"
        return out, ""

    # .type nombre
    if stripped.startswith(".type "):
        name = stripped[6:].strip()
        if name in ctx:
            obj = ctx[name]
            out = "type(%s): %r\n" % (name, type(obj))
        else:
            out = "Name %r not found in context.\n" % name
        return out, ""

    # .repr nombre
    if stripped.startswith(".repr "):
        name = stripped[6:].strip()
        if name in ctx:
            obj = ctx[name]
            out = "repr(%s): %r\n" % (name, obj)
        else:
            out = "Name %r not found in context.\n" % name
        return out, ""

    # Ningún comando especial
    return None, None


def handle_command(cmd, ctx):
    log("handle_command() received cmd=%r" % cmd)

    cmd = cmd.rstrip("\n")
    if not cmd:
        log("Empty command.")
        return "", ""

    # Primero intentamos comandos especiales tipo .vars, etc.
    special_out, special_err = handle_special_commands(cmd, ctx)
    if special_out is not None or special_err is not None:
        return special_out or "", special_err or ""

    stdout_buf = StringIO()
    stderr_buf = StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = stdout_buf
    sys.stderr = stderr_buf

    try:
        code_obj = compile(cmd, "<remote>", "eval")
        log("Compiled as eval.")
        result = eval(code_obj, ctx, ctx)
        if result is not None:
            print(repr(result))
    except SystemExit:
        raise
    except Exception:
        log("Exception while running code.")
        traceback.print_exc(file=stderr_buf)
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    out = stdout_buf.getvalue()
    err = stderr_buf.getvalue()

    if out:
        log("stdout=%r" % out)
    if err:
        log("stderr=%r" % err)

    return out, err

def handle_addon(client_sock, cmd):
    buf1 = alloc(1)
    name = cmd.split(":", 1)[1].strip()
    code = ""

    # Read until we encounter __LOAD_END__
    while True:
        n = u64_to_i64(sc.syscalls.read(client_sock, buf1, 1))
        if n <= 0:
            break

        c = chr(buf1[0])
        code += c

        if code.endswith("__LOAD_END__"):
            code = code[:-len("__LOAD_END__")]  # strip marker
            break

    # Execute addon code
    try:
        exec compile(code, "<addon:%s>" % name, "exec") in ctx, ctx
        msg = "Addon '%s' loaded successfully.\n" % name
    except Exception as e:
        msg = "Addon '%s' failed: %s\n" % (name, e)

    sc.syscalls.write(client_sock, msg, len(msg))
    sc.syscalls.write(client_sock, END_MARKER, len(END_MARKER))

# Outer loop
while True:
    log("Waiting for incoming connection...")
    client_sock = u64_to_i64(sc.syscalls.accept(s, sockaddr_in, len_buf))
    log("Accepted client_sock=%d" % client_sock)

    buf1 = alloc(1)

    # Send greeting
    greeting = (
        "Remote Python console ready (Python 2.7).\n"
        "Reusing Stage-1 listener socket.\n"
        "Special commands: .exit, .quit, .vars, .type name, .repr name\n"
    )
    sc.syscalls.write(client_sock, greeting, len(greeting))

    ctx = globals()
    log("Globals loaded into REPL context.")

    # -----------------------------------------------------
    #  Inner REPL loop
    # -----------------------------------------------------
    while True:
        log("Writing prompt.")
        sc.syscalls.write(client_sock, PROMPT, len(PROMPT))

        log("Reading command bytes...")
        cmd_bytes = ""

        # Read command line (1 byte at a time)
        while True:
            n = u64_to_i64(sc.syscalls.read(client_sock, buf1, 1))

            if n <= 0:
                log("read <= 0, closing.")
                sc.syscalls.close(client_sock)
                raise SystemExit

            c = chr(buf1[0])
            cmd_bytes += c

            if c == "\n":
                log("Newline detected, end of command.")
                break

        # Now decode
        log("Decoding cmd_bytes=%r" % cmd_bytes)
        try:
            cmd = cmd_bytes.decode("utf-8", "replace")
        except Exception as e:
            log("DECODE ERROR: %s" % e)
            cmd = ""

        # Load addon
        try:
            if cmd.startswith("__LOAD_BEGIN__:"):
                handle_addon(client_sock, cmd)
                continue
        except Exception as e:
            log("Addon load ERROR: %s" % e)
            cmd = ""

        log("Decoded command: %r" % cmd)

        # Execute command
        try:
            out, err = handle_command(cmd, ctx)
        except SystemExit:
            bye = "Bye.\n"
            sc.syscalls.write(client_sock, bye, len(bye))
            sc.syscalls.close(client_sock)
            break

        # Send results
        result = out + err
        if result:
            log("Sending result len=%d" % len(result))
            sc.syscalls.write(client_sock, result, len(result))

        sc.syscalls.write(client_sock, END_MARKER, len(END_MARKER))
