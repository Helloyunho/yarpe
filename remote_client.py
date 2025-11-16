import socket
import sys
import os

END_MARKER = b"\n<<<END_OF_RESULT>>>\n"


def recv_until(sock, marker):
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if marker in data:
            break
    parts = data.split(marker, 1)
    return parts[0].decode("utf-8", errors="ignore")


def send_addon(sock, name):
    """
    Sends the contents of a local addon file from ./shell/<name>.py
    to the remote shell.
    """
    path = os.path.join("./payloads/shell", name + ".py")

    if not os.path.exists(path):
        print("Addon not found:", path)
        return

    with open(path, "r") as f:
        contents = f.read()

    header = "__LOAD_BEGIN__:%s\n" % name
    sock.sendall(header.encode("utf-8"))
    sock.sendall(contents.encode("utf-8"))
    sock.sendall("__LOAD_END__".encode("utf-8"))

    # Wait for remote ack
    result = recv_until(sock, END_MARKER)
    sys.stdout.write(result)
    sys.stdout.flush()


def main(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Initial greeting
    try:
        s.settimeout(0.25)
        init = s.recv(4096)
        if init:
            sys.stdout.write(init.decode("utf-8", errors="ignore"))
    except socket.timeout:
        pass
    finally:
        s.settimeout(None)

    while True:
        sys.stdout.write("ps> ")
        sys.stdout.flush()

        line = sys.stdin.readline()
        if not line:
            break

        # Check if local client should intercept command
        if line.startswith(".load "):
            # Send the .load command to remote
            s.sendall(line.encode("utf-8"))

            # Expect __LOAD_REQUEST__ from remote
            resp = recv_until(s, END_MARKER)
            if "__LOAD_REQUEST__:" in resp:
                # Extract clean request
                idx = resp.find("__LOAD_REQUEST__:")
                req_line = resp[idx:].strip()

                # Now parse name
                reqname = req_line.split(":", 1)[1].strip()

                # Send addon to remote
                send_addon(s, reqname)
                continue
            else:
                # Unexpected output
                sys.stdout.write(resp)
                sys.stdout.flush()

            continue

        # Normal command, send to remote
        s.sendall(line.encode("utf-8"))

        # Read result
        result = recv_until(s, END_MARKER)
        if result:
            sys.stdout.write(result)
            sys.stdout.flush()

        if line.strip() in (".exit", "quit()", "exit()", ".quit"):
            break

    s.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: remote_client.py <ip> <port>")
        sys.exit(1)

    main(sys.argv[1], int(sys.argv[2]))
