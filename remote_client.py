import socket
import sys

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


def main(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Read initial greeting (may also include first prompt)
    try:
        s.settimeout(0.25)
        init = s.recv(4096)
        if init:
            sys.stdout.write(init.decode("utf-8", errors="ignore"))
            sys.stdout.flush()
    except socket.timeout:
        pass
    finally:
        s.settimeout(None)

    while True:
        # Local prompt
        sys.stdout.write("ps> ")
        sys.stdout.flush()

        # User input
        line = sys.stdin.readline()
        if not line:
            break

        s.sendall(line.encode("utf-8"))

        # Read execution result
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
