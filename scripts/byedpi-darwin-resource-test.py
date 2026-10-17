import resource
import socket
import subprocess
import sys
import time


def limit_files():
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    address = reservation.getsockname()

clients = []
process = subprocess.Popen(
    [sys.argv[1], "--ip", address[0], "--port", str(address[1]), "--no-domain"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    preexec_fn=limit_files,
)
try:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            clients.append(socket.create_connection(address, timeout=0.1))
            break
        except OSError:
            if process.poll() is not None:
                raise RuntimeError("ByeDPI exited before accepting connections")
    if not clients:
        raise RuntimeError("ByeDPI did not listen")
    for _ in range(60):
        try:
            clients.append(socket.create_connection(address, timeout=0.05))
        except OSError:
            pass
    if len(clients) < 30:
        raise RuntimeError("File descriptor pressure was not reached")
    time.sleep(0.2)
    if process.poll() is not None:
        raise RuntimeError("File descriptor pressure terminated ByeDPI")
    for client in clients:
        client.close()
    clients.clear()
    time.sleep(0.3)
    with socket.create_connection(address, timeout=2) as client:
        client.sendall(b"\x05\x01\x00")
        if client.recv(2) != b"\x05\x00":
            raise RuntimeError("ByeDPI did not recover after file descriptors were released")
finally:
    for client in clients:
        client.close()
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
