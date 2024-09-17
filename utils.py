import struct
import socket
import threading
import queue
from typing import Dict, List, Tuple


# TODO: add support for ipv6


def pack_peers(peers: list[str, int]) -> bytes:
    packed_peers = bytearray()

    for ip, port in peers:
        packed_peers.extend(socket.inet_aton(ip))
        packed_peers.extend(struct.pack("!H", port))

    return bytes(packed_peers)


def unpack_peers(packed_peers: bytes) -> List[Tuple[str, int]]:
    assert len(packed_peers) % 6 == 0

    peers = []
    offset = 0
    for _ in range(len(packed_peers)//6):
        ip = struct.unpack_from("!I", packed_peers, offset)[0]
        ip = socket.inet_ntoa(struct.pack("!I", ip))
        offset += 4
        port = struct.unpack_from("!H", packed_peers, offset)[0]
        offset += 2
        peers.append((ip, port))

    return peers


def unpack_nodes(packed_nodes: bytes) -> list[bytes, str, int]:
    assert len(packed_nodes) % 26 == 0

    nodes = []
    offset = 0
    for _ in range(len(packed_nodes)//26):
        node_id = packed_nodes[offset:offset+20]
        ip, port = unpack_peers(packed_nodes[offset+20:offset+26])[0]
        nodes.append((node_id, ip, port))
        offset += 26
    return nodes


class DHTSocket(threading.Thread):
    def __init__(self) -> None:
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(1)
        self.socket.settimeout(1)
        # self.socket.bind(("127.0.0.1", 12000))  # TODO

        self.qq: Dict[str, queue.Queue] = {}
        self.qq_lock = threading.Lock()

    def sendto(self, bytes, address):
        self.socket.sendto(bytes, address)

    def recv_from(self, address: tuple, timeout: int) -> bytes | None:
        address = f'{address[0]}:{address[1]}'
        with self.qq_lock:
            if not address in self.qq:
                self.qq[address] = queue.Queue()
            msg_queue = self.qq[address]
        try:
            return msg_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def stop(self):
        self._stop_event.set()

    def run(self):
        ''' run the thread '''

        self._stop_event.clear()
        while not self._stop_event.is_set():
            try:
                msg, address = self.socket.recvfrom(1024)
                if type(address) is tuple:
                    address = f'{address[0]}:{address[1]}'
                with self.qq_lock:
                    if not address in self.qq:
                        self.qq[address] = queue.Queue()
                    msg_queue = self.qq[address]
                msg_queue.put(msg)
            except socket.timeout:
                continue

    def close(self):
        self.socket.close()


if __name__ == '__main__':
    # peers = [('192.168.1.1', 8080)]

    # packed_peers = pack_peers(peers)
    # print(packed_peers)

    # pp = unpack_peers(packed_peers)
    # print(pp)

    sock = DHTSocket()
    sock.start()
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = b'test'
        addr = ("127.0.0.1", 12000)
        client_socket.sendto(message, addr)
        # client_socket.bind(('127.0.0.1', 12010))
        msg = sock.recv_from(
            ('127.0.0.1', client_socket.getsockname()[1]), timeout=400)
        print(msg)
    except KeyboardInterrupt:
        pass
    finally:
        sock.stop()
        sock.join()
        sock.close()
