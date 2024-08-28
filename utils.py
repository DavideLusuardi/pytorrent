import struct
import socket


def pack_peers(peers: list[int, int]) -> bytes:
    packed_peers = bytearray()

    for ip, port in peers:
        packed_peers.extend(socket.inet_aton(ip))
        packed_peers.extend(struct.pack("!H", port))

    return bytes(packed_peers)


def unpack_peers(packed_peers: bytes) -> list[int, int]:
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


if __name__ == '__main__':
    peers = [('192.168.1.1', 8080)]

    packed_peers = pack_peers(peers)
    print(packed_peers)

    pp = unpack_peers(packed_peers)
    print(pp)
