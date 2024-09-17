import random
import bencodepy
import logging
import threading
import queue
from typing import List, Dict, Tuple

import utils

logger = logging.getLogger(__name__)


class Bucket(list):
    pass


class DHTNode(threading.Thread):
    def __init__(self, info_hash: bytes, handle_new_peers) -> None:
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()

        self.node_id: bytes = random.randbytes(160//8)
        self.info_hash: bytes = info_hash
        self.handle_new_peers = handle_new_peers

        self.k: int = 8  # bucket size
        self.routing_table: List = self.construct_routing_table()

        self.socket = utils.DHTSocket()
        self.socket.start()

        self.node_queue = queue.Queue()

        logger.debug(f'dht node created')

    def construct_routing_table(self, d: int = 160) -> List:
        if d == 0:
            return Bucket()

        routing_table = [self.construct_routing_table(d-1), Bucket()]
        return routing_table

    def distance(id1: bytes, id2: bytes) -> int:
        ''' xor distance '''

        assert len(id2) == 160//8
        res = bytes(a ^ b for a, b in zip(id1, id2))
        return int.from_bytes(res, 'big')

    def distance_binary(id1: bytes, id2: bytes) -> str:
        dist = bin(DHTNode.distance(id1, id2))[2:]
        assert len(dist) <= 160
        return '0'*(160-len(dist)) + dist

    def add(self, ip: str, port: int, node_id: bytes):
        node = (ip, port, node_id)

        binary_dist = DHTNode.distance_binary(self.node_id, node_id)
        routing_table = self.routing_table
        for bit in binary_dist:
            routing_table = routing_table[int(bit)]
            if type(routing_table) is Bucket:
                bucket = routing_table
                if len(bucket) < self.k:
                    bucket.append(node)
                    logger.debug(f'add:{ip}:{port} {node_id}')
                    # TODO: remove bad nodes
                # else:
                #     print('full bucket')
                break

    def search_rec(self, routing_table, info_hash: bytes):
        # TODO: return torrent peers when found

        def search_bucket(bucket: Bucket):
            min_dist = 2**161
            node = None
            for n in bucket:
                dist = DHTNode.distance(info_hash, n[2])
                if dist < min_dist:
                    min_dist = dist
                    node = n
            return min_dist, node

        if type(routing_table) == Bucket:
            return search_bucket(routing_table)

        dist1, node1 = self.search_rec(routing_table[0], info_hash)
        dist2, node2 = self.search_rec(routing_table[1], info_hash)
        if dist1 < dist2:
            return dist1, node1
        return dist2, node2

    def search(self, info_hash: bytes):
        return self.search_rec(self.routing_table, info_hash)

    def ping(self, host: str, port: int) -> bytes | None:
        logger.debug(f'ping {host}:{port}')

        transaction_id = random.randbytes(2)
        payload = bencodepy.encode({
            't': transaction_id,
            'y': 'q',
            'q': 'ping',
            'a': {
                'id': self.node_id
            }
        })
        self.socket.sendto(payload, (host, port))
        response = self.socket.recv_from((host, port), timeout=10)
        if response is None:
            return None
        response = bencodepy.decode(response)

        logger.debug(f'ping response::{response}')
        assert response[b't'] == transaction_id
        node_id = response[b'r'][b'id']
        return node_id

    def find_node(self, host: str, port: int, target_id: bytes) -> bytes:
        logger.debug(f'find_node {target_id}')

        transaction_id = random.randbytes(2)
        payload = bencodepy.encode({
            't': transaction_id,
            'y': 'q',
            'q': 'find_node',
            'a': {
                'id': self.node_id,
                'target': target_id
            }
        })
        self.socket.sendto(payload, (host, port))
        response = self.socket.recv_from((host, port), timeout=10)
        if response is None:
            return None
        response = bencodepy.decode(response)

        logger.debug(f'find_node response::{response}')
        assert response[b't'] == transaction_id
        nodes = response[b'r'][b'nodes']
        return nodes

    def get_peers(self, host: str, port: int, info_hash: bytes) -> Tuple:
        logger.debug(f'get_peers {info_hash}')

        transaction_id = random.randbytes(2)
        payload = bencodepy.encode({
            't': transaction_id,
            'y': 'q',
            'q': 'get_peers',
            'a': {
                'id': self.node_id,
                'info_hash': info_hash
            }
        })
        self.socket.sendto(payload, (host, port))
        response = self.socket.recv_from((host, port), timeout=10)
        if response is None:
            return None, None, None
        response = bencodepy.decode(response)

        logger.debug(f'get_peers response::{response}')
        assert response[b't'] == transaction_id

        if not b'token' in response[b'r']:
            logger.debug(f'token not present')
            token = None
        else:
            token = response[b'r'][b'token']

        if b'values' in response[b'r']:
            peers = response[b'r'][b'values']
            peers = utils.unpack_peers(b''.join(peers))
            return True, peers, token

        nodes = response[b'r'][b'nodes']
        nodes = utils.unpack_nodes(nodes)
        return False, nodes, token

    def announce_peer(self, host: str, port: int, info_hash: bytes, peer_port: int, token: bytes) -> bytes:
        logger.debug(f'announce_peer')

        transaction_id = random.randbytes(2)
        payload = bencodepy.encode({
            't': transaction_id,
            'y': 'q',
            'q': 'announce_peer',
            'a': {
                'id': self.node_id,
                'info_hash': info_hash,
                'port': peer_port,
                'token': token,
                'implied_port': 0  # TODO: peers behind a NAT
            }
        })
        self.socket.sendto(payload, (host, port))
        response = self.socket.recv_from((host, port), timeout=10)
        if response is None:
            return None
        response = bencodepy.decode(response)

        logger.debug(f'announce_peer response::{response}')
        assert response[b't'] == transaction_id
        nodes = response[b'r'][b'nodes']
        return nodes

    def check_and_add(self, host: str, port: int) -> bool:
        # TODO: make the function non-blocking

        node_id = self.ping(host, port)
        logger.debug(f'node id:{node_id}')

        if node_id is not None:
            self.add(host, port, node_id)

        peers_found = False
        nodes: list = [(node_id, host, port)]
        while not peers_found and len(nodes) > 0:
            node_id, host, port = nodes.pop()
            peers_found, peers_nodes, token = self.get_peers(
                host, port, self.info_hash)
            if peers_found is None:
                continue
            if peers_found:
                logger.info(f'dht peers: {peers_nodes}')
                self.handle_new_peers(peers_nodes)
                return True

            # logger.info(f'dht nodes: {peers_nodes}')
            nodes += peers_nodes
            nodes.sort(key=lambda node: DHTNode.distance(
                node[0], self.info_hash), reverse=True)

        return False

    def stop(self) -> None:
        self._stop_event.set()
        self.socket.stop()
        self.socket.join()
        self.socket.close()

    # def run(self) -> None:
    #     while not self._stop_event.is_set():
    #         try:
    #             self.node_queue.get(timeout=1)
    #         except queue.Empty:
    #             pass


if __name__ == '__main__':
    info_hash = random.randbytes(160//8)
    dht_node = DHTNode(info_hash)
    # print(dht_node.routing_table)

    for i in range(1000):
        ip, port, node_id = f'0.0.0.{i}', 8000+i, random.randbytes(160//8)
        dht_node.add(ip, port, node_id)

    print(dht_node.routing_table)

    dist, node = dht_node.search(info_hash)
    print(dist)
    print(node)
