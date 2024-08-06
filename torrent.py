import bencodepy
import requests
import hashlib
import gzip
import struct
import socket
import time
import socket
import threading
import pprint
import os


class Torrent:
    def __init__(self, torrent_file) -> None:
        self.peer_id = hashlib.sha1(b'0').digest()  # TODO: generate random id
        self.torrent_file: str = torrent_file
        self.metainfo: dict = None
        self.tracker_url: str = None
        self.trackerid: bytes = None
        self.pieces_hashes: list = None
        self.info_hash: bytes = None
        self.peers: list = None

        self.am_choking = True
        self.am_interested = False
        self.peer_choking = True
        self.peer_interested = False

        self.socket = None
        self.queue_pieces = []
        self.downloaded_pieces = set()

        self.read_torrent_file()

    def read_torrent_file(self):
        with open(self.torrent_file, 'rb') as f:
            self.metainfo = bencodepy.decode(f.read())

        pieces = self.metainfo[b'info'][b'pieces']
        assert len(pieces) % 20 == 0, 'malformed pieces field'
        num_pieces = len(pieces)//20
        self.pieces_hashes = []
        for i in range(num_pieces):
            self.pieces_hashes.append(pieces[i*20:(i+1)*20])
        # print(self.pieces_hashes)

        self.tracker_url = self.metainfo[b'announce'].decode()
        # print(f"tracker_url: {self.tracker_url}")

        self.info_hash = hashlib.sha1(
            bencodepy.encode(self.metainfo[b'info'])).digest()
        print(self.info_hash)

        self.metainfo[b'info'][b'pieces'] = None
        pprint.pprint(self.metainfo)
        self.metainfo[b'info'][b'pieces'] = pieces

    def query_tracker(self):
        params = {
            'info_hash': self.info_hash,
            'peer_id': self.peer_id,
            'port': 6881,  # TODO: select port
            'uploaded': 0,
            'downloaded': 0,
            'left': self.metainfo[b'info'][b'length'],
            'compact': 0,
            # 'no_peer_id':
            'event': 'started',
            # 'ip':
            'numwant': 10,
            # 'key':
        }
        if self.trackerid is not None:
            params['trackerid'] = self.trackerid

        response = requests.get(url=self.tracker_url, params=params)
        assert response.ok, 'tracker response error'
        response = bencodepy.decode(response.content)
        pprint.pprint(response)

        if b'trackerid' in response:
            self.trackerid = response[b'trackerid']
            print('trackerid present')
            print(self.trackerid)

        assert len(response[b'peers']) % 6 == 0, 'malformed peers field'
        self.peers = []
        offset = 0
        for _ in range(len(response[b'peers'])//6):
            ip = struct.unpack_from("!i", response[b'peers'], offset)[0]
            ip = socket.inet_ntoa(struct.pack("!i", ip))
            offset += 4
            port = struct.unpack_from("!H", response[b'peers'], offset)[0]
            offset += 2
            self.peers.append((ip, port))

    def scrape_tracker(self):
        params = {
            'info_hash': self.info_hash,
        }
        response = requests.get(
            url='https://torrent.ubuntu.com/scrape', params=params)  # TODO: fix url

        pprint.pprint(bencodepy.decode(response.content))

    def handshake_peer(self):
        assert len(self.peers) > 0, 'no peers'
        # if len(self.peers) == 0:
        #     print('no peers')
        #     self.peers = [('185.125.190.59', 6901)]

        ip, port = self.peers[0]
        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr).to_bytes(1, 'big')
        reserved = b'\x00' * 8
        payload = pstrlen + pstr + reserved + self.info_hash + self.peer_id
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(1)
        self.socket.connect((ip, port))
        self.socket.sendall(payload)
        print(pstrlen.decode())
        print(payload)
        data = self.socket.recv(1024)
        print(data)
        p_pstrlen = int.from_bytes(data[:1], 'big')
        print(f"p_pstrlen: {p_pstrlen}")
        p_pstr = data[1:1+p_pstrlen]
        p_reserved = data[1+p_pstrlen: 1+p_pstrlen+8]
        p_info_hash = data[1+p_pstrlen+8: 1+p_pstrlen+8+20]
        p_peer_id = data[1+p_pstrlen+8+20: 1+p_pstrlen+8+20+20]
        assert len(p_peer_id) == 20
        print(p_pstrlen)
        print(p_pstr)
        print(p_reserved)
        print(p_info_hash)
        print(p_peer_id)

    def receive_data(self, data_len):
        data = self.socket.recv(data_len)
        while len(data) < data_len:
            data += self.socket.recv(data_len - len(data))
        assert len(data) == data_len
        return data

    def receive_msg(self):
        messages = ['choke', 'unchoke', 'interested', 'not interested',
                    'have', 'bitfield', 'request', 'piece', 'cancel', 'port']
        while True:
            data = self.receive_data(4)

            len_prefix = int.from_bytes(data, 'big')
            print(f"len_prefix: {len_prefix}")
            if len_prefix == 0:
                # keep-alive msg
                print(f"r::keep-alive")
                continue

            data = self.receive_data(len_prefix)
            message_id = int.from_bytes(data[:1], 'big')
            assert message_id < len(messages), 'unknown message received'
            print(f"r::{messages[message_id]}")

            if message_id == 4:
                # have msg
                piece_index = int.from_bytes(data[1:5], 'big')
                if not piece_index in self.downloaded_pieces:
                    self.queue_pieces.append(piece_index)
                print(f"piece_index: {piece_index}")
            elif message_id == 5:
                # bitfield msg
                bitfield = int.from_bytes(data[1:], 'big')
                print(f"bitfield: {bitfield}")
            elif message_id == 7:
                # piece msg
                index = int.from_bytes(data[1:5], 'big')
                begin = int.from_bytes(data[5:9], 'big')
                print(f"index: {index}")
                print(f"begin: {begin}")
                print(f"block: {data[9:100]}")

    def send_msg(self):
        # unchoke msg
        print('s::unchoke')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (1).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

        time.sleep(2)
        # interested msg
        print('s::interested')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (2).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

    def download(self):
        while True:
            while len(self.queue_pieces) == 0:
                time.sleep(1)

            piece_idx = self.queue_pieces.pop(0)

            # request msg
            print(f's::request::{piece_idx}')
            len_prefix = (13).to_bytes(4, 'big')
            message_id = (6).to_bytes(1, 'big')
            payload = (piece_idx).to_bytes(4, 'big') + \
                (0).to_bytes(4, 'big') + (2**14).to_bytes(4, 'big')
            self.socket.sendall(len_prefix + message_id + payload)

    def run(self):
        self.send_msg()

        t1 = threading.Thread(target=self.receive_msg)
        t2 = threading.Thread(target=self.download)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def __str__(self):
        return '\n'.join(
            f"peer_id: {self.peer_id}",
            f"torrent_file: {self.torrent_file}",
            f"tracker_url: {self.tracker_url}"
        )


def main():
    # torrent_file = os.path.join('torrent_files','torrent_file.torrent')
    torrent_file = os.path.join('torrent_files', 'ubuntu18.torrent')
    torrent = Torrent(torrent_file)
    torrent.query_tracker()
    print(torrent.peers)
    torrent.scrape_tracker()
    torrent.handshake_peer()

    # torrent.receive_msg()
    torrent.run()


if __name__ == '__main__':
    main()
