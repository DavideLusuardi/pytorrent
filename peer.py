import socket
import time
import socket
import threading
from filemanager import FileManager


class Peer(threading.Thread):
    def __init__(self, ip, port, peer_manager, file_manager, info_hash, peer_id) -> None:
        threading.Thread.__init__(self)

        self.ip = ip
        self.port = port
        # self.id = f"{ip}:{port}"
        # self.peer_manager: PeerManager = peer_manager
        self.file_manager: FileManager = file_manager
        self.info_hash = info_hash
        self.peer_id = peer_id

        self.am_choking = True
        self.am_interested = False
        self.peer_choking = True
        self.peer_interested = False

        self.socket = None
        self.available_pieces = []
        self.idx_next_piece = 0
        # self.downloaded_pieces = set()

    def receive_data(self, data_len):
        data = self.socket.recv(data_len)
        while len(data) < data_len:
            data += self.socket.recv(data_len - len(data))
        assert len(data) == data_len
        return data

    def handshake_peer(self):
        # assert len(self.peer_manager.peers) > 0, 'no peers'
        # ip, port = self.peer_manager.peers[0]

        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr).to_bytes(1, 'big')
        reserved = b'\x00' * 8
        payload = pstrlen + pstr + reserved + \
            self.info_hash + self.peer_id

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(1)
        self.socket.connect((self.ip, self.port))
        self.socket.sendall(payload)
        # print(pstrlen.decode())
        # print(payload)

        p_pstrlen = int.from_bytes(self.receive_data(1), 'big')
        print(f"p_pstrlen: {p_pstrlen}")
        assert p_pstrlen > 0
        data = self.receive_data(p_pstrlen+48)
        # data = self.socket.recv(1024)
        print(data)
        # TODO: check peer_id coherence
        # p_pstrlen = int.from_bytes(data[:1], 'big')
        p_pstr = data[:p_pstrlen]
        p_reserved = data[p_pstrlen: p_pstrlen+8]
        p_info_hash = data[p_pstrlen+8: p_pstrlen+8+20]
        p_peer_id = data[p_pstrlen+8+20: p_pstrlen+8+20+20]
        assert len(p_peer_id) == 20
        print(p_pstrlen)
        print(p_pstr)
        print(p_reserved)
        print(p_info_hash)
        print(p_peer_id)

    def send_unchoke(self):
        ''' unchoke msg '''

        print('s::unchoke')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (1).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

        self.am_choking = False

    def send_interested(self):
        ''' interested msg '''

        print('s::interested')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (2).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

        self.am_interested = True

    def send_request(self, piece_index: int, begin: int, length: int):
        ''' request msg '''

        print(f's::request::{piece_index}')
        len_prefix = (13).to_bytes(4, 'big')
        message_id = (6).to_bytes(1, 'big')
        payload = (piece_index).to_bytes(4, 'big') + \
            (begin).to_bytes(4, 'big') + (length).to_bytes(4, 'big')
        self.socket.sendall(len_prefix + message_id + payload)

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

            if message_id == 0:
                # choke msg
                self.peer_choking = True

            elif message_id == 1:
                # unchoke msg
                self.peer_choking = False

            elif message_id == 2:
                # interested msg
                self.peer_interested = True

            elif message_id == 3:
                # not interested msg
                self.peer_interested = False

            elif message_id == 4:
                # have msg
                piece_index = int.from_bytes(data[1:5], 'big')
                # if not piece_index in self.downloaded_pieces:
                self.available_pieces.append(piece_index)
                print(f"piece_index: {piece_index}")

            elif message_id == 5:
                # bitfield msg
                bitfield = int.from_bytes(data[1:], 'big')
                print(f"bitfield: {bitfield}")

            elif message_id == 6:
                # request msg
                # TODO
                pass

            elif message_id == 7:
                # piece msg
                piece_index = int.from_bytes(data[1:5], 'big')
                begin = int.from_bytes(data[5:9], 'big')
                block = data[9:]
                print(f"index: {piece_index}")
                print(f"begin: {begin}")
                # print(f"block: {block[:100]}")
                self.file_manager.add_block(
                    piece_index, begin, block)

            elif message_id == 8:
                # cancel msg
                # TODO
                pass

            elif message_id == 9:
                # port msg
                # TODO
                pass

    def next_piece_index(self):
        while len(self.available_pieces) > self.idx_next_piece:
            piece_index = self.available_pieces[self.idx_next_piece]
            self.idx_next_piece += 1
            if not piece_index in self.file_manager.downloaded_pieces:
                return piece_index
        return None

    def download_piece(self, piece_index: int):
        piece_length = self.file_manager.piece_length(piece_index)
        block_index = 0
        begin = 0
        while begin < piece_length:
            block_length = min(
                self.file_manager.block_length, piece_length - begin)
            self.send_request(piece_index, begin, block_length)
            block_index += 1
            begin += block_length
            time.sleep(1)  # TODO

    def download(self):
        while True:
            piece_index = self.next_piece_index()
            if piece_index is None:
                time.sleep(1)  # TODO: use semaphores
                continue

            self.download_piece(piece_index)
            # TODO: more peers can download the same piece

    def run(self):
        self.handshake_peer()
        self.send_unchoke()
        self.send_interested()

        t1 = threading.Thread(target=self.receive_msg)
        t2 = threading.Thread(target=self.download)
        t1.start()
        t2.start()
        t1.join()
        t2.join()


class PeerManager:
    def __init__(self, file_manager: FileManager) -> None:
        self.peers: list[Peer] = []
        self.file_manager: FileManager = file_manager
        self.uploaded: int = 0  # [bytes]

    def update_peers(self, peers: list[Peer]):
        # TODO: change logic
        self.peers = [peers[0]]

    def download(self, max_peers: int):
        for p in self.peers[:max_peers]:
            p.start()
        for p in self.peers[:max_peers]:
            p.join()
