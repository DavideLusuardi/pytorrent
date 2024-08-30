import socket
import threading
import bencodepy
import math
import random
import logging
from bitstring import BitArray
import time
from typing import Tuple

from queueLL import Queue
import utils
from filemanager import FileManager

logger = logging.getLogger(__name__)


class Peer(threading.Thread):
    BINDING_PORT = 6883  # TODO
    MESSAGES = {
        0: 'choke',
        1: 'unchoke',
        2: 'interested',
        3: 'not interested',
        4: 'have',
        5: 'bitfield',
        6: 'request',
        7: 'piece',
        8: 'cancel',
        9: 'port',
        20: 'extension protocol'
    }

    def __init__(self, ip, port, peer_id, peer_manager, file_manager, info_hash, client_id) -> None:
        threading.Thread.__init__(self)

        self.ip: str = ip
        self.port: int = port
        self.peer_id: bytes = peer_id
        self.id: str = f"{ip}:{port}"
        self.peer_manager: PeerManager = peer_manager
        self.file_manager: FileManager = file_manager
        self.info_hash: bytes = info_hash
        self.client_id: bytes = client_id

        self.init_vars()

    def init_vars(self):
        self.am_choking = True
        self.am_interested = False
        self.peer_choking = True
        self.peer_interested = False

        self.socket: socket.socket = None
        self.available_pieces: list[int] = []
        self.idx_next_piece: int = 0
        self.queue: Queue[int, int] = Queue()
        self.queue_len: int = 10

        self.start_time: int = 0
        self.downloaded_blocks: list[int] = []
        self.request_pieces: int = 0

        self._stop_event = threading.Event()

    @property
    def speed(self) -> int:
        ''' return the speed [bytes/s] '''

        time_interval = 10
        i = len(self.downloaded_blocks) - 1
        download = 0
        while i >= 0:
            piece_index, downloaded_bytes, t = self.downloaded_blocks[i]
            if time.time() - t < time_interval:
                download += downloaded_bytes
            else:
                break
            i -= 1

        return download/time_interval

    @property
    def avg_speed(self) -> int:
        ''' return the average speed [bytes/s] '''

        return len(self.downloaded_blocks)*self.file_manager.block_length / (time.time()-self.start_time)

    def update_stats(self, piece_index: int, downloaded_bytes: int):
        self.downloaded_blocks.append(
            (piece_index, downloaded_bytes, time.time()))

    def receive_data(self, data_len: int) -> bytes:
        data = self.socket.recv(data_len)
        while len(data) < data_len:
            data += self.socket.recv(data_len - len(data))
        assert len(data) == data_len
        return data

    def handshake_peer(self) -> None:
        logger.debug(f'{self.id}:handshaking')

        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr).to_bytes(1, 'big')
        # reserved = b'\x00' * 8
        reserved = b'\x00' * 5 + b'\x10' + b'\x00' * 2  # support for Extension Protocol
        logger.debug(f'{self.id}:enable support for Extension Protocol')

        payload = pstrlen + pstr + reserved + self.info_hash + self.client_id

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(1)
        # self.socket.bind(('0.0.0.0', Peer.BINDING_PORT))  # TODO
        # self.socket.listen()
        self.socket.settimeout(4)
        self.socket.connect((self.ip, self.port))
        logger.debug(f'{self.id}:connected to peer')
        self.socket.settimeout(None)
        self.socket.sendall(payload)

        p_pstrlen = int.from_bytes(self.receive_data(1), 'big')
        assert p_pstrlen > 0
        data = self.receive_data(p_pstrlen+48)
        # logger.debug(f'{self.id}:handshake recv:{data}')

        p_pstr = data[:p_pstrlen]
        p_reserved = data[p_pstrlen: p_pstrlen+8]
        p_info_hash = data[p_pstrlen+8: p_pstrlen+8+20]
        p_peer_id = data[p_pstrlen+8+20: p_pstrlen+8+20+20]
        assert len(p_peer_id) == 20
        if not self.peer_id is None:
            assert self.peer_id == p_peer_id
        else:
            self.peer_id = p_peer_id

        logger.debug(f'{self.id}:handshake recv:pstrlen:{p_pstrlen}')
        logger.debug(f'{self.id}:handshake recv:pstr:{p_pstr}')
        logger.debug(f'{self.id}:handshake recv:reserved:{p_reserved}')
        logger.debug(f'{self.id}:handshake recv:info_hash:{p_info_hash}')
        logger.debug(f'{self.id}:handshake recv:peer_id:{p_peer_id}')

    def send_keepalive(self) -> None:
        ''' keep-alive msg '''

        logger.debug(f'{self.id}:send:keep-alive')
        len_prefix = (0).to_bytes(4, 'big')
        self.socket.sendall(len_prefix)

    def send_choke(self) -> None:
        ''' choke msg '''

        logger.debug(f'{self.id}:send:choke')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (0).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

        self.am_choking = True

    def send_unchoke(self) -> None:
        ''' unchoke msg '''

        logger.debug(f'{self.id}:send:unchoke')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (1).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

        self.am_choking = False

    def send_interested(self) -> None:
        ''' interested msg '''

        logger.debug(f'{self.id}:send:interested')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (2).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

        self.am_interested = True

    def send_not_interested(self) -> None:
        ''' not interested msg '''

        logger.debug(f'{self.id}:send:not interested')
        len_prefix = (1).to_bytes(4, 'big')
        message_id = (3).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id)

        self.am_interested = False

    def send_have(self, piece_index: int) -> None:
        ''' have msg '''

        logger.debug(f'{self.id}:send:have:{piece_index}')
        len_prefix = (5).to_bytes(4, 'big')
        message_id = (4).to_bytes(1, 'big')
        payload = (piece_index).to_bytes(4, 'big')
        self.socket.sendall(len_prefix + message_id + payload)

    def send_bitfield(self) -> None:
        ''' bitfield msg '''

        logger.debug(f'{self.id}:send:bitfield')
        bitfield = BitArray('0b'+self.file_manager.bitfield).tobytes()
        len_prefix = (1+len(bitfield)).to_bytes(4, 'big')
        message_id = (5).to_bytes(1, 'big')
        self.socket.sendall(len_prefix + message_id + bitfield)

    def send_request(self, piece_index: int, begin: int, length: int) -> None:
        ''' request msg '''

        logger.debug(f'{self.id}:send:request:{piece_index}:{begin}')
        len_prefix = (13).to_bytes(4, 'big')
        message_id = (6).to_bytes(1, 'big')
        payload = (piece_index).to_bytes(4, 'big') + \
            (begin).to_bytes(4, 'big') + (length).to_bytes(4, 'big')
        self.socket.sendall(len_prefix + message_id + payload)

        self.request_pieces += 1

    def send_piece(self, piece_index: int, begin: int, block: bytes) -> None:
        ''' piece msg '''

        logger.debug(f'{self.id}:send:piece:{piece_index}')
        len_prefix = (9+len(block)).to_bytes(4, 'big')
        message_id = (7).to_bytes(1, 'big')
        index = piece_index.to_bytes(4, 'big')
        begin = begin.to_bytes(4, 'big')
        payload = index + begin + block
        self.socket.sendall(len_prefix + message_id + payload)

    def send_cancel(self, piece_index: int, begin: int, length: int) -> None:
        ''' cancel msg '''

        logger.debug(f'{self.id}:send:cancel:{piece_index}')
        len_prefix = (13).to_bytes(4, 'big')
        message_id = (8).to_bytes(1, 'big')
        payload = (piece_index).to_bytes(4, 'big') + \
            (begin).to_bytes(4, 'big') + (length).to_bytes(4, 'big')
        self.socket.sendall(len_prefix + message_id + payload)

    def send_port(self, port: int) -> None:
        ''' port msg '''

        logger.debug(f'{self.id}:send:port:{port}')
        len_prefix = (3).to_bytes(4, 'big')
        message_id = (9).to_bytes(1, 'big')
        payload = port.to_bytes(2, 'big')
        self.socket.sendall(len_prefix + message_id + payload)

    def send_extended(self, extended_message_id: int, data: dict) -> None:
        ''' Extension Protocol msg '''

        assert extended_message_id >= 0
        message_id = (20).to_bytes(1, 'big')
        payload = extended_message_id.to_bytes(
            1, 'big') + bencodepy.encode(data)
        len_prefix = (1+len(payload)).to_bytes(4, 'big')
        self.socket.sendall(len_prefix + message_id + payload)

    def send_extension_protocol_handshake(self) -> None:
        ''' Extension Protocol handshake msg '''

        logger.debug(f'{self.id}:send:Extension Protocol handshake')
        extended_message_id = 0  # handshake extended message ID
        data = {
            'm': {
                'ut_pex': 1  # TODO: fix hardcoded id
            },
            'v': 'pytorrent 0.1'
        }
        self.send_extended(extended_message_id, data)

    def send_pex(self) -> None:
        ''' Peer Exchange msg '''

        logger.debug(f'{self.id}:send:PEX')
        extended_message_id = 1  # TODO: fix hardcoded id
        data = {
            # TODO
        }
        self.send_extended(extended_message_id, data)

    def send_all_have_pieces(self) -> None:
        ''' send a have msg for each saved piece '''

        for piece_index in self.file_manager.downloaded_pieces:
            self.send_have(piece_index)

    def receive_msg(self) -> None:
        ''' receive msg loop '''

        while not self.is_stopped():
            try:
                data = self.receive_data(4)
            except:
                if not self.is_stopped():
                    logger.exception(f'{self.id}:error occured')
                    self.stop_and_notify()
                break

            len_prefix = int.from_bytes(data, 'big')
            logger.debug(f'{self.id}:recv:len_prefix:{len_prefix}')
            if len_prefix == 0:
                # keep-alive msg
                logger.debug(f'{self.id}:recv:keep-alive')
                continue

            try:
                data = self.receive_data(len_prefix)
            except:
                if not self.is_stopped():
                    logger.exception(f'{self.id}:error occured')
                    self.stop_and_notify()
                break

            message_id = int.from_bytes(data[:1], 'big')
            logger.debug(f'{self.id}:recv:message_id:{message_id}')
            assert message_id in Peer.MESSAGES, 'unknown message received'
            if message_id in range(4):
                logger.debug(f'{self.id}:recv:{Peer.MESSAGES[message_id]}')

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
                self.available_pieces.append(piece_index)
                logger.debug(
                    f'{self.id}:recv:{Peer.MESSAGES[message_id]}:{piece_index}')

            elif message_id == 5:
                # bitfield msg
                bitfield = data[1:]
                num_bytes = math.ceil(self.file_manager.num_pieces/8)
                assert num_bytes == len(bitfield)

                binary_bitfield = BitArray(hex=bitfield.hex()).bin
                logger.debug(
                    f'{self.id}:recv:{Peer.MESSAGES[message_id]}:{binary_bitfield}')

                for piece_index, b in enumerate(binary_bitfield):
                    if b == '1':
                        self.available_pieces.append(piece_index)
                logger.debug(
                    f'{self.id}:recv:available pieces:{self.available_pieces}')
                random.shuffle(self.available_pieces)  # TODO

            elif message_id == 6:
                # request msg
                piece_index = int.from_bytes(data[1:5], 'big')
                begin = int.from_bytes(data[5:9], 'big')
                length = int.from_bytes(data[9:13], 'big')

                logger.debug(
                    f'{self.id}:recv:{Peer.MESSAGES[message_id]}:{piece_index}:{begin}:{length}')

                if piece_index in self.file_manager.downloaded_pieces:
                    block = self.file_manager.load_block(
                        piece_index, begin, length)
                    self.send_piece(piece_index, begin, block)
                else:
                    logger.warning(
                        f'{self.id}:piece \'{piece_index}\' not downloaded')

            elif message_id == 7:
                # piece msg
                piece_index = int.from_bytes(data[1:5], 'big')
                begin = int.from_bytes(data[5:9], 'big')
                block = data[9:]
                logger.debug(
                    f'{self.id}:recv:{Peer.MESSAGES[message_id]}:{piece_index}:{begin}:{len(block)}')

                self.file_manager.add_block(piece_index, begin, block)
                self.update_stats(piece_index, len(block))

            elif message_id == 8:
                # cancel msg
                # TODO
                logger.debug(
                    f'{self.id}:recv:{Peer.MESSAGES[message_id]}')

            elif message_id == 9:
                # port msg
                # TODO
                logger.debug(
                    f'{self.id}:recv:{Peer.MESSAGES[message_id]}')

            elif message_id == 20:
                # extension protocol msg

                extended_message_id = int.from_bytes(data[1:2], 'big')
                if extended_message_id == 0:
                    # handshake
                    handshake_data = bencodepy.decode(data[2:])
                    logger.debug(
                        f'{self.id}:recv:{Peer.MESSAGES[message_id]}:handshake:{handshake_data}')
                else:
                    extended_data = bencodepy.decode(data[2:])
                    logger.debug(
                        f'{self.id}:recv:{Peer.MESSAGES[message_id]}:{extended_data}')
                    # logger.info(
                    #     f'{self.id}:PEX:{utils.unpack_peers(extended_data['added'])}')
                    peers = []
                    for ip, port in utils.unpack_peers(extended_data[b'added']):
                        peers.append(Peer(ip, port, None, self.peer_manager,
                                          self.file_manager, self.info_hash, self.client_id))
                    self.peer_manager.update_peers(peers)
                    # TODO: manage other fields

        logger.debug(f'{self.id}:receive_msg:close')

    def clean_queue(self) -> Tuple[int, int]:
        ''' remove downloaded and timed-out pieces from queue '''

        downloaded_count = 0
        timedout_count = 0
        # 30 s timeout
        while not self.queue.is_empty():
            if self.queue.first()[0] in self.file_manager.downloaded_pieces:
                self.queue.pop()
                downloaded_count += 1
            elif time.time() - self.queue.first()[1] > 30:
                piece_index, _ = self.queue.pop()
                self.available_pieces.append(piece_index)
                timedout_count += 1
            else:
                break

        if downloaded_count > 0:
            logger.debug(
                f"{self.id}:{downloaded_count} downloaded pieces removed from queue")

        if timedout_count > 0:
            logger.debug(
                f"{self.id}:{timedout_count} timed-out pieces removed from queue")

        return downloaded_count, timedout_count

    def next_piece_index(self) -> int | None:
        ''' return the next piece index to request '''

        while len(self.available_pieces) > self.idx_next_piece:
            piece_index = self.available_pieces[self.idx_next_piece]
            self.idx_next_piece += 1
            if not piece_index in self.file_manager.downloaded_pieces:
                return piece_index
        return None

    def download_piece(self, piece_index: int) -> None:
        ''' request all blocks of a piece '''

        self.queue.add((piece_index, time.time()))
        piece_length = self.file_manager.piece_length(piece_index)
        block_index = 0
        begin = 0
        while begin < piece_length and not self.is_stopped():
            block_length = min(
                self.file_manager.block_length, piece_length - begin)
            self.send_request(piece_index, begin, block_length)
            block_index += 1
            begin += block_length

            self._stop_event.wait(timeout=0.1)

    def download(self) -> None:
        ''' download loop '''

        self.start_time = time.time()
        waiting_count = 0
        while not self.is_stopped():
            piece_index = self.next_piece_index()
            if piece_index is None:
                self._stop_event.wait(timeout=1)
                continue

            # TODO: manage queue length
            while self.queue.len() >= self.queue_len and not self.is_stopped():
                downloaded, timedout = self.clean_queue()
                if downloaded + timedout == 0:
                    waiting_count += 1
                    logger.debug(
                        f'{self.id}:download:waiting for requested pieces')
                    self._stop_event.wait(timeout=2)
                elif timedout > 0:
                    self.queue_len = max(self.queue_len - 1, 2)
                else:
                    self.queue_len += int(1.5 * self.queue_len)
                logger.debug(f'{self.id}:queue len:{self.queue_len}')
                # self.request_pieces = 0

            if self.is_stopped():
                break

            logger.debug(f"{self.id}:speed {self.speed}")
            logger.debug(f"{self.id}:avg speed {self.avg_speed}")
            logger.debug(f"{self.id}:waiting_count {waiting_count}")
            logger.info(f"{self.id}:download {piece_index}")
            try:
                self.download_piece(piece_index)
            except:
                if not self.is_stopped():
                    logger.exception(f'{self.id}:error occured')
                    self.stop_and_notify()
                break

        logger.debug(f'{self.id}:download:close')

    def stop(self) -> None:
        if not self.is_stopped():
            logger.debug(f'{self.id}:stop received')
            self._stop_event.set()
            try:
                self.socket.shutdown(socket.SHUT_RD)
            except:
                pass

            try:
                self.socket.shutdown(socket.SHUT_WR)
            except:
                pass

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def stop_and_notify(self) -> None:
        if not self.is_stopped():
            self.stop()
            self.peer_manager.peer_stopped(self.peer_id)

    def run(self) -> None:
        self.init_vars()

        try:
            self.handshake_peer()
            self.send_extension_protocol_handshake()
            self.send_bitfield()
            self.send_unchoke()
            self.send_interested()
            # self.send_all_have_pieces()
        except:
            if not self.is_stopped():
                logger.exception(f'{self.id}:error occured')
                self.stop_and_notify()
            return

        t1 = threading.Thread(target=self.receive_msg)
        t2 = threading.Thread(target=self.download)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def __str__(self) -> str:
        return f"Peer({self.ip}:{self.port})"


class PeerManager:
    def __init__(self, file_manager: FileManager) -> None:
        self.file_manager: FileManager = file_manager

        self.peers: dict[str, Peer] = {}
        self.active_peers: set[Peer] = set()
        self.uploaded: int = 0  # [bytes]
        self.downloading = False
        self.max_active_peers: int = 50

    def update_peers(self, peers: list[Peer]) -> None:
        for p in peers:
            if p.id not in self.peers:
                self.peers[p.id] = p
                logger.info(f'new peer:{p.id}')
                # logger.info(f'active_peers:{self.active_peers}')
                # logger.info(f'self.downloading:{self.downloading}')
                if self.downloading:
                    self.activate_peer_if_needed(p)

    def activate_peer_if_needed(self, peer: Peer) -> bool:
        assert self.downloading

        if len(self.active_peers) < self.max_active_peers:
            logger.info(f"activate peer {peer.id}")
            # TODO: add and start in mutex
            self.active_peers.add(peer.id)
            peer.start()
            return True
        return False

    def download(self, max_active_peers: int = 50) -> None:
        assert not self.downloading
        self.max_active_peers = max_active_peers
        self.downloading = True

        for p in self.peers.values():
            if not self.activate_peer_if_needed(p):
                break

    def peer_stopped(self, peer_id: str):
        if peer_id in self.active_peers:
            # self.peers[peer_id].join()  # TODO: join thread
            self.active_peers.remove(peer_id)

    def stop(self) -> None:
        logger.info('stop all peers')

        for peer_id in self.active_peers:
            p = self.peers[peer_id]
            p.stop()

        for peer_id in self.active_peers:
            p = self.peers[peer_id]
            # p.join(timeout=1)
            p.join()

        self.active_peers = set()
        self.downloading = False

        logger.info('all peers closed')
