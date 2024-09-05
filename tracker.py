import bencodepy
import requests
import struct
import socket
import threading
import logging
from urllib.parse import urlparse, ParseResult
import random
import time
from typing import Dict, Any

import utils
from peer import Peer, PeerManager
from filemanager import FileManager

logger = logging.getLogger(__name__)


class Tracker(threading.Thread):
    port = 6881  # TODO: select port

    def __init__(self, tracker_url, peer_manager, file_manager, info_hash, peer_id) -> None:
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()

        self.tracker_url: str = tracker_url
        self.peer_manager: PeerManager = peer_manager
        self.file_manager: FileManager = file_manager
        self.info_hash: bytes = info_hash
        self.peer_id: bytes = peer_id
        self.trackerid: bytes = None
        self.interval: int = 60  # default interval [s]
        self.complete: int = None
        self.incomplete: int = None
        self.peers: list[Peer] = []

        self.url_parsed: ParseResult = urlparse(self.tracker_url)
        assert self.url_parsed.scheme in [
            'http', 'https', 'udp'], f'\'{self.url_parsed.scheme}\' protocol not supported'
        self.address = (self.url_parsed.hostname, self.url_parsed.port)
        if self.url_parsed.scheme == 'udp':
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.connection_id_timeout = 0

        logger.info(self.tracker_url)

    # def scrape_tracker(self):
    #     params = {
    #         'info_hash': self.info_hash,
    #     }
    #     response = requests.get(
    #         url='https://torrent.ubuntu.com/scrape', params=params)  # TODO: fix url

    #     # logger.debug(bencodepy.decode(response.content))

    # def udp_recv(self):
    #     data, address = self.socket.recvfrom(1024)
    #     print(address)  # TODO: assert address == tracker
    #     assert len(data) >= 16  # Check whether the packet is at least 16 bytes

    def connect_udp(self) -> None:
        protocol_id = (0x41727101980).to_bytes(8, 'big')
        action = (0).to_bytes(4, 'big')  # connect action
        transaction_id = random.randint(0, 2**32-1).to_bytes(4, 'big')
        payload = protocol_id + action + transaction_id

        self.socket.sendto(payload, self.address)
        data, address = self.socket.recvfrom(1024)
        assert len(data) >= 16

        r_action = data[:4]
        r_transaction_id = data[4:8]
        self.connection_id = data[8:16]
        self.connection_id_timeout = time.time() + 60
        assert action == r_action
        assert transaction_id == r_transaction_id

    def announce_udp(self, params: Dict[str, Any]) -> Dict[bytes, Any]:
        assert self.connection_id_timeout > time.time()

        action = (1).to_bytes(4, 'big')  # announce action
        transaction_id = random.randint(0, 2**32-1).to_bytes(4, 'big')
        event = (params['event'].encode('utf-8')
                 if 'event' in params else (0).to_bytes(4, 'big'))
        ip_address = (socket.inet_aton(params['ip'])
                      if 'ip' in params else (0).to_bytes(4, 'big'))
        key = (params['key'].to_bytes(4, 'big')
               if 'key' in params else self.peer_id[:4])  # TODO: generate valid key
        numwant = (params['numwant']
                   if 'numwant' in params else -1).to_bytes(4, 'big')
        port = params['port'].to_bytes(4, 'big')

        payload = self.connection_id + action + transaction_id \
            + params['info_hash'] + params['peer_id'] + params['downloaded'].to_bytes(8, 'big') \
            + params['left'].to_bytes(8, 'big') + params['uploaded'].to_bytes(8, 'big') \
            + event + ip_address + key + numwant + port

        self.socket.sendto(payload, self.address)
        data, address = self.socket.recvfrom(1024)
        assert len(data) >= 20

        r_action = data[:4]
        assert r_action == action

        r_transaction_id = data[4:8]
        assert r_transaction_id == transaction_id

        trail_bytes = (len(data) - 20) % 6  # invalid bytes in trail

        response = {
            b'interval': int.from_bytes(data[8:12], 'big'),
            b'leechers': int.from_bytes(data[12:16], 'big'),
            b'seeders': int.from_bytes(data[16:20], 'big'),
            b'peers': data[20:len(data) - trail_bytes]
        }
        return response

    def send_http(self, params: Dict[str, Any]) -> Dict[bytes, Any]:
        response = requests.get(url=self.tracker_url, params=params)
        assert response.ok, 'tracker response error'
        return bencodepy.decode(response.content)

    def send_udp(self, params: Dict[str, Any]) -> Dict[bytes, Any]:
        if self.connection_id_timeout <= time.time():
            self.connect_udp()
        return self.announce_udp(params)

    def send(self, params: Dict[str, Any]) -> bytes:
        if self.url_parsed.scheme == 'udp':
            response = self.send_udp(params)
        else:
            response = self.send_http(params)
        return response

    def send_request(self, params: Dict[str, Any]):
        if self.trackerid is not None:
            params['trackerid'] = self.trackerid

        logger.debug(f'{self.tracker_url}:request:{params}')
        response = self.send(params)
        logger.debug(f'{self.tracker_url}:response:{response}')

        if b'trackerid' in response:
            self.trackerid = response[b'trackerid']
            logger.debug(f'{self.tracker_url}:trackerid:{self.trackerid}')

        # assert (b'interval' in response) and (b'complete' in response) and (
        #     b'incomplete' in response) and (b'peers' in response), 'malformed tracker response'

        if b'interval' in response:
            self.interval = response[b'interval']
            logger.debug(f'{self.tracker_url}:interval:{self.interval}')

        if b'complete' in response:
            self.complete = response[b'complete']
            logger.debug(f'{self.tracker_url}:complete:{self.complete}')

        if b'incomplete' in response:
            self.incomplete = response[b'incomplete']
            logger.debug(f'{self.tracker_url}:incomplete:{self.incomplete}')

        self.peers = []
        if isinstance(response[b'peers'], dict):
            # dictionary model
            for p in response[b'peers']:
                peer_id = p[b'peer_id']
                ip = socket.inet_ntoa(struct.pack("!i", p[b'ip']))
                port = p[b'port']
                self.peers.append(Peer(ip, port, peer_id, self.peer_manager,
                                       self.file_manager, self.info_hash, self.peer_id))
        else:
            # binary model
            assert len(
                response[b'peers']) % 6 == 0, 'malformed \'peers\' field of tracker response'
            for ip, port in utils.unpack_peers(response[b'peers']):
                self.peers.append(Peer(ip, port, None, self.peer_manager,
                                       self.file_manager, self.info_hash, self.peer_id))

        for p in self.peers:
            logger.info(f'{self.tracker_url}:peer:{p}')

        return self.peers

    def query(self):
        ''' first request to the tracker '''

        params = {
            'info_hash': self.info_hash,
            'peer_id': self.peer_id,
            'port': Tracker.port,
            'uploaded': self.peer_manager.uploaded,
            'downloaded': self.file_manager.downloaded,
            'left': self.file_manager.left,
            'compact': 0,
            # 'no_peer_id':
            'event': 'started',
            # 'ip':
            'numwant': 10,
            # 'key':
        }

        logger.debug(f'{self.tracker_url}:first request')
        peers = self.send_request(params)
        self.peer_manager.update_peers(peers)

    def update(self):
        ''' regular update '''

        self._stop_event.wait(timeout=self.interval)
        while not self.is_stopped():
            params = {
                'info_hash': self.info_hash,
                'peer_id': self.peer_id,
                'port': Tracker.port,
                'uploaded': self.peer_manager.uploaded,
                'downloaded': self.file_manager.downloaded,
                'left': self.file_manager.left,
                'compact': 0,
                # 'no_peer_id':
                # 'event': 'started',
                # 'ip':
                # 'numwant': 10,
                # 'key':
            }

            logger.debug(f'{self.tracker_url}:update')
            peers = self.send_request(params)
            self.peer_manager.update_peers(peers)

            self._stop_event.wait(timeout=self.interval)

    def stop(self):
        logger.debug(f'{self.tracker_url}:stop received')
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    def run(self):
        ''' run the thread '''

        self._stop_event.clear()
        logger.info(f'{self.tracker_url}:querying tracker')
        self.query()
        self.update()


class TrackerManager:
    def __init__(self, trackers: list[Tracker], peer_manager: PeerManager) -> None:
        self.trackers: list[Tracker] = trackers
        self.peer_manager: PeerManager = peer_manager

    def query_trackers(self) -> None:
        # TODO: fix
        # self.trackers = [self.trackers[0]]
        # for t in self.trackers:
        #     if not t.tracker_url.split(':')[0] in ['http', 'https']:
        #         t.start()
        #         break

        # self.trackers = [self.trackers[4]]
        for tracker in self.trackers:
            tracker.start()

    def stop(self):
        logger.info('stop all trackers')

        for tracker in self.trackers:
            tracker.stop()
        for tracker in self.trackers:
            # tracker.join(timeout=1)
            tracker.join()

        logger.info('all trackers closed')
