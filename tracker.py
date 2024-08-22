import bencodepy
import requests
import struct
import socket
import threading
import time
import logging

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

        logger.info(self.tracker_url)

    def scrape_tracker(self):
        params = {
            'info_hash': self.info_hash,
        }
        response = requests.get(
            url='https://torrent.ubuntu.com/scrape', params=params)  # TODO: fix url

        # logger.debug(bencodepy.decode(response.content))

    def send_request(self, params):
        if self.trackerid is not None:
            params['trackerid'] = self.trackerid

        logger.debug(f'{self.tracker_url}:request:{params}')
        response = requests.get(url=self.tracker_url, params=params)
        assert response.ok, 'tracker response error'
        response = bencodepy.decode(response.content)
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
            offset = 0
            for _ in range(len(response[b'peers'])//6):
                ip = struct.unpack_from("!i", response[b'peers'], offset)[0]
                ip = socket.inet_ntoa(struct.pack("!i", ip))
                offset += 4
                port = struct.unpack_from("!H", response[b'peers'], offset)[0]
                offset += 2
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

        while not self.is_stopped():
            time.sleep(self.interval)

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

    def stop(self):
        logger.debug(f'{self.tracker_url}:stop received')
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    def run(self):
        ''' run the thread '''

        self.query()
        self.update()


class TrackerManager:
    def __init__(self, trackers: list[Tracker], peer_manager: PeerManager) -> None:
        self.trackers: list[Tracker] = trackers
        self.peer_manager: PeerManager = peer_manager

    def query_trackers(self) -> None:
        # peers = []
        # for tracker in self.trackers:
        #     peers += tracker.query()

        # self.peer_manager.update_peers(peers)

        # TODO: fix
        self.trackers[0].start()
