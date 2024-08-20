import bencodepy
import requests
import struct
import socket
import threading
import pprint
from peer import Peer, PeerManager
from filemanager import FileManager


class Tracker(threading.Thread):
    def __init__(self, tracker_url, peer_manager, file_manager, info_hash, peer_id) -> None:
        self.tracker_url = tracker_url
        self.peer_manager: PeerManager = peer_manager
        self.file_manager: FileManager = file_manager
        self.info_hash = info_hash
        self.peer_id = peer_id
        self.port = 6881  # TODO: select port
        self.trackerid = None
        self.peers: list[Peer] = []

    def scrape_tracker(self):
        params = {
            'info_hash': self.info_hash,
        }
        response = requests.get(
            url='https://torrent.ubuntu.com/scrape', params=params)  # TODO: fix url

        pprint.pprint(bencodepy.decode(response.content))

    def query(self):
        ''' first request to the tracker '''

        params = {
            'info_hash': self.info_hash,
            'peer_id': self.peer_id,
            'port': self.port,
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
            self.peers.append(Peer(ip, port, self.peer_manager,
                              self.file_manager, self.info_hash, self.peer_id))

        return self.peers

    def update(self):
        ''' regular update '''
        # TODO: implement
        pass

    def run(self):
        ''' run the thread '''

        self.query()
        self.update()


class TrackerManager:
    def __init__(self, trackers: list[Tracker], peer_manager: PeerManager) -> None:
        self.trackers = trackers
        self.peer_manager = peer_manager

    def query_trackers(self):
        peers = []
        for tracker in self.trackers:
            peers += tracker.query()

        self.peer_manager.update_peers(peers)
