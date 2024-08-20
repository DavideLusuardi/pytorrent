import bencodepy
import hashlib
import time
import os
from tracker import Tracker, TrackerManager
from peer import PeerManager
from filemanager import FileManager


class Torrent:
    def __init__(self, torrent_file: str) -> None:
        # TODO: generate meaningful id
        self.peer_id: bytes = hashlib.sha1(
            int(time.time()).to_bytes(4, 'big')).digest()
        self.torrent_file: str = torrent_file
        self.metainfo: dict = None
        # self.trackers: list[Tracker] = []
        self.hashes: list = None
        self.info_hash: bytes = None
        self.tracker_manager: TrackerManager = None
        self.peer_manager: PeerManager = None
        # self.peers: list[Peer] = []
        self.file_manager: FileManager = None

        self.read_torrent_file()

    def read_torrent_file(self):
        with open(self.torrent_file, 'rb') as f:
            self.metainfo = bencodepy.decode(f.read())

        self.info_hash = hashlib.sha1(
            bencodepy.encode(self.metainfo[b'info'])).digest()
        print(self.info_hash)

        pieces = self.metainfo[b'info'][b'pieces']
        assert len(pieces) % 20 == 0, 'malformed pieces field'
        num_pieces = len(pieces)//20
        self.hashes = []
        for i in range(num_pieces):
            self.hashes.append(pieces[i*20:(i+1)*20])
        # print(self.hashes)

        self.file_manager = FileManager(
            self.metainfo[b'info'][b'name'].decode(), 'tmp', self.metainfo[b'info'][b'length'], self.metainfo[b'info'][b'piece length'], self.hashes)
        self.peer_manager = PeerManager(self.file_manager)

        trackers = []
        if b'announce-list' in self.metainfo:
            for tracker_url in self.metainfo[b'announce-list']:
                trackers.append(
                    Tracker(tracker_url[0].decode(), self.peer_manager, self.file_manager, self.info_hash, self.peer_id))
        else:
            tracker_url = self.metainfo[b'announce'].decode()
            trackers.append(
                Tracker(tracker_url, self.peer_manager, self.file_manager, self.info_hash, self.peer_id))
            # print(f"tracker_url: {self.tracker_url}")

        self.tracker_manager = TrackerManager(trackers, self.peer_manager)

    # def query_trackers(self):
    #     self.tracker_manager.query_trackers()

    def download(self):
        self.tracker_manager.query_trackers()
        self.peer_manager.download(max_peers=5)

    # def pause(self):
    #     pass

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
    torrent.download()
    # torrent.query_trackers()
    # print(torrent.peers)
    # torrent.scrape_tracker()
    # torrent.handshake_peer()

    # torrent.receive_msg()
    # torrent.run()


if __name__ == '__main__':
    main()
