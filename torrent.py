import bencodepy
import hashlib
import time
import os
import sys
import logging
from tracker import Tracker, TrackerManager
from peer import PeerManager
from filemanager import FileManager

logger = logging.getLogger(__name__)


class Torrent:
    def __init__(self, torrent_file: str) -> None:
        self.torrent_file: str = torrent_file
        logger.info(f"torrent file:{torrent_file}")

        self.peer_id: bytes = hashlib.sha1(
            int(time.time()).to_bytes(4, 'big')).digest()
        logger.debug(f"peer_id:{self.peer_id}")

        self.metainfo: dict = None
        self.hashes: list[bytes] = None
        self.info_hash: bytes = None
        self.tracker_manager: TrackerManager = None
        self.peer_manager: PeerManager = None
        self.file_manager: FileManager = None

        self.read_torrent_file()

    def read_torrent_file(self):
        with open(self.torrent_file, 'rb') as f:
            self.metainfo = bencodepy.decode(f.read())
            # logger.debug(self.metainfo)

        self.info_hash = hashlib.sha1(
            bencodepy.encode(self.metainfo[b'info'])).digest()
        logger.debug(self.info_hash)

        pieces = self.metainfo[b'info'][b'pieces']
        assert len(pieces) % 20 == 0, 'malformed pieces field'
        num_pieces = len(pieces)//20
        self.hashes = []
        for i in range(num_pieces):
            self.hashes.append(pieces[i*20:(i+1)*20])
        logger.debug(self.hashes)

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

        self.tracker_manager = TrackerManager(trackers, self.peer_manager)

    def download(self):
        logger.info('starting download')

        self.tracker_manager.query_trackers()
        time.sleep(1)
        self.peer_manager.download(max_active_peers=2)

        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            self.peer_manager.stop()

    def __str__(self):
        return '\n'.join(
            f"peer_id: {self.peer_id}",
            f"torrent_file: {self.torrent_file}",
            f"tracker_url: {self.tracker_url}"
        )


def main():
    logging.basicConfig(filename='tmp/torrent.log', level=logging.DEBUG)

    root = logging.getLogger()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # handler.setFormatter(formatter)
    root.addHandler(handler)

    # torrent_file = os.path.join('torrent_files','torrent_file.torrent')
    # torrent_file = os.path.join('torrent_files', 'ubuntu18.torrent')
    torrent_file = os.path.join('torrent_files', 'LibreOffice.torrent')
    # torrent_file = os.path.join('torrent_files', 'gimp.torrent')
    # torrent_file = os.path.join('torrent_files', 'blender.torrent')
    # torrent_file = os.path.join('torrent_files', 'blender_hybrid.torrent')
    torrent = Torrent(torrent_file)
    torrent.download()


def test():
    import math
    from bitstring import BitArray

    b = BitArray('0b00101011')
    bitfield = b.tobytes()

    binary_bitfield = BitArray(hex=bitfield.hex()).bin
    available_pieces = []
    for piece_index, b in enumerate(binary_bitfield):
        if b == '1':
            available_pieces.append(piece_index)
    print("available pieces:")
    print(available_pieces)


if __name__ == '__main__':
    # test()
    main()
