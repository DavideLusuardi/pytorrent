import argparse
import bencodepy
import hashlib
import time
import sys
import logging
import threading

from tracker import Tracker, TrackerManager
from peer import PeerManager
from filemanager import FileManager

logger = logging.getLogger(__name__)


class Torrent:
    def __init__(self, torrent_file: str, download_dir: str) -> None:
        self.torrent_file: str = torrent_file
        self.download_dir: str = download_dir
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

        self._stop_event = threading.Event()

        self.read_torrent_file()

    def read_torrent_file(self):
        with open(self.torrent_file, 'rb') as f:
            self.metainfo = bencodepy.decode(f.read())
            # logger.debug(self.metainfo)

        self.info_hash = hashlib.sha1(
            bencodepy.encode(self.metainfo[b'info'])).digest()
        logger.debug(f'info hash:{self.info_hash}')

        pieces = self.metainfo[b'info'][b'pieces']
        assert len(pieces) % 20 == 0, 'malformed pieces field'
        num_pieces = len(pieces)//20
        self.hashes = []
        for i in range(num_pieces):
            self.hashes.append(pieces[i*20:(i+1)*20])
        # logger.debug(self.hashes)

        self.file_manager = FileManager(self.metainfo[b'info'][b'name'].decode(), self.download_dir, self.metainfo[b'info'][b'length'],
                                        self.metainfo[b'info'][b'piece length'], self.hashes, lambda: self._stop_event.set())
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
        if len(self.file_manager.downloaded_pieces) == self.file_manager.num_pieces:
            logger.info('file already downloaded')
            return

        self.tracker_manager.query_trackers()
        time.sleep(1)
        self.peer_manager.download(max_active_peers=50)

        try:
            self._stop_event.wait()
        except KeyboardInterrupt:
            pass
        finally:
            self.tracker_manager.stop()
            self.peer_manager.stop()

    def __str__(self):
        return '\n'.join(
            f"peer_id: {self.peer_id}",
            f"torrent_file: {self.torrent_file}",
            f"tracker_url: {self.tracker_url}"
        )


def main():
    parser = argparse.ArgumentParser(
        prog='pytorrent',
        description='Download files from the BitTorrent network.'
    )
    parser.add_argument('filename', help='torrent file')
    args = parser.parse_args()

    logging.basicConfig(filename='torrent.log', level=logging.DEBUG)

    root = logging.getLogger()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # handler.setFormatter(formatter)
    root.addHandler(handler)

    torrent = Torrent(args.filename, 'downloads')
    torrent.download()


if __name__ == '__main__':
    # test()
    main()
