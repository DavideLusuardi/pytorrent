import hashlib
import os
import math
import shutil
# from torrent import Torrent
# from tracker import Tracker
# from peer import Peer


class FileManager:
    def __init__(self, filename, directory, length, piece_len, hashes) -> None:
        self.filename = filename
        self.directory = os.path.join(directory, filename)
        self.length = length  # [bytes]
        self.piece_len = piece_len  # [bytes]
        self.last_piece_len = length % piece_len  # [bytes]
        self.num_pieces = len(hashes)
        self.hashes = hashes

        self.block_length = 2**14
        self.incomplete_pieces = {}
        self.downloaded_pieces = set()
        self._downloaded = 0  # [bytes]

        print(self.directory)
        os.makedirs(self.directory)
        # shutil.rmtree(self.directory)

    @property
    def left(self):
        return max(self.length - self._downloaded, 0)

    @property
    def downloaded(self):
        return max(self._downloaded, self.length)

    def piece_length(self, piece_index):
        if (piece_index == self.num_pieces-1):
            return self.last_piece_len
        return self.piece_len

    def is_valid_piece(self, piece_index: int, piece: bytes):
        return hashlib.sha1(piece).digest() == self.hashes[piece_index]

    def num_blocks_in_piece(self, piece_index: int):
        return math.ceil(self.piece_length(piece_index) / self.block_length)

    def add_block(self, piece_index: int, begin: int, block: bytes):
        assert piece_index < self.num_pieces
        assert begin % self.block_length == 0

        if not piece_index in self.incomplete_pieces:
            num_blocks = self.num_blocks_in_piece(piece_index)
            print(f"piece:{piece_index}:num_blocks:{num_blocks}")
            self.incomplete_pieces[piece_index] = {
                'remaining_blocks': num_blocks,
                'blocks': [None] * num_blocks
            }

        block_index = begin // self.block_length
        if not self.incomplete_pieces[piece_index]['blocks'][block_index] is None:
            return

        assert self.incomplete_pieces[piece_index]['remaining_blocks'] > 0
        self.incomplete_pieces[piece_index]['blocks'][block_index] = block
        self.incomplete_pieces[piece_index]['remaining_blocks'] -= 1
        self._downloaded += len(block)

        # piece_len = self.piece_length(piece_index)
        if self.incomplete_pieces[piece_index]['remaining_blocks'] == 0:
            piece = b''.join(self.incomplete_pieces[piece_index]['blocks'])
            if self.is_valid_piece(piece_index, piece):
                self.downloaded_pieces.add(piece_index)
                self.save_piece(piece_index, piece)
            else:
                print(f"error, piece_index {piece_index} is not valid")
                # TODO: sum all blocks len
                self._downloaded -= self.piece_length(piece_index)
            del self.incomplete_pieces[piece_index]

    def save_piece(self, piece_index: int, piece: bytes):
        path = os.path.join(
            self.directory, f"{piece_index}.part")
        with open(path, 'wb') as f:
            f.write(piece)
