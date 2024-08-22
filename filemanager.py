import hashlib
import os
import math
import sys
import logging

logger = logging.getLogger(__name__)


class FileManager:
    def __init__(self, filename, directory, length, piece_len, hashes) -> None:
        self.filename: str = filename
        self.base_directory: str = directory
        self.pieces_directory: str = os.path.join(
            self.base_directory, f'{self.filename}.pieces')
        self.filepath: str = os.path.join(self.base_directory, self.filename)
        self.length: int = length  # [bytes]
        self.piece_len: int = piece_len  # [bytes]
        self.last_piece_len: int = length % piece_len  # [bytes]
        self.num_pieces: int = len(hashes)
        self.hashes: list[bytes] = hashes

        self.block_length: int = 2**14
        self.incomplete_pieces: dict[int, dict] = dict()
        self.downloaded_pieces: set[int] = set()
        self._downloaded: int = 0  # [bytes]

        logger.info(f'filepath:{self.filepath}')
        logger.info(f'file size:{self.length}')
        logger.info(f'pieces_directory:{self.pieces_directory}')
        logger.info(f'num pieces:{self.num_pieces}')
        logger.info(f'piece size:{self.piece_len}')
        logger.info(f'block size:{self.block_length}')

        if os.path.isdir(self.pieces_directory):
            logger.info(f'scan downloaded pieces')
            self.scan_downloaded_pieces()
        else:
            os.makedirs(self.pieces_directory)

    @property
    def left(self) -> int:
        ''' remaining bytes to be downloaded '''
        return max(self.length - self._downloaded, 0)

    @property
    def downloaded(self) -> int:
        ''' downloaded bytes '''
        return max(self._downloaded, self.length)

    @property
    def bitfield(self) -> str:
        ''' calculate bitfield of pieces '''

        bitfield = ['0']*self.num_pieces
        for piece_index in self.downloaded_pieces:
            bitfield[piece_index] = '1'
        return ''.join(bitfield)

    def saved_pieces(self, piece_indexes=None):
        ''' load downloaded pieces '''

        if piece_indexes is None:
            files = os.listdir(self.pieces_directory)
        else:
            files = [f'{p}.piece' for p in piece_indexes]

        for file in files:
            filepath = os.path.join(self.pieces_directory, file)
            if not os.path.isfile(filepath):
                continue

            with open(filepath, 'rb') as f:
                piece = f.read()

            piece_index = int(file.split('.')[0])
            if self.is_valid_piece(piece_index, piece):
                yield piece_index, piece
            else:
                logger.warning(f'\'{piece_index}\' piece corrupted')
                os.remove(filepath)

    def scan_downloaded_pieces(self):
        ''' update filemanager with downloaded pieces '''

        for piece_index, piece in self.saved_pieces():
            self.downloaded_pieces.add(piece_index)
            self._downloaded += len(piece)

        logger.info(f'downloaded pieces:{len(self.downloaded_pieces)}')
        logger.info(f'downloaded bytes:{self._downloaded}')

    def piece_length(self, piece_index):
        ''' calculate length of a piece '''

        if (piece_index == self.num_pieces-1):
            return self.last_piece_len
        return self.piece_len

    def is_valid_piece(self, piece_index: int, piece: bytes):
        ''' verify piece hash '''

        assert piece_index < self.num_pieces
        return hashlib.sha1(piece).digest() == self.hashes[piece_index]

    def num_blocks_in_piece(self, piece_index: int):
        ''' calculate number of blocks in a piece '''

        return math.ceil(self.piece_length(piece_index) / self.block_length)

    def add_block(self, piece_index: int, begin: int, block: bytes):
        ''' add block to piece '''

        assert piece_index < self.num_pieces
        assert begin % self.block_length == 0

        if not piece_index in self.incomplete_pieces:
            num_blocks = self.num_blocks_in_piece(piece_index)
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

        if self.incomplete_pieces[piece_index]['remaining_blocks'] == 0:
            piece = b''.join(self.incomplete_pieces[piece_index]['blocks'])
            if self.is_valid_piece(piece_index, piece):
                self.downloaded_pieces.add(piece_index)
                self.save_piece(piece_index, piece)
                if len(self.downloaded_pieces) == self.num_pieces:
                    logger.info(f'download complete')
                    self.finalize_download()
                    sys.exit(0)
            else:
                logger.warning(f'piece \'{piece_index}\' is not valid')
                # TODO: sum all blocks len
                self._downloaded -= self.piece_length(piece_index)
            del self.incomplete_pieces[piece_index]

    def save_piece(self, piece_index: int, piece: bytes):
        ''' save piece to disk '''

        path = os.path.join(
            self.pieces_directory, f"{piece_index}.piece")
        with open(path, 'wb') as f:
            f.write(piece)

    def finalize_download(self):
        with open(self.filepath, 'wb') as f:
            size = 0
            for piece_index, piece in self.saved_pieces(piece_indexes=range(self.num_pieces)):
                f.write(piece)
                size += len(piece)
            assert size == self.length
        logger.info(f'file saved:{self.filepath}')

    def load_block(self, piece_index: int, begin: int, length: int) -> bytes:
        ''' return the specified block '''

        pieces = list(self.saved_pieces(piece_indexes=[piece_index]))
        assert len(pieces) == 1

        _, piece = pieces[0]
        return piece[begin:begin+length]
