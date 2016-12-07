#!/usr/bin/env python
# _*_ coding=utf-8 _*_

import os
import time
import mmap
import contextlib
import struct
from collections import namedtuple
import zlib
import logging


# TOMBSTONE
TOMBSTONE = "TOMBSTONE"
TOMBSTONE_POS = -1

# file type
HINT = "hint"
IMMUTABLE = "immutable"
ACTIVE = "active"
IMMUTABLE_TEMP = "itemp"
HINT_TEMP = "htemp"

logger = logging.getLogger("bytecask")


class BadCrcError(Exception):
    """Crc error
    """


class BadHeaderError(Exception):
    """Header Error
    """


def get_file_id(filename):
    return int(filename.split(".")[0])


HintEntry = namedtuple("HintEntry", ['tstamp', 'key_sz', 'value_sz',
                                     'value_pos', 'key'])

hint_fmt = ">diii"
hint_size = struct.calcsize(hint_fmt)
hint_struct = struct.Struct(hint_fmt)


@contextlib.contextmanager
def build_hint_file(hint_file_name):
    hint_file = HintFile(hint_file_name)
    hint_file.init_write_fd()
    try:
        yield hint_file
    finally:
        hint_file.close_write_fd()


@contextlib.contextmanager
def read_hint_file(hint_file_name):
    hint_file = HintFile(hint_file_name)
    hint_file.init_read_fd()
    try:
        yield hint_file
    finally:
        hint_file.close_read_fd()


class HintFile(object):
    """用于快速启动的索引文件
    """

    def __init__(self, filename):
        self.filename = filename
        self.file_id = get_file_id(filename)
        self.byte_size = 0
        if os.path.exists(filename):
            self.byte_size = os.stat(self.filename).st_size
        self.read_fd = None
        self.write_fd = None

    @property
    def size(self):
        return self.byte_size

    def init_write_fd(self):
        self.write_fd = open(self.filename, 'ab')

    def write(self, key, tstamp, value_pos, value_sz):
        self.write_fd.write(hint_struct.pack(
            tstamp, len(key), value_sz, value_pos) + key)
        self.byte_size += hint_size + len(key)

    def close_write_fd(self):
        self.write_fd.close()

    def init_read_fd(self):
        self.read_fd = open(self.filename, 'rb')

    def close_read_fd(self):
        self.read_fd.close()

    def iter_entries(self):
        fmmap = mmap.mmap(self.read_fd.fileno(), 0, mmap.ACCESS_READ)
        with contextlib.closing(fmmap):
            pos = 0
            while True:
                try:
                    entry, new_pos = self._read(fmmap, pos)
                    yield entry
                    pos = new_pos
                except EOFError:
                    raise StopIteration
                except BadHeaderError:
                    logger.warning("Found corrupt header at "
                                   "file_id:%d position:%d", self.file_id, pos)
                    raise StopIteration

    def _read(self, fmmap, pos):
        hint_header = fmmap[pos:pos+hint_size]
        if hint_header == b'':
            raise EOFError
        try:
            tstamp, key_sz, value_sz, value_pos = hint_struct.unpack(
                hint_header)[0]
        except struct.error as e:
            raise BadHeaderError(e)

        pos += hint_size
        key = fmmap[pos:pos+key_sz]
        pos += key_sz
        return HintEntry(tstamp, key_sz, value_sz, value_pos, key), pos


DataEntry = namedtuple("DataEntry", ['crc32', 'tstamp', 'key_sz', 'value_sz', 'key', 'value'])

# size
crc32_fmt = ">I"
crc32_size = struct.calcsize(crc32_fmt)
crc32_struct = struct.Struct(crc32_fmt)

header_fmt = ">dii"
header_size = struct.calcsize(header_fmt)
header_struct = struct.Struct(header_fmt)


class DataFile(object):

    def __init__(self, base_path, filename):
        self.base_path = base_path
        self.file_id = get_file_id(filename)
        self.filename = os.path.join(base_path, filename)
        self.hint_filename = os.path.join(base_path,
                                          "%d.%s" % (self.file_id, HINT))
        self.byte_size = 0
        if os.path.exists(self.filename):
            self.byte_size = os.stat(self.filename).st_size
        self.read_fd = None
        self.write_fd = None

    @property
    def size(self):
        return self.byte_size

    def init_read_fd(self):
        self.read_fd = open(self.filename, "rb")

    def close_read_fd(self):
        if self.read_fd:
            self.read_fd.close()

    def init_write_fd(self):
        self.write_fd = open(self.filename, 'ab')

    def close_write_fd(self):
        if self.write_fd:
            self.write_fd.flush()
            os.fsync(self.write_fd.fileno())
            self.write_fd.close()

    def exists(self):
        return os.path.exists(self.filename)

    @property
    def has_hint(self):
        return os.path.exists(self.hint_filename)

    @property
    def hint_size(self):
        if self.has_hint:
            return os.stat(self.hint_filename).st_size
        return 0

    def iter_entries(self):
        """use mmap to disable cache, and large file read
        """
        fmmap = mmap.mmap(self.read_fd.fileno(), 0, access=mmap.ACCESS_READ)
        with contextlib.closing(fmmap):
            pos = 0
            while True:
                try:
                    entry, new_pos = self._read(fmmap, pos)
                    pos = new_pos
                    yield entry
                except EOFError:
                    raise StopIteration
                except BadCrcError:
                    logger.warning("Found BadCrc on %s at position: %s, "
                                   "the rest of the file will be ignored",
                                   self.file_id, pos)
                    raise StopIteration
                except BadHeaderError:
                    logger.warning("Found corrupted header on %s "
                                   "at position: %s, "
                                   "the rest of the file will be ignored",
                                   self.file_id, pos)
                    raise StopIteration

    def _read(self, fmmap, pos):
        crc32_bytes = fmmap[pos:pos+crc32_size]
        pos += crc32_size
        header = fmmap[pos:pos+header_size]
        pos += header_size
        if crc32_bytes == b'' or header == b'':
            raise EOFError
        try:
            crc32 = crc32_struct.unpack(crc32_bytes)[0]
            tstamp, key_sz, value_sz = header_struct.unpack(header)
        except struct.error as e:
            raise BadHeaderError(e)
        key = fmmap[pos:pos+key_sz]
        pos += key_sz
        value = fmmap[pos:pos+value_sz]
        pos += value_sz
        # verify crc
        crc32_new = zlib.crc32(header + key + value) & 0xFFFFFFFF
        if crc32_new == crc32:
            return DataEntry(key, value, tstamp, crc32), pos
        else:
            raise BadCrcError(crc32, crc32_new)

    def get_value(self, value_pos, value_sz):
        self.read_fd.seek(value_pos)
        return self.read_fd.read(value_sz)

    def should_optimize(self):
        return True

    def write(self, key, value):
        tstamp = time.time()
        key_sz = len(key)
        value_sz = len(value)
        header_bytes = header_struct.pack(tstamp, key_sz, value_sz)
        crc32 = zlib.crc32(header_bytes + key + value) & 0xffffffff
        value_pos = self.byte_size + crc32_size + header_size + key_sz
        self.write_fd.write(crc32_struct.pack(crc32) +
                            header_bytes + key + value)
        self.byte_size = value_pos + value_sz
        return tstamp, value_pos, value_sz


KeydirEntry = namedtuple("KeydirEntry", ['file_id', 'tstamp',
                                         'value_sz', 'value_pos'])


class KeyDir(dict):
    pass


class BitCask(object):
    """bitcask
    """

    def __init__(self, base_path, max_file_size=1024*1024*1024):
        self.base_path = base_path
        self.max_file_size = max_file_size
        if not os.path.exists(base_path):
            os.mkdir(base_path)
        elif not os.path.isdir(base_path):
            raise ValueError("base path %s can't be directory" % base_path)

        self._immutables = {}
        self._active_file = None

        self._find_data_files()
        self._keydir = KeyDir()
        self._build_keydir()

    def _find_data_files(self):
        """find data files
        """
        active_file = None
        for filename in os.listdir(self.base_path):
            if IMMUTABLE in filename:
                immutable_file = DataFile(self.base_path, filename)
                immutable_file.init_read_fd()
                self._immutables[immutable_file.file_id] = immutable_file
            elif ACTIVE in filename:
                active_file = DataFile(self.base_path, filename)

        if not active_file:
            active_file = DataFile(self.base_path, "%d.%s" % (
                self.get_next_file_id(), ACTIVE))

        active_file.init_write_fd()
        active_file.init_read_fd()
        self._active_file = active_file

    def get_next_file_id(self):
        file_id = int(time.time())
        max_immutable_file_id = max(self._immutables.keys())
        if max_immutable_file_id and max_immutable_file_id >= file_id:
            file_id = max_immutable_file_id + 1
        if self._active_file and self._active_file.file_id >= file_id:
            file_id = self._active_file.file_id + 1
        return file_id

    def _build_keydir(self):
        """init keydir
        """
        logger.info("build keydir...")
        for data_file in sorted(self._immutables.values(),
                                key=lambda a:getattr(a, "filename")):
            if data_file.has_hint and data_file.hint_size > 0:
                self._load_from_hint(data_file)
            elif data_file.exists() and data_file.size > 0:
                self._load_from_data(data_file)
            else:
                logger.debug("Ignoring empty live file.")

        if self._active_file and self._active_file.exists() and self._active_file.size > 0:
            self._load_from_data(self._active_file)

        logger.info("keydir ready! keys:%d", len(self._keydir))

    def _load_from_hint(self, data_file):
        with read_hint_file(data_file.hint_filename) as hint_file:
            for entry in hint_file.iter_entries():
                if entry.value_pos == TOMBSTONE_POS:
                    self._keydir.pop(entry.key, None)
                else:
                    self._keydir[entry.key] = KeydirEntry(
                        data_file.file_id, entry.value_sz,
                        entry.value_pos, entry.tstamp)

    def _load_from_data(self, data_file):
        for entry in data_file.iter_entries():
            if entry.value == TOMBSTONE:
                self._keydir.pop(entry.key, None)
            else:
                self._keydir[entry.key] = KeydirEntry(
                    data_file.file_id, entry.value_sz,
                    entry.value_pos, entry.tstamp)

    def get(self, key):
        if not isinstance(key, bytes):
            raise KeyError("key must be bytes")
        key_entry = self._keydir.get(key)
        if key_entry:
            if key_entry.file_id in self._immutables:
                return self._immutables[key_entry.file_id].get_value(
                    key_entry.value_pos, key_entry.value_sz)
            elif self._active_file:
                return self._active_file.get_value(
                    key_entry.value_pos, key_entry.value_sz)

    def put(self, key, value):
        if not isinstance(key, bytes):
            raise KeyError("key must be bytes")
        if not isinstance(value, bytes):
            raise ValueError("value must be bytes")

        if self._active_file.size + \
                (len(key)+len(value)+header_size+crc32_size) > self.max_file_size:
            self._active_file.close_read_fd()
            self._active_file.close_write_fd()
            new_immutable_name = self._active_file.filename.replace(ACTIVE, IMMUTABLE)
            os.rename(self._active_file.filename, new_immutable_name)
            immutable_file = DataFile(*os.path.split(new_immutable_name))
            immutable_file.init_read_fd()
            self._immutables[immutable_file.file_id] = immutable_file
            self._active_file = DataFile(self.base_path, "%d.%s" % (
                self.get_next_file_id(), ACTIVE))
            self._active_file.init_read_fd()
            self._active_file.init_write_fd()

        tstamp, value_pos, value_sz = self._active_file.write(key, value)
        if value != TOMBSTONE:
            self._keydir[key] = KeydirEntry(self._active_file.file_id,
                                            tstamp, value_pos, value_sz)

    def contains(self, key):
        return key in self

    def keys(self):
        return self._keydir.keys()

    #TODO 进程保护
    def optimize(self):
        """释放那些已经删除、无用的data entry
        """
        logger.info("optimize...")
        for data_file in self._immutables.values():
            if not data_file.should_optimize():
                continue

            key_entries = []
            temp_immutable_file = DataFile(self.base_path, "%d.%s" % (
                self.get_next_file_id(), IMMUTABLE_TEMP))
            temp_immutable_file.init_write_fd()

            for data_entry in data_file.iter_entries():
                if data_entry.key not in self._keydir or \
                    data_entry.tstamp < self._keydir[data_entry.key].tstamp:
                    continue

                tstamp, value_pos, value_sz = temp_immutable_file.write(
                    data_entry.key, data_entry.value)
                key_entries.append((data_entry.key, KeydirEntry(
                    temp_immutable_file.file_id, tstamp, value_sz, value_pos)))

            temp_immutable_file.close_write_fd()
            if len(key_entries) == 0:
                continue

            new_file_name = temp_immutable_file.filename.replace(IMMUTABLE_TEMP, ACTIVE)
            os.rename(temp_immutable_file.filename, new_file_name)
            new_immutable_file = DataFile(*os.path.split(new_file_name))
            new_immutable_file.init_read_fd()
            data_file.close()
            self._immutables.pop(data_file.file_id)
            os.remove(data_file.filename)
            self._immutables[new_immutable_file.file_id] = new_immutable_file

            # update keydir
            for key, entry in key_entries:
                if key in self._keydir and self._keydir[key].tstamp <= entry.tstamp:
                    self._keydir[key] = entry

            # build hint file
            temp_hint_file_name = os.path.join(self.base_path, "%d.%s" % (
                new_immutable_file.file_id, HINT_TEMP))
            with build_hint_file(temp_hint_file_name) as hint_file:
                for key_entry in key_entries:
                    hint_file.write(key_entry.key, key_entry.tstamp,
                                    key_entry.value_pos, key_entry.value_sz)
            new_hint_file_name = temp_hint_file_name.replace(HINT_TEMP, HINT)
            os.rename(temp_hint_file_name, new_hint_file_name)

        logger.info("optimize ended!")

    def __contains__(self, key):
        if not isinstance(key, bytes):
            raise KeyError("key must be bytes")
        return key in self._keydir

    def delete(self, key):
        if not isinstance(key, bytes):
            raise KeyError("key must be bytes")

        self.put(key, TOMBSTONE)
        self._keydir.pop(key, None)

    def close(self):
        for data_file in self._immutables.values():
            data_file.close_read_fd()

        if self._active_file:
            self._active_file.close_read_fd()
            self._active_file.close_write_fd()

        self._keydir.clear()