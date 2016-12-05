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

# size
crc32_fmt = ">I"
crc32_size = struct.calcsize(crc32_fmt)
crc32_struct = struct.Struct(crc32_fmt)

header_fmt = ">dii"
header_size = struct.calcsize(header_fmt)
header_struct = struct.Struct(header_fmt)

hint_fmt = ">diii"
hint_size = struct.calcsize(hint_fmt)
hint_struct = struct.Struct(hint_fmt)

# TOMBSTONE
TOMBSTONE = "TOMBSTONE"
TOMBSTONE_POS = -1
# file type
HINT = "hint"
IMMUTABLE = "immutable"
DEAD = "dead"
ACTIVE = "active"

logger = logging.getLogger("bytecask")

class BadCrcError(Exception):
    """Crc error
    """

class BadHeaderError(Exception):
    """Header Error
    """

def is_hint(filename):
    return HINT in filename

def is_immutable(filename):
    return IMMUTABLE in filename

def is_dead(filename):
    return DEAD in filename

def is_active(filename):
    return ACTIVE in filename

def get_file_id(filename):
    return int(filename.split(".")[0])

KeydirEntry = namedtuple("KeydirEntry", ['file_id', 'tstamp', 'value_sz', 'value_pos'])
DataEntry = namedtuple("DataEntry", ['crc32', 'tstamp', 'key_sz', 'value_sz', 'key', 'value'])
HintEntry = namedtuple("HintEntry", ['tstamp', 'key_sz', 'value_sz', 'value_pos', 'key'])


class HintFile(object):

    def __init__(self, filename):
        self.filename = filename
        self.file_id = get_file_id(filename)

    def _open(self):
        self.fd = open(self.filename, "rb")

    def iter_entries(self):
        fmmap = mmap.mmap(self.fd.fileno(),0, mmap.ACCESS_READ)
        with contextlib.closing(fmmap):
            pos = 0
            while True:
                try:
                    entry, new_pos = self.read(fmmap, pos)
                    yield entry
                    pos = new_pos
                except EOFError:
                    raise StopIteration
                except BadHeaderError:
                    logger.warning("Found corrupt header at file_id:%d position:%d", self.file_id, pos)
                    raise StopIteration

    def read(self, fmmap, pos):
        hint_header = fmmap[pos:pos+hint_size]
        if hint_header == b'':
            raise EOFError
        try:
            tstamp, key_sz, value_sz, value_pos = hint_struct.unpack(hint_header)[0]
        except struct.error as e:
            raise BadHeaderError(e)

        pos += hint_size
        key = fmmap[pos:pos+key_sz]
        pos += key_sz
        return HintEntry(tstamp, key_sz, value_sz, value_pos, key), pos

    def __enter__(self):
        self._open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fd.close()


class ImmutableFile(object):

    def __init__(self, base_path, filename):
        self.base_path = base_path
        self.filename = os.path.join(base_path, filename)
        self.file_id = get_file_id(filename)
        self.hint_filename = os.path.join(base_path, "%d.%s" % (self.file_id, HINT))
        self.fd = open(self.filename, 'rb')

    def size(self):
        if self.exists():
            return os.stat(self.filename).st_size
        return 0

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

    def get_hint_file(self):
        return HintFile(self.hint_filename)

    def iter_entries(self):
        """use mmap to disable cache, and large file read
        """
        fmmap = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)
        with contextlib.closing(fmmap):
            pos = 0
            while True:
                try:
                    entry, new_pos = self.read(fmmap, pos)
                    pos = new_pos
                    yield entry
                except EOFError:
                    raise StopIteration
                except BadCrcError:
                    logger.warning("Found BadCrc on %s at position: %s, "
                                   "the rest of the file will be ignored", self.file_id, pos)
                    raise StopIteration
                except BadHeaderError:
                    logger.warning("Found corrupted header on %s at position: %s, "
                                   "the rest of the file will be ignored", self.file_id, pos)
                    raise StopIteration

    def read(self, fmmap, pos):
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
        crc32_new = zlib.crc32(header + key + value_sz) & 0xFFFFFFFF
        if crc32_new == crc32:
            return DataEntry(crc32, tstamp, key_sz, value_sz, key, value_sz), pos
        else:
            raise BadCrcError(crc32, crc32_new)

    def get_value(self):
        pass

class ActiveFile(object):

    def __init__(self, base_path, filename):
        self.base_path = base_path
        self.filename = os.path.join(base_path, filename)
        self.file_id = get_file_id(filename)

    def get_value(self, value_pos, value_sz):
        pass





class KeyDir(dict):
    pass

class BitCask(object):
    """bitcask
    """

    def __init__(self, base_path):
        self.base_path = base_path
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
        for filename in os.listdir(self.base_path):
            if is_immutable(filename):
                # init immutable file
                immutable_file = ImmutableFile(self.base_path, filename)
                self._immutables[immutable_file.file_id] = immutable_file
            elif is_active(filename):
                self._active_file = ActiveFile(self.base_path, filename)

        if not self._active_file:
            active_file_id = int(time.time())
            max_immutable_file_id = max(self._immutables.keys())
            if active_file_id <= max_immutable_file_id:
                active_file_id = max_immutable_file_id + 1
            self._active_file = ActiveFile(self.base_path, "%d.%s" % (active_file_id, ACTIVE))

    def _build_keydir(self):
        """init keydir
        """
        for data_file in sorted(self._immutables.values(), key=lambda a:getattr(a, "filename")):
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
        with data_file.get_hint_file() as hint_file:
            for entry in hint_file.iter_entries():
                if entry.value_pos == TOMBSTONE_POS:
                    self._keydir.pop(entry.key, None)
                else:
                    self._keydir[entry.key] = KeydirEntry(data_file.file_id, entry.value_sz,
                                                            entry.value_pos, entry.tstamp)

    def _load_from_data(self, data_file):
        for entry in data_file.iter_entries():
            if entry.value == TOMBSTONE:
                self._keydir.pop(entry.key, None)
            else:
                self._keydir[entry.key] = KeydirEntry(data_file.file_id, entry.value_sz,
                                                      entry.value_pos, entry.tstamp)

    def get(self, key, default=None):
        if not isinstance(key, bytes):
            raise KeyError("key must be bytes")
        key_entry = self._keydir.get(key)
        if key_entry:
            if key_entry.file_id in self._immutables:
                return self._immutables[key_entry.file_id].get_value(key_entry.value_pos, key_entry.value_sz)
            elif self._active_file:
                return self._active_file.get_value(key_entry.value_pos, key_entry.value_sz)

        return default

    def put(self, key, value):
        if not isinstance(key, bytes):
            raise KeyError("key must be bytes")
        if not isinstance(value, bytes):
            raise ValueError("value must be bytes")

        entry = DataEntry()
        self._active_file.write()


        pass

    def contains(self, key):
        pass

    def keys(self):
        pass

    def __contains__(self, key):
        pass

    def delete(self, key):
        pass

    def merge(self):
        pass

    def close(self):
        pass