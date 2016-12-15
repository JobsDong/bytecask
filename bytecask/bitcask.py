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


class HintFile(object):
    """用于快速启动的索引文件
    """

    def __init__(self, base_path, filename):
        self.base_path = base_path
        self.file_id = get_file_id(filename)
        self.filename = os.path.join(base_path, filename)
        self.byte_size = 0
        if os.path.exists(self.filename):
            self.byte_size = os.stat(self.filename).st_size
        self.fd = open(self.filename, 'rb')

    @property
    def size(self):
        return self.byte_size

    def iter_entries(self):
        fmmap = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)
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
                hint_header)
        except struct.error as e:
            raise BadHeaderError(e)

        pos += hint_size
        key = fmmap[pos:pos+key_sz]
        pos += key_sz
        return HintEntry(tstamp, key_sz, value_sz, value_pos, key), pos

    def close(self):
        self.fd.close()

DataEntry = namedtuple("DataEntry", ['crc32', 'tstamp', 'key_sz', 'value_sz', 'key', 'value'])

# size
crc32_fmt = ">I"
crc32_size = struct.calcsize(crc32_fmt)
crc32_struct = struct.Struct(crc32_fmt)

header_fmt = ">dii"
header_size = struct.calcsize(header_fmt)
header_struct = struct.Struct(header_fmt)


class ITempFile(object):

    def __init__(self, base_path, filename):
        self.base_path = base_path
        self.file_id = get_file_id(filename)
        self.filename = os.path.join(base_path, filename)
        self.key_entries = []
        self.byte_size = 0
        if os.path.exists(self.filename):
            self.byte_size = os.stat(self.filename).st_size
        self.fd = open(self.filename, 'ab')

    @property
    def size(self):
        return self.byte_size

    def delete(self):
        os.unlink(self.filename)

    def make_immutable(self):
        immutable_filename = self.filename.replace(IMMUTABLE_TEMP, IMMUTABLE)
        os.rename(self.filename, immutable_filename)
        return ImmutableFile(*os.path.split(immutable_filename))

    def build_hint(self):
        t_hint_filename = os.path.join(self.base_path, "%d.%s" % (
            self.file_id, HINT_TEMP))
        with open(t_hint_filename, 'wb') as hint_file:
            for key, entry in self.key_entries:
                hint_file.write(hint_struct.pack(
                    entry.tstamp, len(key), entry.value_pos,
                    entry.value_sz) + key)
        hint_filename = t_hint_filename.replace(HINT_TEMP, HINT)
        os.rename(t_hint_filename, hint_filename)

    def update_keydir(self, keydir):
        for key, entry in self.key_entries:
            if key in keydir and keydir[key].tstamp <= entry.tstamp:
                keydir[key] = entry

    def write(self, key, value):
        tstamp = time.time()
        key_sz = len(key)
        value_sz = len(value)
        header_bytes = header_struct.pack(tstamp, key_sz, value_sz)
        crc32 = zlib.crc32(header_bytes + key + value) & 0xffffffff
        value_pos = self.byte_size + crc32_size + header_size + key_sz
        self.fd.write(crc32_struct.pack(crc32) + header_bytes + key + value)
        self.byte_size = value_pos + value_sz
        self.key_entries.append((key, KeydirEntry(
            self.file_id, tstamp, value_sz, value_pos)))

    def close(self):
        self.fd.flush()
        os.fsync(self.fd.fileno())
        self.fd.close()


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
        self.fd = None

    @property
    def size(self):
        return self.byte_size

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
        fmmap = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)
        with contextlib.closing(fmmap):
            pos = 0
            while True:
                try:
                    entry, new_pos = self._read(fmmap, pos)
                    pos = new_pos
                    yield pos-len(entry.value), entry
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
        value_pos = pos
        value = fmmap[pos:pos+value_sz]
        pos += value_sz
        # verify crc
        crc32_new = zlib.crc32(header + key + value) & 0xFFFFFFFF
        if crc32_new == crc32:
            return DataEntry(crc32, tstamp, key_sz, value_sz, key, value), pos
        else:
            raise BadCrcError(crc32, crc32_new)

    def get_value(self, value_pos, value_sz):
        self.fd.seek(value_pos)
        return self.fd.read(value_sz)


class ImmutableFile(DataFile):

    def __init__(self, base_path, filename):
        super(ImmutableFile, self).__init__(base_path, filename)
        self.fd = open(self.filename, 'rb')

    def should_optimize(self):
        return True

    def delete(self):
        self.close()
        os.unlink(self.filename)
        os.unlink(self.hint_filename)

    def close(self):
        self.fd.close()


class ActiveFile(DataFile):

    def __init__(self, base_path, filename):
        super(ActiveFile, self).__init__(base_path, filename)
        self.fd = open(self.filename, 'ab+')

    def write(self, key, value):
        tstamp = time.time()
        key_sz = len(key)
        value_sz = len(value)
        header_bytes = header_struct.pack(tstamp, key_sz, value_sz)
        crc32 = zlib.crc32(header_bytes + key + value) & 0xffffffff
        value_pos = self.byte_size + crc32_size + header_size + key_sz
        self.fd.write(crc32_struct.pack(crc32) + header_bytes + key + value)
        self.byte_size = value_pos + value_sz
        return tstamp, value_pos, value_sz

    def make_immutable(self):
        """close file and replace name
        """
        self.close()
        new_immutable_filename = self.filename.replace(ACTIVE, IMMUTABLE)
        os.rename(self.filename, new_immutable_filename)
        return ImmutableFile(*os.path.split(new_immutable_filename))

    def close(self):
        self.fd.flush()
        os.fsync(self.fd.fileno())
        self.fd.close()


KeydirEntry = namedtuple("KeydirEntry", ['file_id', 'tstamp',
                                         'value_pos', 'value_sz'])


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
                immutable_file = ImmutableFile(self.base_path, filename)
                self._immutables[immutable_file.file_id] = immutable_file
            elif ACTIVE in filename:
                active_file = ActiveFile(self.base_path, filename)

        if not active_file:
            active_file = ActiveFile(self.base_path, "%d.%s" % (
                self.get_next_file_id(), ACTIVE))

        self._active_file = active_file

    def get_next_file_id(self):
        file_id = int(time.time())
        max_immutable_file_id = max(self._immutables.keys()) \
            if self._immutables else None
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
        with contextlib.closing(
                HintFile(*os.path.split(data_file.hint_filename))) as hint_file:
            for entry in hint_file.iter_entries():
                if entry.value_pos == TOMBSTONE_POS:
                    self._keydir.pop(entry.key, None)
                else:
                    self._keydir[entry.key] = KeydirEntry(
                        data_file.file_id, entry.tstamp,
                        entry.value_pos, entry.value_sz)

    def _load_from_data(self, data_file):
        for value_pos, entry in data_file.iter_entries():
            if entry.value == TOMBSTONE:
                self._keydir.pop(entry.key, None)
            else:
                self._keydir[entry.key] = KeydirEntry(
                    data_file.file_id, entry.tstamp,
                    value_pos, entry.value_sz)

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
            logger.info("%s file is beyond max file size" % self._active_file.filename)
            # make immutable and build new active file
            immutable_file = self._active_file.make_immutable()
            self._immutables[immutable_file.file_id] = immutable_file
            self._active_file = ActiveFile(self.base_path, "%d.%s" % (
                self.get_next_file_id(), ACTIVE))

        tstamp, value_pos, value_sz = self._active_file.write(key, value)
        if value != TOMBSTONE:
            self._keydir[key] = KeydirEntry(self._active_file.file_id,
                                            tstamp, value_pos, value_sz)

    def optimize(self):
        logger.info("optimizing...")
        for data_file in self._immutables.values():
            if not data_file.should_optimize():
                continue

            t_file_name = "%d.%s" % (self.get_next_file_id(), IMMUTABLE_TEMP)

            with contextlib.closing(
                    ITempFile(self.base_path, t_file_name)) as t_file:
                for value_pos, entry in data_file.iter_entries():
                    if entry.key not in self._keydir or \
                            entry.tstamp < self._keydir[entry.key].tstamp:
                        continue

                    t_file.write(entry.key, entry.value)

            if t_file.size == 0:
                t_file.delete()
                continue

            # build hint
            self._immutables.pop(data_file.file_id)
            data_file.delete()
            self._immutables[t_file.file_id] = t_file.make_immutable()
            t_file.update_keydir(self._keydir)
            t_file.build_hint()

        logger.info("optimize ended!")

    def contains(self, key):
        return key in self

    def keys(self):
        return self._keydir.keys()

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
            data_file.close()

        if self._active_file:
            self._active_file.close()

        self._keydir.clear()