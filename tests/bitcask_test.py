#!/usr/bin/env python
# -*- coding: utf-8 -*-


__author__ = ['"wuyadong" <wuyadong311521@gmail.com>']

import os
import shutil
from unittest import TestCase
from bytecask.bitcask import (HintFile, DataFile, get_file_id, crc32_size,
                              header_size)


def test_get_file_id():
    assert get_file_id("3423434.active") == 3423434
    assert get_file_id("3423434.immutabe") == 3423434
    assert get_file_id("3423434.hint") == 3423434


def setup():
    if os.path.exists("./testdir"):
        shutil.rmtree("./testdir")
    os.mkdir("./testdir")


def teardown():
    if os.path.exists("./testdir"):
        shutil.rmtree("./testdir")


class DataFileTest(TestCase):

    def test_exists_size(self):
        """exists size hint hint file size
        """
        data_file = DataFile("./testdir", "321234.immutable")
        assert not data_file.exists()
        assert 0 == data_file.size
        data_file.init_write_fd()
        assert data_file.exists()
        data_file.close_write_fd()
        assert data_file.size == 0
        assert not data_file.has_hint
        hint_file = HintFile(data_file.hint_filename)
        hint_file.init_write_fd()
        assert data_file.has_hint
        hint_file.close_write_fd()
        assert 0 == data_file.hint_size

    def test_write_entries(self):
        """write entries
        """
        # write
        data_file = DataFile("./testdir", "1.immutable")
        assert 0 == data_file.size
        data_file.init_write_fd()
        tstamp, value_pos, value_sz = data_file.write("test", "0123456789")
        assert value_sz == 10
        assert value_pos == 4 + 16 + 4
        tstamp2, _, _ = data_file.write("hello", "9876543210")
        data_file.close_write_fd()
        assert data_file.size == 69
        data_file.init_read_fd()
        iterator = data_file.iter_entries()
        entry1 = iterator.next()
        assert entry1.tstamp == tstamp
        assert entry1.key == "test"
        assert entry1.value == "0123456789"
        entry2 = iterator.next()
        assert entry2.tstamp == tstamp2
        assert entry2.key == "hello"
        assert entry2.value == "9876543210"
        data_file.close_read_fd()

    def test_write_get_value(self):
        """write and get value
        """
        data_file = DataFile("./testdir", "2.active")
        assert 0 == data_file.size
        data_file.init_write_fd()
        data_file.init_read_fd()
        tstamp, v_pos, v_sz = data_file.write("hello", "12345")
        value = data_file.get_value(v_pos, v_sz)
        print value, "-----"
        assert value == '12345'
        tstamp2, v_pos, v_sz = data_file.write("test", "12345")
        value2 = data_file.get_value(v_pos, v_sz)
        assert value2 == "12345"
        data_file.close_write_fd()
        data_file.close_read_fd()
