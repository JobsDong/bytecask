#!/usr/bin/env python
# -*- coding: utf-8 -*-


__author__ = ['"wuyadong" <wuyadong311521@gmail.com>']

import os
import shutil
from unittest import TestCase
from struct import Struct
from bytecask.bitcask import (IMMUTABLE, ITempFile, ActiveFile,
                              get_file_id, ImmutableFile, HintFile, BitCask)


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


class ActiveFileTest(TestCase):

    def test_write(self):
        a_f = ActiveFile("./testdir", "1.active")
        try:
            t1, v_p1, v_s1 = a_f.write("hello", "world")
            assert v_p1 == 25 and v_s1 == 5
            t2, v_p2, v_s2 = a_f.write(Struct(">i").pack(1), Struct(">i").pack(2))
            assert v_p2 == 54 and v_s2 == 4
            assert t1 < t2
        finally:
            a_f.close()

    def test_make_immutable(self):
        a_f = ActiveFile("./testdir", "2.active")
        _, v_p1, v_s1 = a_f.write("hello", "world")
        _, v_p2, v_s2 = a_f.write(Struct(">i").pack(1), Struct(">i").pack(2))
        immutable_file = a_f.make_immutable()
        try:
            assert immutable_file.file_id == 2 and immutable_file.filename.endswith(IMMUTABLE)
            assert not os.path.exists(os.path.join("./testdir", "2.active"))
        finally:
            immutable_file.close()

    def test_get_value(self):
        a_f = ActiveFile("./testdir", "3.active")
        _, v_p1, v_s1 = a_f.write("hello", "world")
        _, v_p2, v_s2 = a_f.write(Struct(">i").pack(1), Struct(">i").pack(2))
        _, v_p3, v_s3 = a_f.write("world", "lllll")
        try:
            assert "world" == a_f.get_value(v_p1, v_s1)
            assert Struct(">i").unpack(a_f.get_value(v_p2, v_s2))[0] == 2
            assert a_f.get_value(v_p3, v_s3) == "lllll"
        finally:
            a_f.close()

    def test_iter_entries(self):
        a_f = ActiveFile("./testdir", "4.active")
        _, v_p1, v_s1 = a_f.write("hello", "world")
        _, v_p2, v_s2 = a_f.write(Struct(">i").pack(1), Struct(">i").pack(2))
        _, v_p3, v_s3 = a_f.write("world", "lllll")
        a_f.close()

        a_f = ActiveFile("./testdir", "4.active")
        entry_list = list(a_f.iter_entries())
        try:
            assert len(entry_list) == 3
            assert entry_list[0][1].key == "hello" and entry_list[0][1].value == "world"
            assert Struct(">i").unpack(entry_list[1][1].key)[0] == 1 and \
                Struct(">i").unpack(entry_list[1][1].value)[0] == 2
            assert entry_list[2][1].key == "world" and entry_list[2][1].value == "lllll"
        finally:
            a_f.close()


class ImmutableFileTest(TestCase):

    def build_immutable_file(self, filename):
        a_f = ActiveFile("./testdir", filename)
        a_f.write("hello", "world")
        a_f.write(Struct(">i").pack(1), Struct(">i").pack(2))
        a_f.write("world", "lllll")
        a_f.close()

    def test_iter_entries(self):
        self.build_immutable_file("5.immutable")
        i_f = ImmutableFile("./testdir", "5.immutable")
        entry_list = list(i_f.iter_entries())
        try:
            assert len(entry_list) == 3
            assert entry_list[0][1].key == "hello" and entry_list[0][1].value == "world"
            assert Struct(">i").unpack(entry_list[1][1].key)[0] == 1 and \
                Struct(">i").unpack(entry_list[1][1].value)[0] == 2
            assert entry_list[2][1].key == "world" and entry_list[2][1].value == "lllll"
        finally:
            i_f.close()

    def test_get_value(self):
        self.build_immutable_file("6.immutable")
        i_f = ImmutableFile("./testdir", "6.immutable")
        try:
            assert "world" == i_f.get_value(25, 5)
            assert 2 == Struct(">i").unpack(i_f.get_value(54, 4))[0]
        finally:
            i_f.close()


class ITempFileTest(TestCase):

    def test_build_immutable(self):
        i_f = ITempFile("./testdir", "7.itemp")
        i_f.write("hello", "world")
        i_f.write(Struct(">i").pack(1), Struct(">i").pack(2))
        i_f.write("world", "lllll")
        i_f.close()
        assert os.path.exists("./testdir/7.itemp")
        immutable_file = i_f.make_immutable()
        l = list(immutable_file.iter_entries())
        assert len(l) == 3
        assert l[0][1].key == "hello" and l[0][1].value == "world"
        assert Struct(">i").unpack(l[1][1].key)[0] == 1 and Struct('>i').unpack(l[1][1].value)[0] == 2
        assert l[2][1].key == "world" and l[2][1].value == "lllll"
        immutable_file.close()
        assert os.path.exists("./testdir/7.immutable") and not os.path.exists("./testdir/7.itemp")
        i_f.build_hint()
        assert os.path.exists("./testdir/7.hint")
        h_f = HintFile("./testdir", "7.hint")
        l1 = list(h_f.iter_entries())
        assert len(l1) == 3
        assert l1[0].key == "hello" and l1[0].value_pos == 25 and l1[0].value_sz == 5
        assert Struct(">i").unpack(l1[1].key)[0] == 1 and l1[1].value_pos == 54 and l1[1].value_sz == 4
        h_f.close()


class BitCaskTest(TestCase):

    def test_get_set(self):
        bitcask = BitCask("./testdir/bitcask", max_file_size=25*1024)
        try:
            assert not bitcask.contains("hello")
            assert not bitcask.contains(Struct(">i").pack(1))
            bitcask.put("hello", "world")
            bitcask.put(Struct(">i").pack(1), Struct(">i").pack(2))
            assert bitcask.get("hello") == "world"
            assert bitcask.get(Struct(">i").pack(1)) == Struct(">i").pack(2)
            bitcask.put(Struct(">i").pack(1), Struct(">i").pack(3))
            assert bitcask.get(Struct(">i").pack(1)) == Struct(">i").pack(3)
        finally:
            bitcask.close()

    def test_delete_keys(self):
        bitcask = BitCask("./testdir/bitcask1", max_file_size=25*1024)
        try:
            bitcask.put("hello", "world")
            bitcask.put(Struct(">i").pack(1), Struct(">i").pack(2))
            assert bitcask.get("hello") == "world"
            assert len(bitcask.keys()) == 2 and bitcask.keys()[0] == "hello" and bitcask.keys()[1] == Struct(">i").pack(1)
            bitcask.delete("hello")
            assert not bitcask.contains("hello")
            assert len(bitcask.keys()) == 1
            assert bitcask._active_file.get_value(58+4+16+5, 9) == "TOMBSTONE"
        finally:
            bitcask.close()

    def test_build_keydir_from_data(self):
        bitcask = BitCask("./testdir/bitcask2", max_file_size=25*1024)
        try:
            bitcask.put("hello", "world")
            bitcask.put(Struct(">i").pack(1), Struct(">i").pack(2))
        finally:
            bitcask.close()

        bitcask2 = BitCask("./testdir/bitcask2", max_file_size=25*1024)
        try:
            assert bitcask2.get("hello") == "world"
            assert bitcask2.get(Struct(">i").pack(1)) == Struct(">i").pack(2)
        finally:
            bitcask2.close()

    def test_optimize(self):
        pass

    def testk_build_keydir_from_hint(self):
        pass