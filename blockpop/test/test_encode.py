# Copyright (C) 2014 Peter Todd <pete@petertodd.org>
#
# This file is part of Blockpop.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of Blockpop, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import io
import random
import unittest

from bitcoin.core import *
from bitcoin.core.script import *

import blockpop
import blockpop.encode

class Test_ChunkGenerator(unittest.TestCase):
    def test(self):

        chunk_ctrl = blockpop.ChunkControl()
        chunk_gen = blockpop.encode.ChunkGenerator(io.BytesIO(b''))

        self.assertEqual(chunk_gen.get(0, 100, chunk_ctrl), b'\x80')
        self.assertEqual(chunk_gen.done, True)


        chunk_ctrl = blockpop.ChunkControl()
        chunk_gen = blockpop.encode.ChunkGenerator(io.BytesIO(b'abcd'))

        self.assertEqual(chunk_gen.get(0, 5, chunk_ctrl), b'\x00abcd')
        self.assertEqual(chunk_gen.done, False)
        self.assertEqual(chunk_gen.get(0, 5, chunk_ctrl), b'\x80')
        self.assertEqual(chunk_gen.done, True)


        chunk_ctrl = blockpop.ChunkControl(pubkey_steganography=1)
        chunk_gen = blockpop.encode.ChunkGenerator(io.BytesIO(b'abcd'))

        self.assertEqual(chunk_gen.get(33, 33, chunk_ctrl), b'\x02\xc7\x9aabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(chunk_gen.done, True)


        chunk_ctrl = blockpop.ChunkControl(pubkey_steganography=1)
        chunk_gen = blockpop.encode.ChunkGenerator(io.BytesIO(b'\x00'*31))

        self.assertEqual(chunk_gen.get(33, 33, chunk_ctrl), b'\x03\xb1@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(chunk_gen.done, False)
        self.assertEqual(chunk_gen.get(33, 33, chunk_ctrl), b'\x03)\x9d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(chunk_gen.done, True)

class Test(unittest.TestCase):
    def test_op_return_encoding(self):

        key = b'\x00'*32
        buf = b'\x00'*40 + b'\xff'*40 + b'hi!'
        tx = blockpop.encode.encode_all_op_return(buf, key)
        #print(tx)

        extractor = blockpop.SimpleTxDataExtractor(tx, key)

        buf2 = extractor.read()

        self.assertEqual(buf, buf2)

    def test_p2sh_multisig_encoding(self):

        key = b'\x00'*32
        buf = b'\x00'*40 + b'\xff'*40 + b'hi!'
        tx = blockpop.encode.encode_all_op_return(buf, key)
        #print(tx)

        extractor = blockpop.SimpleTxDataExtractor(tx, key)

        buf2 = extractor.read()

        self.assertEqual(buf, buf2)
