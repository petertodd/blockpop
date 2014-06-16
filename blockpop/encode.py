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

import copy
import io
import ctypes
import random

from bitcoin.core import *
from bitcoin.core.script import *
import bitcoin.core.key

import Crypto.Cipher.AES
import Crypto.Cipher.blockalgo

import blockpop

class ChunkGenerator:
    """Turn a byte stream into PUSHDATA chunks"""

    def __init__(self, src_stream, cipher=blockpop.NullCipher()):
        self.src_stream = src_stream
        self.cipher = cipher
        self.done = False

    def get(self, min_length, max_length, chunk_ctrl):
        """Get the next chunk

        min_length - Minimum length of the chunk; nothing smaller will be
                     returned.
        max_length - Max length of the chunk, including control byte and
                     pubkey/nonce (if applicable)

        chunk_ctrl - Current control byte. Will be updated as required.

        When the end of data is reached self.done is set to True
        """

        # FIXME: change these asserts to something more friendly
        if min_length == 0:
            min_length = 1
        assert 1 < max_length
        assert 0 < min_length <= max_length
        assert min_length <= 128 # max representable padding
        assert not self.done

        if chunk_ctrl.pubkey_steganography:
            assert min_length == max_length == 33
            min_length -= 2
            max_length -= 2

        chunk = bytes(chunk_ctrl) + self.src_stream.read(max_length-1)

        # If we're at the end, pad if required.
        if len(chunk) < max_length-1:
            padding = b'\x00' * (min_length - len(chunk))

            # The last chunk is handled specially. The 'done' flag is set and
            # the other 7 bits are used to encode the length of padding added.
            end_chunk_ctrl = blockpop.ChunkControl(done=1, padding_length=len(padding))
            chunk = bytes(end_chunk_ctrl) + chunk[1:] + padding

            self.done = True

        encrypted_chunk = self.cipher.encrypt(chunk)

        if chunk_ctrl.pubkey_steganography:
            # Coerce the chunk into a valid-looking compressed pubkey using a
            # nonce. Valid pubkeys are uniformally distributed with 50%
            # probability, so we can just increment a nonce until we find a
            # valid one.

            # Create some deterministic random bytes to chose the pubkey prefix
            # and initial nonce. We could use random() here, but better to be
            # deterministic for the sake of unit tests.
            det_rand = Hash(encrypted_chunk + self.cipher.key + self.cipher.iv)

            # Either 0x02 or 0x03
            pubkey_prefix = (det_rand[0] & 0b1) + 2

            pubkey_nonce = initial_pubkey_nonce = det_rand[1]
            pubkey = bitcoin.core.key.CPubKey(b'') # invalid

            while not pubkey.is_fullyvalid:
                pubkey_nonce = (pubkey_nonce + 1) % 256
                if pubkey_nonce == initial_pubkey_nonce:
                    raise Exception("Ran out of nonce! This should not happen.")

                pubkey = bitcoin.core.key.CPubKey(bytes([pubkey_prefix, pubkey_nonce]) + encrypted_chunk)

            encrypted_chunk = bytes(pubkey)

        return encrypted_chunk


class ScriptEncoder:
    # Mask of control byte flags that we need set at the beginning for this
    # type of script encoder.
    ctrl_flag_mask = None

    # The values they need to be set too.
    required_ctrl_flags = None

    def __call__(self, chunk_generator, next_ctrl_byte):
        """Encode data, returning a script

        chunk_generator - The chunk generator in use.
        next_chunk_ctrl - What the chunk control needs to be set to on the last
                          push in the script.
        """
        raise NotImplementedError


class P2PKH_ScriptEncoder(ScriptEncoder):
    ctrl_flag_mask = blockpop.ChunkControl(skip_num=0,
                                           pubkey_steganography=0)

    required_ctrl_flags = blockpop.ChunkControl(skip_num=blockpop.ChunkControl.SKIP_NUM_MASK,
                                                pubkey_steganography=1)

    def __call__(self, chunk_generator, next_ctrl_byte):
        push = chunk_generator.get(20, 20, next_ctrl_byte)
        return CScript([OP_DUP, OP_HASH160, push, OP_EQUALVERIFY, OP_CHECKSIG])

class P2SH_ScriptEncoder(ScriptEncoder):
    ctrl_flag_mask = blockpop.ChunkControl(skip_num=0,
                                           pubkey_steganography=0)

    required_ctrl_flags = blockpop.ChunkControl(skip_num=blockpop.ChunkControl.SKIP_NUM_MASK,
                                                pubkey_steganography=1)

    def __call__(self, chunk_generator, next_ctrl_byte):
        push = chunk_generator.get(20, 20, next_ctrl_byte)
        return CScript([OP_HASH160, push, OP_EQUALVERIFY, OP_CHECKSIG])

class OP_Return_ScriptEncoder(ScriptEncoder):
    ctrl_flag_mask = blockpop.ChunkControl(skip_num=0,
                                           pubkey_steganography=0)

    required_ctrl_flags = blockpop.ChunkControl(skip_num=blockpop.ChunkControl.SKIP_NUM_MASK,
                                                pubkey_steganography=1)

    def __init__(self, max_length=40):
        self.max_length = max_length

    def __call__(self, chunk_generator, next_ctrl_byte):
        data = chunk_generator.get(0, self.max_length, next_ctrl_byte)
        return CScript([OP_RETURN, data])


class BareMultisig_ScriptEncoder(ScriptEncoder):
    def __init__(self,
                 m=1,
                 valid_pubkey_generator=lambda:(),
                 max_pubkeys=3,
                 min_length=33, max_length=65,
                 pubkey_steganography=False):

        if pubkey_steganography:
            if not (min_length == max_length == 33):
                raise ValueError('pubkey_steganography requires min_length == max_length == 33')

        self.m = m
        self.valid_pubkey_generator = valid_pubkey_generator
        self.pubkey_steganography = 1 if pubkey_steganography else 0
        self.min_length = min_length
        self.max_length = max_length
        self.max_pubkeys = max_pubkeys

        self.ctrl_flag_mask = blockpop.ChunkControl(skip_num=0,
                                                    pubkey_steganography=self.pubkey_steganography)
        self.required_ctrl_flags = blockpop.ChunkControl(skip_num=blockpop.ChunkControl.SKIP_NUM_MASK,
                                                         pubkey_steganography=1)

    def __call__(self, chunk_generator, next_chunk_ctrl):
        valid_pubkeys = list(self.valid_pubkey_generator())

        pubkeys = []

        chunk_ctrl = blockpop.ChunkControl(skip_num=0, pubkey_steganography=self.pubkey_steganography)

        while not chunk_ctrl.done and len(pubkeys) < self.max_pubkeys - len(valid_pubkeys):

            # The last data pubkey is handled specially using the requested
            # next_chunk_ctrl.
            if len(pubkeys) == self.max_pubkeys - len(valid_pubkeys) - 1:
                chunk_ctrl = next_chunk_ctrl

                # If the skip bit hasn't been set we need to skip past the
                # non-valid pubkeys.
                if not chunk_ctrl.skip:
                    chunk_ctrl.skip_num += len(valid_pubkeys)

            chunk = chunk_generator.get(self.max_length, chunk_ctrl, min_length=self.min_length)
            pubkeys.append(chunk)

        pubkeys = valid_pubkeys + pubkeys

        return CScript([self.m] + pubkeys + [len(pubkeys), OP_CHECKMULTISIG])


def encode_all_op_return(buf, key):
    txouts = []

    # First push needs to be skipped as it stores the iv
    chunk_ctrl = blockpop.ChunkControl(txout_txin_mode=1, skip_num=1)

    # Setup iv
    iv_push = b'iv'
    txouts.append(CTxOut(bytes(chunk_ctrl)[0], CScript([OP_RETURN, iv_push])))

    chunk_ctrl.skip_num = 0

    chunk_generator = ChunkGenerator(io.BytesIO(buf), cipher=blockpop.AESCipher(key, Hash(iv_push)[0:16]))

    script_encoder = OP_Return_ScriptEncoder()

    chunk_ctrl.pubkey_steganography = False
    while not chunk_generator.done:
        scriptPubKey = script_encoder(chunk_generator, chunk_ctrl)

        txout = CTxOut(0, scriptPubKey)

        txouts.append(txout)

    return CTransaction([], txouts)


def encode_P2SH_encoding(buf, key, valid_pubkey):
    txouts = []
    p2sh_redeemScripts = []

    # First push needs to be skipped as it stores the iv
    chunk_ctrl = blockpop.ChunkControl(txout_txin_mode=1, skip_num=1)

    # Setup iv
    iv_push = b'iv'
    txouts.append(CTxOut(bytes(chunk_ctrl)[0], CScript([OP_RETURN, iv_push])))

    chunk_ctrl.skip_num = 0

    chunk_generator = ChunkGenerator(io.BytesIO(buf), cipher=blockpop.AESCipher(key, Hash(iv_push)[0:16]))

    script_encoder = BareMultisig_ScriptEncoder(valid_pubkey_generator=lambda:[valid_pubkey])

    chunk_ctrl.pubkey_steganography = True
    while not chunk_ctrl.done:
        scriptPubKey = script_encoder(chunk_generator, chunk_ctrl)

        txout = CTxOut(0, scriptPubKey)

        txouts.append(txout)

    return CTransaction([], txouts)
