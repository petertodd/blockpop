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

import Crypto.Cipher.AES

import bitcoin.core
import bitcoin.core.script

"""PoP data extraction

Note that this part of blockpop is consensus critical.
"""

class NullCipher:
    """Placeholder that does nothing"""
    def __init__(self, key=b'', iv=b''):
        self.key = key
        self.iv = iv

    def decrypt(self, data):
        return data

    def encrypt(self, data):
        return data

def AESCipher(key, iv):
    """AES stream cipher"""
    r = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CFB, iv)
    r.key = key
    r.iv = iv
    return r

class _ChunkControlFields(ctypes.Structure):
    _fields_ = [('skip_num',             ctypes.c_ubyte, 3),
                ('end_script',           ctypes.c_ubyte, 1),
                ('txout_txin_mode',      ctypes.c_ubyte, 1),
                ('open_p2sh',            ctypes.c_ubyte, 1),
                ('pubkey_steganography', ctypes.c_ubyte, 1),
                ('done',                 ctypes.c_ubyte, 1)]


class ChunkControl(ctypes.Union):
    SKIP_NUM_MASK = 0b111

    _anonymous_ = ('_chunk_control_fields',)
    _fields_ = [('_chunk_control_fields', _ChunkControlFields),
                ('padding_length', ctypes.c_ubyte, 7)]

    def __int__(self):
        return bytes(self)[0]

    def __ixor__(self, other):
        self.skip_num             ^= other.skip_num
        self.end_script           ^= other.end_script
        self.txout_txin_mode      ^= other.txout_txin_mode
        self.open_p2sh            ^= other.open_p2sh
        self.pubkey_steganography ^= other.pubkey_steganography
        self.done                 ^= other.done
        return self


    def __iand__(self, other):
        self.skip_num             &= other.skip_num
        self.end_script           &= other.end_script
        self.txout_txin_mode      &= other.txout_txin_mode
        self.open_p2sh            &= other.open_p2sh
        self.pubkey_steganography &= other.pubkey_steganography
        self.done                 &= other.done
        return self

    def __ior__(self, other):
        self.skip_num             |= other.skip_num
        self.end_script           |= other.end_script
        self.txout_txin_mode      |= other.txout_txin_mode
        self.open_p2sh            |= other.open_p2sh
        self.pubkey_steganography |= other.pubkey_steganography
        self.done                 |= other.done
        return self

    def __xor__(self, other):
        r = copy.copy(self)
        r ^= other
        return r

    def __and__(self, other):
        r = copy.copy(self)
        r &= other
        return r

    def __or__(self, other):
        r = copy.copy(self)
        r |= other
        return r

    def __repr__(self):
        return '%s(0x%.2X)' % (self.__class__.__qualname__, int(self))


def extract_script_pushes(script):
    """Extract all pushes in a script

    Returns an iterable
    """
    r = []
    for (op, data, sop_idx) in script.raw_iter():
        if data is not None:
            r.append(data)
    return r

class BaseTxDataExtractor:
    """Base class for tx data extractors

    This class just handles the mechanics of extraction; it does not handle IV
    setup, determining the initial index of encoded data, etc.
    """

    def __iter_data_chunks(self, start_idx, init_chunk_ctrl):
        """Iterate through the data chunks in the transaction

        start_idx       - Starting index
        init_chunk_ctrl - Initial chunk control flags (not modified)

        Yields decrypted data chunks.
        """
        chunk_ctrl = copy.copy(init_chunk_ctrl)

        # There are three layers of iteration going on.
        #
        # To account for scriptSig malleability the order the pushes are
        # decoded from right to left, so the inner-most iterator is
        # extract_script_pushes(), which extracts all pushes in a script.
        #
        # The next level is do_script() which evaluates the last chunk control
        # byte for each new push to determine what push to evaluate next.
        #
        # Finally the outermost layer of iteration is do_tx(), which determines
        # which txin or txout to evaluate, again based on the last chunk
        # control byte.
        #
        # Finally do_tx() is called in a loop that decrypts each push as it is
        # found, updates the chunk control byte, and returns the decrypted data
        # to the callee.

        def do_tx(tx, start_idx):
            txout_iter = iter(tx.vout[start_idx:])
            txin_iter = iter(tx.vin[start_idx:])

            def do_script(script):
                for pushdata in reversed(extract_script_pushes(script)):
                    if chunk_ctrl.done:
                        break

                    elif chunk_ctrl.skip_num > 0:
                        chunk_ctrl.skip_num -= 1
                        continue

                    elif chunk_ctrl.open_p2sh:
                        chunk_ctrl.open_p2sh = 0 # or we'll do this again recursively!
                        yield from do_script(bitcoin.core.script.CScript(pushdata))

                    else:
                        yield pushdata
                        if chunk_ctrl.end_script:
                            break

            while True:
                if chunk_ctrl.txout_txin_mode:
                    # txout scriptPubKey
                    yield from do_script(next(txout_iter).scriptPubKey)

                else:
                    # txin scriptSig
                    yield from do_script(next(txin_iter).scriptSig)

        for push in do_tx(self.tx, start_idx):
            if chunk_ctrl.pubkey_steganography:
                push = push[2:]

            plaintext = self.cipher.decrypt(push)

            chunk_ctrl = ChunkControl.from_buffer(bytearray(plaintext[0:1]))

            if chunk_ctrl.done:
                plaintext = plaintext[:len(plaintext)-chunk_ctrl.padding_length]
                yield plaintext[1:]
                return

            yield plaintext[1:]

        raise Exception('Data truncated!')

    def __init__(self, tx, start_idx, init_chunk_ctrl, cipher=NullCipher):
        self.tx = tx
        self.cipher = cipher
        self.extractor = self.__iter_data_chunks(start_idx, init_chunk_ctrl)
        self.unused_bytes = b''

    def read(self, max_size=None):
        """Read bytes

        max_size - Maximum number to read. Default is no limit, which will
                   always return all data encoded.

        Returns b'' when end of data is reached.
        """

        # Get another chunk from the chunk extractor if needed
        while max_size is None or len(self.unused_bytes) < max_size:
            try:
                self.unused_bytes += next(self.extractor)
            except StopIteration:
                break

        r = self.unused_bytes[0:max_size]
        self.unused_bytes = self.unused_bytes[max_size:] if max_size is not None else b''
        return r

class SimpleTxDataExtractor(BaseTxDataExtractor):
    """Simple PoP extraction algorithm

    Starts extraction at the first txout. The initial chunk control value is
    taken from the lower 8 bits of the nValue. AES encryption is used with the
    iv set to the Hash() of the last push.
    """

    def __init__(self, tx, key, start_idx=0, cipher_algo=AESCipher):
        init_chunk_ctrl = ChunkControl.from_buffer(bytearray([tx.vout[start_idx].nValue & 0xff]))
        iv = bitcoin.core.Hash(extract_script_pushes(tx.vout[start_idx].scriptPubKey)[-1])[0:16]
        cipher = cipher_algo(key, iv)

        super().__init__(tx, start_idx, init_chunk_ctrl, cipher)
