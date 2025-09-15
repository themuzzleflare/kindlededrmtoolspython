# coding=utf-8
#  Copyright © 2025 Paul Tavitian.

import hashlib

try:
    from Cryptodome.Util.py3compat import bchr
except ImportError:
    from Crypto.Util.py3compat import bchr

from dedrmtools.kfxdedrm.kfxtables.kfxtables import *
from dedrmtools.kfxdedrm.obfuscationtable import OBFUSCATION_TABLE
from dedrmtools.kfxdedrm.workspace import Workspace


# asserts must always raise exceptions for proper functioning
def _assert(test, msg="Exception"):
    if not test:
        raise Exception(msg)


class IonUtils:
    def __init__(self):
        pass

    TID_NULL = 0
    TID_BOOLEAN = 1
    TID_POSINT = 2
    TID_NEGINT = 3
    TID_FLOAT = 4
    TID_DECIMAL = 5
    TID_TIMESTAMP = 6
    TID_SYMBOL = 7
    TID_STRING = 8
    TID_CLOB = 9
    TID_BLOB = 0xA
    TID_LIST = 0xB
    TID_SEXP = 0xC
    TID_STRUCT = 0xD
    TID_TYPEDECL = 0xE
    TID_UNUSED = 0xF

    SID_UNKNOWN = -1
    SID_ION = 1
    SID_ION_1_0 = 2
    SID_ION_SYMBOL_TABLE = 3
    SID_NAME = 4
    SID_VERSION = 5
    SID_IMPORTS = 6
    SID_SYMBOLS = 7
    SID_MAX_ID = 8
    SID_ION_SHARED_SYMBOL_TABLE = 9
    SID_ION_1_0_MAX = 10

    LEN_IS_VAR_LEN = 0xE
    LEN_IS_NULL = 0xF

    VERSION_MARKER = [b"\x01", b"\x00", b"\xEA"]

    SYM_NAMES = ['com.amazon.drm.Envelope@1.0',
                 'com.amazon.drm.EnvelopeMetadata@1.0', 'size', 'page_size',
                 'encryption_key', 'encryption_transformation',
                 'encryption_voucher', 'signing_key', 'signing_algorithm',
                 'signing_voucher', 'com.amazon.drm.EncryptedPage@1.0',
                 'cipher_text', 'cipher_iv', 'com.amazon.drm.Signature@1.0',
                 'data', 'com.amazon.drm.EnvelopeIndexTable@1.0', 'length',
                 'offset', 'algorithm', 'encoded', 'encryption_algorithm',
                 'hashing_algorithm', 'expires', 'format', 'id',
                 'lock_parameters', 'strategy', 'com.amazon.drm.Key@1.0',
                 'com.amazon.drm.KeySet@1.0', 'com.amazon.drm.PIDv3@1.0',
                 'com.amazon.drm.PlainTextPage@1.0',
                 'com.amazon.drm.PlainText@1.0', 'com.amazon.drm.PrivateKey@1.0',
                 'com.amazon.drm.PublicKey@1.0', 'com.amazon.drm.SecretKey@1.0',
                 'com.amazon.drm.Voucher@1.0', 'public_key', 'private_key',
                 'com.amazon.drm.KeyPair@1.0', 'com.amazon.drm.ProtectedData@1.0',
                 'doctype', 'com.amazon.drm.EnvelopeIndexTableOffset@1.0',
                 'enddoc', 'license_type', 'license', 'watermark', 'key', 'value',
                 'com.amazon.drm.License@1.0', 'category', 'metadata',
                 'categorized_metadata', 'com.amazon.drm.CategorizedMetadata@1.0',
                 'com.amazon.drm.VoucherEnvelope@1.0', 'mac', 'voucher',
                 'com.amazon.drm.ProtectedData@2.0',
                 'com.amazon.drm.Envelope@2.0',
                 'com.amazon.drm.EnvelopeMetadata@2.0',
                 'com.amazon.drm.EncryptedPage@2.0',
                 'com.amazon.drm.PlainText@2.0', 'compression_algorithm',
                 'com.amazon.drm.Compressed@1.0', 'page_index_table',
                 ] + ['com.amazon.drm.VoucherEnvelope@%d.0' % n
                      for n in list(range(2, 29)) + [
                          9708, 1031, 2069, 9041, 3646,
                          6052, 9479, 9888, 4648, 5683]]

    @staticmethod
    def addprottable(ion):
        ion.addtocatalog("ProtectedData", 1, IonUtils.SYM_NAMES)

    @staticmethod
    def pkcs7pad(msg, blocklen):
        paddinglen = blocklen - len(msg) % blocklen
        padding = bchr(paddinglen) * paddinglen
        return msg + padding

    @staticmethod
    def pkcs7unpad(msg, blocklen):
        _assert(len(msg) % blocklen == 0)

        paddinglen = msg[-1]

        _assert(0 < paddinglen <= blocklen, "Incorrect padding - Wrong key")
        _assert(msg[-paddinglen:] == bchr(paddinglen) * paddinglen, "Incorrect padding - Wrong key")

        return msg[:-paddinglen]

    # obfuscate shared secret according to the VoucherEnvelope version
    @staticmethod
    def obfuscate(secret, version):
        if version == 1:  # v1 does not use obfuscation
            return secret

        magic, word = OBFUSCATION_TABLE["V%d" % version]

        # extend secret so that its length is divisible by the magic number
        if len(secret) % magic != 0:
            secret = secret + b'\x00' * (magic - len(secret) % magic)

        secret = bytearray(secret)

        obfuscated = bytearray(len(secret))
        wordhash = bytearray(hashlib.sha256(word).digest())

        # shuffle secret and xor it with the first half of the word hash
        for i in range(0, len(secret)):
            index = i // (len(secret) // magic) + magic * (i % (len(secret) // magic))
            obfuscated[index] = secret[i] ^ wordhash[index % 16]

        return obfuscated

    # scramble() and obfuscate2() from https://github.com/andrewc12/DeDRM_tools/commit/d9233d61f00d4484235863969919059f4d0b2057

    @staticmethod
    def scramble(st, magic):
        ret = bytearray(len(st))
        padlen = len(st)
        for counter in range(len(st)):
            ivar2 = (padlen // 2) - 2 * (counter % magic) + magic + counter - 1
            ret[ivar2 % padlen] = st[counter]
        return ret

    @staticmethod
    def obfuscate2(secret, version):
        if version == 1:  # v1 does not use obfuscation
            return secret
        magic, word = OBFUSCATION_TABLE["V%d" % version]
        # extend secret so that its length is divisible by the magic number
        if len(secret) % magic != 0:
            secret = secret + b'\x00' * (magic - len(secret) % magic)
        obfuscated = bytearray(len(secret))
        wordhash = bytearray(hashlib.sha256(word).digest()[16:])
        # print(wordhash.hex())
        shuffled = bytearray(IonUtils.scramble(secret, magic))
        for i in range(0, len(secret)):
            obfuscated[i] = shuffled[i] ^ wordhash[i % 16]
        return obfuscated

    # scramble3() and obfuscate3() from https://github.com/Satsuoni/DeDRM_tools/commit/da6b6a0c911b6d45fe1b13042b690daebc1cc22f

    @staticmethod
    def scramble3(st, magic):
        ret = bytearray(len(st))
        padlen = len(st)
        divs = padlen // magic
        cntr = 0
        # noinspection PyUnusedLocal
        i_var6 = 0
        offset = 0
        if 0 < ((magic - 1) + divs):
            while True:
                if (offset & 1) == 0:
                    u_var4 = divs - 1
                    if offset < divs:
                        i_var3 = 0
                        u_var4 = offset
                    else:
                        i_var3 = (offset - divs) + 1
                    if u_var4 >= 0:
                        i_var5 = u_var4 * magic
                        index = ((padlen - 1) - cntr)
                        while True:
                            if magic <= i_var3: break
                            ret[index] = st[i_var3 + i_var5]
                            i_var3 = i_var3 + 1
                            cntr = cntr + 1
                            u_var4 = u_var4 - 1
                            i_var5 = i_var5 - magic
                            index -= 1
                            if u_var4 <= -1: break
                else:
                    if offset < magic:
                        i_var3 = 0
                    else:
                        i_var3 = (offset - magic) + 1
                    if i_var3 < divs:
                        u_var4 = offset
                        if magic <= offset:
                            u_var4 = magic - 1

                        index = ((padlen - 1) - cntr)
                        i_var5 = i_var3 * magic
                        while True:
                            if u_var4 < 0: break
                            i_var3 += 1
                            ret[index] = st[u_var4 + i_var5]
                            u_var4 -= 1
                            index = index - 1
                            i_var5 = i_var5 + magic
                            cntr += 1
                            if i_var3 >= divs: break
                offset = offset + 1
                if offset >= ((magic - 1) + divs): break
        return ret

    # not sure if the third variant is used anywhere, but it is in Kindle, so I tried to add it
    @staticmethod
    def obfuscate3(secret, version):
        if version == 1:  # v1 does not use obfuscation
            return secret
        magic, word = OBFUSCATION_TABLE["V%d" % version]
        # extend secret so that its length is divisible by the magic number
        if len(secret) % magic != 0:
            secret = secret + b'\x00' * (magic - len(secret) % magic)
        # secret = bytearray(secret)
        obfuscated = bytearray(len(secret))
        wordhash = bytearray(hashlib.sha256(word).digest())
        # print(wordhash.hex())
        shuffled = bytearray(IonUtils.scramble3(secret, magic))
        # print(shuffled)
        # shuffle secret and xor it with the first half of the word hash
        for i in range(0, len(secret)):
            obfuscated[i] = shuffled[i] ^ wordhash[i % 16]
        return obfuscated

    @staticmethod
    def process_v9708(st):
        # e9c457a7dae6aa24365e7ef219b934b17ed58ee7d5329343fc3aea7860ed51f9a73de14351c9
        ws = Workspace([0x11] * 16)
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.shuffle(repl)
            ws.sbox(d0x6a06ea70, d0x6a0dab50)
            ws.sbox(d0x6a073a70, d0x6a0dab50)
            ws.shuffle(repl)
            ws.exlookup(d0x6a072a70)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)

    @staticmethod
    def process_v1031(st):
        # d53efea7fdd0fda3e1e0ebbae87cad0e8f5ef413c471c3ae81f39222a9ec8b8ed582e045918c
        ws = Workspace([0x06, 0x18, 0x60, 0x68, 0x3b, 0x62, 0x3e, 0x3c, 0x06, 0x50, 0x71, 0x52, 0x02, 0x5a, 0x63, 0x03])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.shuffle(repl)
            ws.sbox(d0x6a0797c0, d0x6a0dab50, [3])
            ws.sbox(d0x6a07e7c0, d0x6a0dab50, [3])
            ws.shuffle(repl)
            ws.sbox(d0x6a0797c0, d0x6a0dab50, [3])
            ws.sbox(d0x6a07e7c0, d0x6a0dab50, [3])
            ws.exlookup(d0x6a07d7c0)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
            # break
        return bytes(out)

    @staticmethod
    def process_v2069(st):
        # 8e6196d754a304c9354e91b5d79f07b048026d31c7373a8691e513f2c802c706742731caa858
        ws = Workspace([0x79, 0x0d, 0x12, 0x08, 0x66, 0x77, 0x2e, 0x5b, 0x02, 0x09, 0x0a, 0x13, 0x11, 0x0c, 0x11, 0x62])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.sbox(d0x6a084498, d0x6a0dab50, [2])
            ws.shuffle(repl)
            ws.sbox(d0x6a089498, d0x6a0dab50, [2])
            ws.sbox(d0x6a089498, d0x6a0dab50, [2])
            ws.sbox(d0x6a084498, d0x6a0dab50, [2])
            ws.shuffle(repl)
            ws.exlookup(d0x6a088498)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)

    @staticmethod
    def process_v9041(st):
        # 11f7db074b24e560dfa6fae3252b383c3b936e51f6ded570dc936cb1da9f4fc4a97ec686e7d8
        ws = Workspace([0x49, 0x0b, 0x0e, 0x3b, 0x19, 0x1a, 0x49, 0x61, 0x10, 0x73, 0x19, 0x67, 0x5c, 0x1b, 0x11, 0x21])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.sbox(d0x6a094170, d0x6a0dab50, [1])
            ws.shuffle(repl)
            ws.shuffle(repl)
            ws.sbox(d0x6a08f170, d0x6a0dab50, [1])
            ws.sbox(d0x6a08f170, d0x6a0dab50, [1])
            ws.sbox(d0x6a094170, d0x6a0dab50, [1])

            ws.exlookup(d0x6a093170)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
            # break
        return bytes(out)

    @staticmethod
    def process_v3646(st):
        # d468aa362b44479282291983243b38197c4b4aa24c2c58e62c76ec4b81e08556ca0c54301664
        ws = Workspace([0x0a, 0x36, 0x3e, 0x29, 0x4e, 0x02, 0x18, 0x38, 0x01, 0x36, 0x73, 0x13, 0x14, 0x1b, 0x16, 0x6a])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.shuffle(repl)
            ws.sbox(d0x6a099e48, d0x6a0dab50, [2, 3])
            ws.sbox(d0x6a09ee48, d0x6a0dab50, [2, 3])
            ws.sbox(d0x6a09ee48, d0x6a0dab50, [2, 3])
            ws.shuffle(repl)
            ws.sbox(d0x6a099e48, d0x6a0dab50, [2, 3])
            ws.sbox(d0x6a099e48, d0x6a0dab50, [2, 3])
            ws.shuffle(repl)
            ws.sbox(d0x6a09ee48, d0x6a0dab50, [2, 3])
            ws.exlookup(d0x6a09de48)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)

    @staticmethod
    def process_v6052(st):
        # d683c8c4e4f46ae45812196f37e218eabce0fae08994f25fabb01d3e569b8bf3866b99d36f57
        ws = Workspace([0x5f, 0x0d, 0x01, 0x12, 0x5d, 0x5c, 0x14, 0x2a, 0x17, 0x69, 0x14, 0x0d, 0x09, 0x21, 0x1e, 0x3b])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.shuffle(repl)
            ws.sbox(d0x6a0a4b20, d0x6a0dab50, [1, 3])
            ws.shuffle(repl)
            ws.sbox(d0x6a0a4b20, d0x6a0dab50, [1, 3])
            ws.sbox(d0x6a0a9b20, d0x6a0dab50, [1, 3])
            ws.shuffle(repl)
            ws.sbox(d0x6a0a9b20, d0x6a0dab50, [1, 3])
            ws.sbox(d0x6a0a9b20, d0x6a0dab50, [1, 3])
            ws.sbox(d0x6a0a4b20, d0x6a0dab50, [1, 3])

            ws.exlookup(d0x6a0a8b20)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)

    @staticmethod
    def process_v9479(st):
        # 925635db434bccd3f4791eb87b89d2dfc7c93be06e794744eb9de58e6d721e696980680ab551
        ws = Workspace([0x65, 0x1d, 0x19, 0x7c, 0x09, 0x79, 0x1d, 0x69, 0x7c, 0x4e, 0x13, 0x0e, 0x04, 0x1b, 0x6a, 0x3c])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.sbox(d0x6a0af7f8, d0x6a0dab50, [1, 2, 3])
            ws.sbox(d0x6a0af7f8, d0x6a0dab50, [1, 2, 3])
            ws.sbox(d0x6a0b47f8, d0x6a0dab50, [1, 2, 3])
            ws.sbox(d0x6a0af7f8, d0x6a0dab50, [1, 2, 3])
            ws.shuffle(repl)
            ws.sbox(d0x6a0b47f8, d0x6a0dab50, [1, 2, 3])
            ws.shuffle(repl)
            ws.shuffle(repl)
            ws.sbox(d0x6a0b47f8, d0x6a0dab50, [1, 2, 3])
            ws.exlookup(d0x6a0b37f8)

            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)

    @staticmethod
    def process_v9888(st):
        # 54c470723f8c105ba0186b6319050869de673ce31a5ec15d4439921d4cd05c5e860cb2a41fea
        ws = Workspace([0x3f, 0x17, 0x79, 0x69, 0x24, 0x6b, 0x37, 0x50, 0x63, 0x09, 0x45, 0x6f, 0x0c, 0x07, 0x07, 0x09])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.sbox(d0x6a0ba4d0, d0x6a0dab50, [1, 2])
            ws.sbox(d0x6a0bf4d0, d0x6a0dab50, [1, 2])
            ws.sbox(d0x6a0bf4d0, d0x6a0dab50, [1, 2])
            ws.sbox(d0x6a0ba4d0, d0x6a0dab50, [1, 2])
            ws.shuffle(repl)
            ws.shuffle(repl)
            ws.shuffle(repl)
            ws.sbox(d0x6a0bf4d0, d0x6a0dab50, [1, 2])
            ws.sbox(d0x6a0ba4d0, d0x6a0dab50, [1, 2])
            ws.exlookup(d0x6a0be4d0)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)

    @staticmethod
    def process_v4648(st):
        # 705bd4cd8b61d4596ef4ca40774d68e71f1f846c6e94bd23fd26e5c127e0beaa650a50171f1b
        ws = Workspace([0x16, 0x2b, 0x64, 0x62, 0x13, 0x04, 0x18, 0x0d, 0x63, 0x25, 0x14, 0x17, 0x0f, 0x13, 0x46, 0x0c])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.sbox(d0x6a0ca1a8, d0x6a0dab50, [1, 3])
            ws.shuffle(repl)
            ws.sbox(d0x6a0ca1a8, d0x6a0dab50, [1, 3])
            ws.sbox(d0x6a0c51a8, d0x6a0dab50, [1, 3])
            ws.sbox(d0x6a0ca1a8, d0x6a0dab50, [1, 3])
            ws.sbox(d0x6a0c51a8, d0x6a0dab50, [1, 3])
            ws.sbox(d0x6a0c51a8, d0x6a0dab50, [1, 3])
            ws.shuffle(repl)
            ws.shuffle(repl)
            ws.exlookup(d0x6a0c91a8)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)

    @staticmethod
    def process_v5683(st):
        # 1f5af733423e5104afb9d5594e682ecf839a776257f33747c9beee671c57ab3f84943f69d8fd
        ws = Workspace([0x7c, 0x36, 0x5c, 0x1a, 0x0d, 0x10, 0x0a, 0x50, 0x07, 0x0f, 0x75, 0x1f, 0x09, 0x3b, 0x0d, 0x72])
        repl = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        remln = len(st)
        sto = 0
        out = []
        while remln > 0:
            ws.sbox(d0x6a0d4e80, d0x6a0dab50, [])
            ws.shuffle(repl)
            ws.sbox(d0x6a0cfe80, d0x6a0dab50, [])
            ws.sbox(d0x6a0d4e80, d0x6a0dab50, [])
            ws.sbox(d0x6a0cfe80, d0x6a0dab50, [])
            ws.sbox(d0x6a0d4e80, d0x6a0dab50, [])
            ws.shuffle(repl)
            ws.sbox(d0x6a0cfe80, d0x6a0dab50, [])
            ws.shuffle(repl)
            ws.exlookup(d0x6a0d3e80)
            dat = ws.mask(st[sto:sto + 16])
            out += dat
            sto += 16
            remln -= 16
        return bytes(out)
