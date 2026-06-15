# coding=utf-8
#  Copyright © 2025-2026 Paul Tavitian.

import sys


class PukallCipher:
    def __init__(self):
        pass

    @staticmethod
    def pc1(key, src, decryption=True):
        sum1 = 0
        sum2 = 0
        key_xor_val = 0
        if len(key) != 16:
            raise Exception("PC1: Bad key length")
        wkey = []
        for i in range(8):
            if sys.version_info[0] == 2:
                wkey.append(ord(key[i * 2]) << 8 | ord(key[i * 2 + 1]))
            else:
                wkey.append(key[i * 2] << 8 | key[i * 2 + 1])
        dst = bytearray(len(src))
        for i in range(len(src)):
            temp1 = 0
            byte_xor_val = 0
            for j in range(8):
                temp1 ^= wkey[j]
                sum2 = (sum2 + j) * 20021 + sum1
                sum1 = (temp1 * 346) & 0xFFFF
                sum2 = (sum2 + sum1) & 0xFFFF
                temp1 = (temp1 * 20021 + 1) & 0xFFFF
                byte_xor_val ^= temp1 ^ sum2

            if sys.version_info[0] == 2:
                cur_byte = ord(src[i])
            else:
                cur_byte = src[i]

            if not decryption:
                key_xor_val = cur_byte * 257
            cur_byte = ((cur_byte ^ (byte_xor_val >> 8)) ^ byte_xor_val) & 0xFF
            if decryption:
                key_xor_val = cur_byte * 257
            for j in range(8):
                wkey[j] ^= key_xor_val

            if sys.version_info[0] == 2:
                # noinspection PyTypeChecker
                dst[i] = chr(cur_byte)
            else:
                dst[i] = cur_byte

        return bytes(dst)
