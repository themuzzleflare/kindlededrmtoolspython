#  Copyright © 2025 Paul Tavitian.
from __future__ import annotations

import codecs
import hashlib
import json
import os
import sys
from abc import ABC, abstractmethod
from struct import pack
from typing import Any

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2


class DrmException(Exception):
    pass


class KindleKey(ABC):
    @staticmethod
    def get_instance() -> 'KindleKey':
        if sys.platform.startswith('win'):
            from dedrmtools.kindlekeys.kindlekeywin import KindleKeyWindows
            return KindleKeyWindows()
        elif sys.platform.startswith('darwin'):
            from dedrmtools.kindlekeys.kindlekeymac import KindleKeyMacOS
            return KindleKeyMacOS()
        else:
            raise DrmException("This script only runs under Windows or Mac OS X.")

    @abstractmethod
    def get_username(self) -> str | bytes | Any:
        pass

    @abstractmethod
    def get_kindle_info_files(self) -> list[Any]:
        pass

    @abstractmethod
    def get_db_from_file(self, k_info_file) -> dict[Any, Any]:
        pass

    @staticmethod
    def md5(message):
        return hashlib.md5(message).digest()

    @staticmethod
    def sha1(message):
        return hashlib.sha1(message).digest()

    @staticmethod
    def sha256(message):
        return hashlib.sha256(message).digest()

    # For K4M/PC 1.6.X and later
    @staticmethod
    def primes(n):
        """
        Return a list of prime integers smaller than or equal to n
        :param n: int
        :return: list->int
        """
        if n == 2:
            return [2]
        elif n < 2:
            return []
        prime_list = [2]

        for potential_prime in range(3, n + 1, 2):
            is_it_prime = True
            for prime in prime_list:
                if potential_prime % prime == 0:
                    is_it_prime = False
            if is_it_prime:
                prime_list.append(potential_prime)

        return prime_list

    # Encode the bytes in data with the characters in map
    # data and map should be byte arrays
    @staticmethod
    def encode(data, char_map):
        result = b''
        for char in data:
            if sys.version_info[0] == 2:
                value = ord(char)
            else:
                value = char

            q = (value ^ 0x80) // len(char_map)
            r = value % len(char_map)

            result += bytes(bytearray([char_map[q]]))
            result += bytes(bytearray([char_map[r]]))

        return result

    # Hash the bytes in data and then encode the digest with the characters in map
    @staticmethod
    def encode_hash(data, char_map):
        return KindleKey.encode(KindleKey.md5(data), char_map)

    # Decode the string in data with the characters in map. Returns the decoded bytes
    @staticmethod
    def decode(data, char_map):
        result = b''
        for i in range(0, len(data) - 1, 2):
            high = char_map.find(data[i])
            low = char_map.find(data[i + 1])
            if (high == -1) or (low == -1):
                break
            value = (((high * len(char_map)) ^ 0x80) & 0xFF) + low
            result += pack('B', value)
        return result

    @staticmethod
    def unprotect_header_data(encrypted_data):
        passwd_data = b'header_key_data'
        salt = b'HEADER.2011'
        # noinspection PyTypeChecker
        key_iv = PBKDF2(passwd_data, salt, dkLen=256, count=128)
        return AES.new(key_iv[0:32], AES.MODE_CBC, key_iv[32:48]).decrypt(encrypted_data)

    def kindlekeys(self, files=None):
        if files is None:
            files = []

        keys = []

        if files == []:
            files = self.get_kindle_info_files()

        for file in files:
            key = self.get_db_from_file(file)

            if key:
                # convert all values to hex, just in case.
                n_key = {}

                for k, v in key.items():
                    n_key[k.decode()] = codecs.encode(v, 'hex_codec').decode()

                # key = {k.decode():v.decode() for k,v in key.items()}
                keys.append(n_key)

        return keys

    # interface for Python DeDRM
    # returns single key or multiple keys, depending on path or file passed in
    def getkey(self, outpath, files=None):
        if files is None:
            files = []

        keys = self.kindlekeys(files)

        if len(keys) > 0:
            if not os.path.isdir(outpath):
                outfile = outpath
                with open(outfile, 'w') as keyfileout:
                    keyfileout.write(json.dumps(keys[0]))
                print("Saved a key to {0}".format(outfile))
            else:
                keycount = 0
                for key in keys:
                    while True:
                        keycount += 1
                        outfile = os.path.join(outpath, "kindlekey{0:d}.k4i".format(keycount))
                        if not os.path.exists(outfile):
                            break
                    with open(outfile, 'w') as keyfileout:
                        keyfileout.write(json.dumps(key))
                    print("Saved a key to {0}".format(outfile))
            return True
        return False
