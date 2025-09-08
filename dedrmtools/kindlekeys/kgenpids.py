__license__ = 'GPL v3'
__version__ = '3.0'

#  Copyright © 2025 Paul Tavitian.

import binascii
import sys
import traceback
from struct import pack


class DrmException(Exception):
    pass


global charMap1
global charMap3
global charMap4

# noinspection PyRedeclaration
charMap1 = b'n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M'
# noinspection PyRedeclaration
charMap3 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
# noinspection PyRedeclaration
charMap4 = b'ABCDEFGHIJKLMNPQRSTUVWXYZ123456789'

# crypto digestroutines
import hashlib


def md5(message):
    ctx = hashlib.md5()
    ctx.update(message)
    return ctx.digest()


def sha1(message):
    ctx = hashlib.sha1()
    ctx.update(message)
    return ctx.digest()


# Encode the bytes in data with the characters in map
# data and map should be byte arrays
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
def encode_hash(data, char_map):
    return encode(md5(data), char_map)


# Decode the string in data with the characters in map. Returns the decoded bytes
def decode(data, char_map):
    result = ''
    for i in range(0, len(data) - 1, 2):
        high = char_map.find(data[i])
        low = char_map.find(data[i + 1])
        if (high == -1) or (low == -1):
            break
        value = (((high * len(char_map)) ^ 0x80) & 0xFF) + low
        result += pack('B', value)
    return result


#
# PID generation routines
#

# Returns two bit at offset from a bit field
def get_two_bits_from_bit_field(bit_field, offset):
    byte_number = offset // 4
    bit_position = 6 - 2 * (offset % 4)
    if sys.version_info[0] == 2:
        return ord(bit_field[byte_number]) >> bit_position & 3
    else:
        return bit_field[byte_number] >> bit_position & 3


# Returns the six bits at offset from a bit field
def get_six_bits_from_bit_field(bit_field, offset):
    offset *= 3
    value = (get_two_bits_from_bit_field(bit_field, offset) << 4) + (
            get_two_bits_from_bit_field(bit_field, offset + 1) << 2) + get_two_bits_from_bit_field(bit_field,
                                                                                                   offset + 2)
    return value


# 8 bits to six bits encoding from hash to generate PID string
def encode_pid(hash_data):
    global charMap3
    pid = b''
    for position in range(0, 8):
        pid += bytes(bytearray([charMap3[get_six_bits_from_bit_field(hash_data, position)]]))

    return pid


# Encryption table used to generate the device PID
def generate_pid_encryption_table():
    table = []
    for counter1 in range(0, 0x100):
        value = counter1
        for counter2 in range(0, 8):
            if value & 1 == 0:
                value = value >> 1
            else:
                value = value >> 1
                value = value ^ 0xEDB88320
        table.append(value)
    return table


# Seed value used to generate the device PID
def generate_pid_seed(table, dsn):
    value = 0
    for counter in range(0, 4):
        index = (dsn[counter] ^ value) & 0xFF
        value = (value >> 8) ^ table[index]
    return value


# Generate the device PID
def generate_device_pid(table, dsn, nb_roll):
    global charMap4
    seed = generate_pid_seed(table, dsn)
    pid_ascii = b''
    pid = [(seed >> 24) & 0xFF, (seed >> 16) & 0xff, (seed >> 8) & 0xFF, seed & 0xFF, (seed >> 24) & 0xFF,
           (seed >> 16) & 0xff, (seed >> 8) & 0xFF, seed & 0xFF]
    index = 0
    for counter in range(0, nb_roll):
        pid[index] = pid[index] ^ dsn[counter]
        index = (index + 1) % 8
    for counter in range(0, 8):
        index = ((((pid[counter] >> 5) & 3) ^ pid[counter]) & 0x1f) + (pid[counter] >> 7)
        pid_ascii += bytes(bytearray([charMap4[index]]))
    return pid_ascii


def crc32(s):
    return (~binascii.crc32(s, -1)) & 0xFFFFFFFF


# convert from 8 digit PID to 10 digit PID with checksum
def checksum_pid(s):
    global charMap4
    crc = crc32(s)
    crc = crc ^ (crc >> 16)
    res = s
    l = len(charMap4)
    for _ in (0, 1):
        b = crc & 0xff
        pos = (b // l) ^ (b % l)
        res += bytes(bytearray([charMap4[pos % l]]))
        crc >>= 8
    return res


# old kindle serial number to fixed pid
def pid_from_serial(s, l) -> bytes:
    global charMap4
    crc = crc32(s)
    arr1 = [0] * l
    for i in range(len(s)):
        if sys.version_info[0] == 2:
            arr1[i % l] ^= ord(s[i])
        else:
            arr1[i % l] ^= s[i]
    crc_bytes = [crc >> 24 & 0xff, crc >> 16 & 0xff, crc >> 8 & 0xff, crc & 0xff]
    for i in range(l):
        arr1[i] ^= crc_bytes[i & 3]
    pid = b""
    for i in range(l):
        b = arr1[i] & 0xff
        pid += bytes(bytearray([charMap4[(b >> 7) + ((b >> 5 & 3) ^ (b & 0x1f))]]))
    return pid


# Parse the EXTH header records and use the Kindle serial number to calculate the book pid.
def get_kindle_pids(rec209, token, serialnum):
    if isinstance(serialnum, str):
        serialnum = serialnum.encode('utf-8')

    if sys.version_info[0] == 2:
        # noinspection PyUnresolvedReferences
        if isinstance(serialnum, unicode):
            serialnum = serialnum.encode('utf-8')

    if rec209 is None:
        return [serialnum]

    pids = []

    # Compute book PID
    pid_hash = sha1(serialnum + rec209 + token)
    book_pid = encode_pid(pid_hash)
    book_pid = checksum_pid(book_pid)
    pids.append(book_pid)

    # compute fixed pid for old pre 2.5 firmware update pid as well
    kindle_pid = pid_from_serial(serialnum, 7) + b"*"
    kindle_pid = checksum_pid(kindle_pid)
    pids.append(kindle_pid)

    return pids


# parse the Kindleinfo file to calculate the book pid.

keynames = ['kindle.account.tokens', 'kindle.cookie.item', 'eulaVersionAccepted', 'login_date', 'kindle.token.item',
            'login', 'kindle.key.item', 'kindle.name.info', 'kindle.device.info', 'MazamaRandomNumber']


def get_k4_pids(rec209, token, kindle_database):
    global charMap1
    pids = []

    try:
        # Get the kindle account token, if present
        kindle_account_token = bytearray.fromhex((kindle_database[1])['kindle.account.tokens'])

    except KeyError:
        kindle_account_token = b''
        pass

    try:
        # Get the DSN token, if present
        dsn = bytearray.fromhex((kindle_database[1])['DSN'])
        print("Got DSN key from database {0}".format(kindle_database[0]))
    except KeyError:
        # See if we have the info to generate the DSN
        try:
            # Get the Mazama Random number
            mazama_random_number = bytearray.fromhex((kindle_database[1])['MazamaRandomNumber'])
            # print "Got MazamaRandomNumber from database {0}".format(kindleDatabase[0])

            try:
                # Get the SerialNumber token, if present
                id_string = bytearray.fromhex((kindle_database[1])['SerialNumber'])
                print("Got SerialNumber from database {0}".format(kindle_database[0]))
            except KeyError:
                # Get the IDString we added
                id_string = bytearray.fromhex((kindle_database[1])['IDString'])

            try:
                # Get the UsernameHash token, if present
                encoded_username = bytearray.fromhex((kindle_database[1])['UsernameHash'])
                print("Got UsernameHash from database {0}".format(kindle_database[0]))
            except KeyError:
                # Get the UserName we added
                user_name = bytearray.fromhex((kindle_database[1])['UserName'])
                # encode it
                encoded_username = encode_hash(user_name, charMap1)
                # print "encodedUsername",encodedUsername.encode('hex')
        except KeyError:
            print("Keys not found in the database {0}.".format(kindle_database[0]))
            return pids

        # Get the ID string used
        encoded_id_string = encode_hash(id_string, charMap1)
        # print "encodedIDString",encodedIDString.encode('hex')

        # concat, hash and encode to calculate the DSN
        dsn = encode(sha1(mazama_random_number + encoded_id_string + encoded_username), charMap1)
        # print "DSN",DSN.encode('hex')
        pass

    if rec209 is None:
        pids.append(dsn + kindle_account_token)
        return pids

    # Compute the device PID (for which I can tell, is used for nothing).
    table = generate_pid_encryption_table()
    device_pid = generate_device_pid(table, dsn, 4)
    device_pid = checksum_pid(device_pid)
    pids.append(device_pid)

    # Compute book PIDs

    # book pid
    pid_hash = sha1(dsn + kindle_account_token + rec209 + token)
    book_pid = encode_pid(pid_hash)
    book_pid = checksum_pid(book_pid)
    pids.append(book_pid)

    # variant 1
    pid_hash = sha1(kindle_account_token + rec209 + token)
    book_pid = encode_pid(pid_hash)
    book_pid = checksum_pid(book_pid)
    pids.append(book_pid)

    # variant 2
    pid_hash = sha1(dsn + rec209 + token)
    book_pid = encode_pid(pid_hash)
    book_pid = checksum_pid(book_pid)
    pids.append(book_pid)

    return pids


def get_pid_list(md1, md2, serials=None, k_databases=None):
    if k_databases is None:
        k_databases = []
    if serials is None:
        serials = []
    pidlst = []

    if k_databases is None:
        k_databases = []
    if serials is None:
        serials = []

    for k_database in k_databases:
        try:
            pidlst.extend(map(bytes, get_k4_pids(md1, md2, k_database)))
        except Exception as e:
            print("Error getting PIDs from database {0}: {1}".format(k_database[0], e.args[0]))
            traceback.print_exc()

    for serialnum in serials:
        try:
            pidlst.extend(map(bytes, get_kindle_pids(md1, md2, serialnum)))
        except Exception as e:
            print("Error getting PIDs from serial number {0}: {1}".format(serialnum, e.args[0]))
            traceback.print_exc()

    return pidlst
