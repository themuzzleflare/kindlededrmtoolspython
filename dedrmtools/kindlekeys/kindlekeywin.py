#  Copyright © 2025 Paul Tavitian.
import os
import re
import sys
from ctypes import windll, c_wchar_p, c_uint, POINTER, byref, create_unicode_buffer, create_string_buffer, string_at, \
    Structure, c_void_p, cast
from struct import unpack

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.Util import Counter
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util import Counter

from dedrmtools.kindlekeys.kindlekeygen import KindleKey

try:
    import winreg
except ImportError:
    # noinspection PyUnresolvedReferences
    import _winreg as winreg

MAX_PATH = 255
kernel32 = windll.kernel32
advapi32 = windll.advapi32
crypt32 = windll.crypt32

# Various character maps used to decrypt kindle info values.
# Probably supposed to act as obfuscation
charMap2 = b"AaZzB0bYyCc1XxDdW2wEeVv3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_"
charMap5 = b"AzB0bYyCeVvaZ3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_c1XxDdW2wE"
# New maps in K4PC 1.9.0
testMap1 = b"n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M"
testMap6 = b"9YzAb0Cd1Ef2n5Pr6St7Uvh3Jk4M8WxG"
testMap8 = b"YvaZ3FfUm9Nn_c1XuG4yCAzB0beVg-TtHh5SsIiR6rJjQdW2wEq7KkPpL8lOoMxD"


# interface with Windows OS Routines
class DataBlob(Structure):
    _fields_ = [('cbData', c_uint),
                ('pbData', c_void_p)]


DataBlob_p = POINTER(DataBlob)


class RegError(Exception):
    pass


def get_system_directory():
    # noinspection PyUnresolvedReferences,PyPep8Naming
    GetSystemDirectoryW = kernel32.GetSystemDirectoryW
    GetSystemDirectoryW.argtypes = [c_wchar_p, c_uint]
    GetSystemDirectoryW.restype = c_uint

    buffer = create_unicode_buffer(MAX_PATH + 1)
    GetSystemDirectoryW(buffer, len(buffer))
    return buffer.value


def get_volume_serial_number(path=get_system_directory().split('\\')[0] + '\\'):
    # noinspection PyPep8Naming,PyUnresolvedReferences
    GetVolumeInformationW = kernel32.GetVolumeInformationW
    GetVolumeInformationW.argtypes = [c_wchar_p, c_wchar_p, c_uint,
                                      POINTER(c_uint), POINTER(c_uint),
                                      POINTER(c_uint), c_wchar_p, c_uint]
    GetVolumeInformationW.restype = c_uint

    vsn = c_uint(0)
    GetVolumeInformationW(path, None, 0, byref(vsn), None, None, None, 0)
    return str(vsn.value)


def get_id_string():
    vsn = get_volume_serial_number()
    # print('Using Volume Serial Number for ID: '+vsn)
    return vsn


def get_last_error():
    # noinspection PyUnresolvedReferences,PyPep8Naming
    GetLastError = kernel32.GetLastError
    GetLastError.argtypes = None
    GetLastError.restype = c_uint

    return GetLastError()


def crypt_unprotect_data(indata, entropy, flags):
    # noinspection PyUnresolvedReferences
    _CryptUnprotectData = crypt32.CryptUnprotectData
    _CryptUnprotectData.argtypes = [DataBlob_p, c_wchar_p, DataBlob_p,
                                    c_void_p, c_void_p, c_uint, DataBlob_p]
    _CryptUnprotectData.restype = c_uint

    indatab = create_string_buffer(indata)
    indata = DataBlob(len(indata), cast(indatab, c_void_p))
    entropyb = create_string_buffer(entropy)
    entropy = DataBlob(len(entropy), cast(entropyb, c_void_p))
    outdata = DataBlob()
    if not _CryptUnprotectData(byref(indata), None, byref(entropy),
                               None, None, flags, byref(outdata)):
        # raise DrmException("Failed to Unprotect Data")
        return b'failed'
    return string_at(outdata.pbData, outdata.cbData)


# Returns Environmental Variables that contain unicode
# name must be unicode string, not byte string.
def get_environment_variable(name):
    import ctypes
    # noinspection PyUnresolvedReferences
    n = ctypes.windll.kernel32.GetEnvironmentVariableW(name, None, 0)
    if n == 0:
        return None
    buf = ctypes.create_unicode_buffer("\0" * n)
    # noinspection PyUnresolvedReferences
    ctypes.windll.kernel32.GetEnvironmentVariableW(name, buf, n)
    return buf.value


class KindleKeyWindows(KindleKey):
    def __init__(self):
        print("KindleKeyWindows")

    def get_username(self):
        # noinspection PyPep8Naming,PyUnresolvedReferences
        GetUserNameW = advapi32.GetUserNameW
        GetUserNameW.argtypes = [c_wchar_p, POINTER(c_uint)]
        GetUserNameW.restype = c_uint

        buffer = create_unicode_buffer(2)
        size = c_uint(len(buffer))
        while not GetUserNameW(buffer, byref(size)):
            errcd = get_last_error()
            if errcd == 234:
                # bad wine implementation up through wine 1.3.21
                return "AlternateUserName"
            # double the buffer size
            buffer = create_unicode_buffer(len(buffer) * 2)
            size.value = len(buffer)

        # replace any non-ASCII values with 0xfffd
        for i in range(0, len(buffer)):
            if sys.version_info[0] == 2:
                if buffer[i] > u"\u007f":
                    # print "swapping char "+str(i)+" ("+buffer[i]+")"
                    buffer[i] = u"\ufffd"
            else:
                if buffer[i] > "\u007f":
                    # print "swapping char "+str(i)+" ("+buffer[i]+")"
                    buffer[i] = "\ufffd"
        # return utf-8 encoding of modified username
        # print "modified username:"+buffer.value
        return buffer.value.encode('utf-8')

    # Locate all of the kindle-info style files and return as list
    def get_kindle_info_files(self):
        k_info_files = []
        # some 64 bit machines do not have the proper registry key for some reason
        # or the python interface to the 32 vs 64 bit registry is broken
        path = ""
        if 'LOCALAPPDATA' in os.environ.keys():
            # Python 2.x does not return unicode env. Use Python 3.x
            if sys.version_info[0] == 2:
                path = winreg.ExpandEnvironmentStrings(u"%LOCALAPPDATA%")
            else:
                path = winreg.ExpandEnvironmentStrings("%LOCALAPPDATA%")
            # this is just another alternative.
            # path = getEnvironmentVariable('LOCALAPPDATA')
            if not os.path.isdir(path):
                path = ""
        else:
            # User Shell Folders show take precedent over Shell Folders if present
            try:
                # this will still break
                regkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\")
                path = winreg.QueryValueEx(regkey, 'Local AppData')[0]
                if not os.path.isdir(path):
                    path = ""
                    try:
                        regkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\")
                        path = winreg.QueryValueEx(regkey, 'Local AppData')[0]
                        if not os.path.isdir(path):
                            path = ""
                    except RegError:
                        pass
            except RegError:
                pass

        found = False
        if path == "":
            print('Could not find the folder in which to look for kinfoFiles.')
        else:
            # Probably not the best. To Fix (shouldn't ignore in encoding) or use utf-8
            print("searching for kinfoFiles in " + path)

            # look for (K4PC 1.25.1 and later) .kinf2018 file
            kinfopath = path + '\\Amazon\\Kindle\\storage\\.kinf2018'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.25+ kinf2018 file: ' + kinfopath)
                k_info_files.append(kinfopath)

            # look for (K4PC 1.9.0 and later) .kinf2011 file
            kinfopath = path + '\\Amazon\\Kindle\\storage\\.kinf2011'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.9+ kinf2011 file: ' + kinfopath)
                k_info_files.append(kinfopath)

            # look for (K4PC 1.6.0 and later) rainier.2.1.1.kinf file
            kinfopath = path + '\\Amazon\\Kindle\\storage\\rainier.2.1.1.kinf'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.6-1.8 kinf file: ' + kinfopath)
                k_info_files.append(kinfopath)

            # look for (K4PC 1.5.0 and later) rainier.2.1.1.kinf file
            kinfopath = path + '\\Amazon\\Kindle For PC\\storage\\rainier.2.1.1.kinf'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.5 kinf file: ' + kinfopath)
                k_info_files.append(kinfopath)

            # look for original (earlier than K4PC 1.5.0) kindle-info files
            kinfopath = path + '\\Amazon\\Kindle For PC\\{AMAwzsaPaaZAzmZzZQzgZCAkZ3AjA_AY}\\kindle.info'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC kindle.info file: ' + kinfopath)
                k_info_files.append(kinfopath)

        if not found:
            print('No K4PC kindle.info/kinf/kinf2011 files have been found.')
        return k_info_files

    # determine type of kindle info provided and return a
    # database of keynames and values
    def get_db_from_file(self, k_info_file):
        names = [
            b'kindle.account.tokens',
            b'kindle.cookie.item',
            b'eulaVersionAccepted',
            b'login_date',
            b'kindle.token.item',
            b'login',
            b'kindle.key.item',
            b'kindle.name.info',
            b'kindle.device.info',
            b'MazamaRandomNumber',
            b'max_date',
            b'SIGVERIF',
            b'build_version',
            b'SerialNumber',
            b'UsernameHash',
            b'kindle.directedid.info',
            b'DSN',
            b'kindle.accounttype.info',
            b'krx.flashcardsplugin.data.encryption_key',
            b'krx.notebookexportplugin.data.encryption_key',
            b'proxy.http.password',
            b'proxy.http.username'
        ]
        namehashmap = {self.encode_hash(n, testMap8): n for n in names}
        # print(namehashmap)
        db = {}
        with open(k_info_file, 'rb') as infoReader:
            data = infoReader.read()
        # assume .kinf2011 or .kinf2018 style .kinf file
        # the .kinf file uses "/" to separate it into records
        # so remove the trailing "/" to make it easy to use split
        data = data[:-1]
        items = data.split(b'/')

        # starts with an encoded and encrypted header blob
        headerblob = items.pop(0)
        encrypted_value = self.decode(headerblob, testMap1)
        cleartext = self.unprotect_header_data(encrypted_value)
        # print "header  cleartext:",cleartext
        # now extract the pieces that form the added entropy
        pattern = re.compile(br'''\[Version:(\d+)]\[Build:(\d+)]\[Cksum:([^]]+)]\[Guid:([{}a-z0-9\-]+)]''',
                             re.IGNORECASE)
        for m in re.finditer(pattern, cleartext):
            version = int(m.group(1))
            build = m.group(2)
            guid = m.group(4)

        # noinspection PyUnboundLocalVariable
        if version == 5:  # .kinf2011
            # noinspection PyUnboundLocalVariable
            added_entropy = build + guid
        elif version == 6:  # .kinf2018
            # noinspection PyUnboundLocalVariable
            salt = str(0x6d8 * int(build)).encode('utf-8') + guid
            # noinspection PyTypeChecker
            sp = self.get_username() + b'+@#$%+' + get_id_string().encode('utf-8')
            passwd = self.encode(self.sha256(sp), charMap5)
            key = PBKDF2(passwd, salt, count=10000, dkLen=0x400)[:32]  # this is very slow

        # loop through the item records until all are processed
        while len(items) > 0:

            # get the first item record
            item = items.pop(0)

            # the first 32 chars of the first record of a group
            # is the MD5 hash of the key name encoded by charMap5
            keyhash = item[0:32]

            # the remainder of the first record when decoded with charMap5
            # has the ':' split char followed by the string representation
            # of the number of records that follow
            # and make up the contents
            srcnt = self.decode(item[34:], charMap5)
            rcnt = int(srcnt)

            # read and store in rcnt records of data
            # that make up the contents value
            edlst = []
            for i in range(rcnt):
                item = items.pop(0)
                edlst.append(item)

            # key names now use the new testMap8 encoding
            if keyhash in namehashmap:
                keyname = namehashmap[keyhash]
                # print "keyname found from hash:",keyname
            else:
                keyname = keyhash
                # print "keyname not found, hash is:",keyname

            # the testMap8 encoded contents data has had a length
            # of chars (always odd) cut off of the front and moved
            # to the end to prevent decoding using testMap8 from
            # working properly, and thereby preventing the ensuing
            # CryptUnprotectData call from succeeding.

            # The offset into the testMap8 encoded contents seems to be:
            # len(contents)-largest prime number <=  int(len(content)/3)
            # (in other words split "about" 2/3rds of the way through)

            # move first offsets chars to end to align for decode by testMap8
            # by moving noffset chars from the start of the
            # string to the end of the string
            encdata = b"".join(edlst)
            # print "encrypted data:",encdata
            contlen = len(encdata)
            noffset = contlen - self.primes(int(contlen / 3))[-1]
            pfx = encdata[0:noffset]
            encdata = encdata[noffset:]
            encdata = encdata + pfx
            # print "rearranged data:",encdata

            # noinspection PyUnboundLocalVariable
            if version == 5:
                # decode using new testMap8 to get the original CryptProtect Data
                encrypted_value = self.decode(encdata, testMap8)
                # print "decoded data:",encryptedValue.encode('hex')
                # noinspection PyUnboundLocalVariable
                entropy = self.sha1(keyhash) + added_entropy
                cleartext = crypt_unprotect_data(encrypted_value, entropy, 1)
            elif version == 6:
                # decode using new testMap8 to get IV + ciphertext
                iv_ciphertext = self.decode(encdata, testMap8)
                # pad IV so that we can substitute AES-CTR for GCM
                iv = iv_ciphertext[:12] + b'\x00\x00\x00\x02'
                ciphertext = iv_ciphertext[12:]
                # convert IV to int for use with pycrypto
                iv_ints = unpack('>QQ', iv)
                iv = iv_ints[0] << 64 | iv_ints[1]
                # set up AES-CTR
                ctr = Counter.new(128, initial_value=iv)
                # noinspection PyUnboundLocalVariable
                cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                # decrypt and decode
                cleartext = self.decode(cipher.decrypt(ciphertext), charMap5)

            if len(cleartext) > 0:
                # print "cleartext data:",cleartext,":end data"
                db[keyname] = cleartext
            # print keyname, cleartext

        if len(db) > 6:
            # store values used in decryption
            db[b'IDString'] = get_id_string().encode('utf-8')
            db[b'UserName'] = self.get_username()
            print("Decrypted key file using IDString '{0:s}' and UserName '{1:s}'".format(get_id_string(),
                                                                                          self.get_username().decode(
                                                                                              'utf-8')))
        else:
            print("Couldn't decrypt file.")
            db = {}
        return db
