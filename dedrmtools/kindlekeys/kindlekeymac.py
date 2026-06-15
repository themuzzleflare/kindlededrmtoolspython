# coding=utf-8
#  Copyright © 2025-2026 Paul Tavitian.
import os
import re
import subprocess
import sys
import traceback
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

charMap1 = b'n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M'
charMap2 = b'ZB0bYyc1xDdW2wEV3Ff7KkPpL8UuGA4gz-Tme9Nn_tHh5SvXCsIiR6rJjQaqlOoM'

# For kinf approach of K4Mac 1.6.X or later
# On K4PC charMap5 = 'AzB0bYyCeVvaZ3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_c1XxDdW2wE'
# For Mac they seem to re-use charMap2 here
charMap5 = charMap2

# new in K4M 1.9.X
testMap8 = b'YvaZ3FfUm9Nn_c1XuG4yCAzB0beVg-TtHh5SsIiR6rJjQdW2wEq7KkPpL8lOoMxD'


# implements an Pseudo Mac Version of Windows built-in Crypto routine
class CryptUnprotectData(object):
    def __init__(self, kindlekey: 'KindleKeyMacOS', entropy, id_string):
        sp = kindlekey.get_username() + b'+@#$%+' + id_string
        passwd_data = kindlekey.encode(kindlekey.sha256(sp), charMap2)
        salt = entropy
        key_iv = PBKDF2(passwd_data, salt, count=0x800, dkLen=0x400)
        self.key = key_iv[0:32]
        self.iv = key_iv[32:48]
        # noinspection PyUnresolvedReferences
        self.crp.set_decrypt_key(self.key, self.iv)

    def decrypt(self, kindlekey: 'KindleKeyMacOS', encrypted_data):
        # noinspection PyUnresolvedReferences
        cleartext = self.crp.decrypt(encrypted_data)
        cleartext = kindlekey.decode(cleartext, charMap2)
        return cleartext


# uses a sub process to get the Hard Drive Serial Number using ioreg
# returns serial numbers of all internal hard drive drives
def get_volumes_serial_numbers():
    sernums = []
    sernum = os.getenv('MYSERIALNUMBER')
    if sernum is not None:
        sernums.append(sernum.strip())
    cmdline = '/usr/sbin/ioreg -w 0 -r -c AppleAHCIDiskDriver -c AppleANS3NVMeController'
    cmdline = cmdline.encode(sys.getfilesystemencoding())
    p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         close_fds=False)
    out1, out2 = p.communicate()
    # print out1
    reslst = out1.split(b'\n')
    cnt = len(reslst)
    for j in range(cnt):
        resline = reslst[j]
        pp = resline.find(b'\"Serial Number\" = \"')
        if pp >= 0:
            sernum = resline[pp + 19:-1]
            sernums.append(sernum.strip())
    return sernums


def get_disk_partition_names():
    names = []
    cmdline = '/sbin/mount'
    cmdline = cmdline.encode(sys.getfilesystemencoding())
    p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         close_fds=False)
    out1, out2 = p.communicate()
    reslst = out1.split(b'\n')
    cnt = len(reslst)
    for j in range(cnt):
        resline = reslst[j]
        if resline.startswith(b'/dev'):
            (devpart, mpath) = resline.split(b' on ')[:2]
            dpart = devpart[5:]
            names.append(dpart)
    return names


# uses a sub process to get the UUID of all disk partitions
def get_disk_partition_uuids():
    uuids = []
    uuidnum = os.getenv('MYUUIDNUMBER')
    if uuidnum is not None:
        uuids.append(uuidnum.strip())
    cmdline = '/usr/sbin/ioreg -l -S -w 0 -r -c AppleAHCIDiskDriver -c AppleANS3NVMeController'
    cmdline = cmdline.encode(sys.getfilesystemencoding())
    p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         close_fds=False)
    out1, out2 = p.communicate()
    # print out1
    reslst = out1.split(b'\n')
    cnt = len(reslst)
    for j in range(cnt):
        resline = reslst[j]
        pp = resline.find(b'\"UUID\" = \"')
        if pp >= 0:
            uuidnum = resline[pp + 10:-1]
            uuidnum = uuidnum.strip()
            uuids.append(uuidnum)
    return uuids


def get_mac_addresses_munged():
    macnums = []
    macnum = os.getenv('MYMACNUM')
    if macnum is not None:
        macnums.append(macnum)
    cmdline = '/usr/sbin/networksetup -listallhardwareports'  # en0'
    cmdline = cmdline.encode(sys.getfilesystemencoding())
    p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         close_fds=False)
    out1, out2 = p.communicate()
    reslst = out1.split(b'\n')
    cnt = len(reslst)
    for j in range(cnt):
        resline = reslst[j]
        pp = resline.find(b'Ethernet Address: ')
        if pp >= 0:
            # print resline
            macnum = resline[pp + 18:]
            macnum = macnum.strip()
            maclst = macnum.split(b':')
            n = len(maclst)
            if n != 6:
                continue
            # print 'original mac', macnum
            # now munge it up the way Kindle app does
            # by xoring it with 0xa5 and swapping elements 3 and 4
            for i in range(6):
                # noinspection PyTypeChecker
                maclst[i] = int(b'0x' + maclst[i], 0)
            mlst = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            # noinspection PyTypeChecker
            mlst[5] = maclst[5] ^ 0xa5
            # noinspection PyTypeChecker
            mlst[4] = maclst[3] ^ 0xa5
            # noinspection PyTypeChecker
            mlst[3] = maclst[4] ^ 0xa5
            # noinspection PyTypeChecker
            mlst[2] = maclst[2] ^ 0xa5
            # noinspection PyTypeChecker
            mlst[1] = maclst[1] ^ 0xa5
            # noinspection PyTypeChecker
            mlst[0] = maclst[0] ^ 0xa5
            macnum = b'%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x' % (mlst[0], mlst[1], mlst[2], mlst[3], mlst[4], mlst[5])
            # print 'munged mac', macnum
            macnums.append(macnum)
    return macnums


def get_id_strings():
    # Return all possible ID Strings
    strings = []
    strings.extend(get_mac_addresses_munged())
    strings.extend(get_volumes_serial_numbers())
    strings.extend(get_disk_partition_names())
    strings.extend(get_disk_partition_uuids())
    strings.append(b'9999999999')
    # print "ID Strings:\n",strings
    return strings


class KindleKeyMacOS(KindleKey):
    def __init__(self):
        print("KindleKeyMacOS")

    # uses unix env to get username instead of using sysctlbyname
    def get_username(self):
        username = os.getenv('USER')
        # print "Username:",username
        return username.encode('utf-8')

    def get_kindle_info_files(self):
        # file searches can take a long time on some systems, so just look in known specific places.
        k_info_files = []
        found = False
        home = os.getenv('HOME')
        # check for  .kinf2018 file in new location (App Store Kindle for Mac)
        testpath = home + '/Library/Containers/com.amazon.Kindle/Data/Library/Application Support/Kindle/storage/.kinf2018'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac kinf2018 file: ' + testpath)
            found = True
        # check for  .kinf2018 files
        testpath = home + '/Library/Application Support/Kindle/storage/.kinf2018'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac kinf2018 file: ' + testpath)
            found = True
        # check for  .kinf2011 file in new location (App Store Kindle for Mac)
        testpath = home + '/Library/Containers/com.amazon.Kindle/Data/Library/Application Support/Kindle/storage/.kinf2011'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac kinf2011 file: ' + testpath)
            found = True
        # check for  .kinf2011 files from 1.10
        testpath = home + '/Library/Application Support/Kindle/storage/.kinf2011'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac kinf2011 file: ' + testpath)
            found = True
        # check for  .rainier-2.1.1-kinf files from 1.6
        testpath = home + '/Library/Application Support/Kindle/storage/.rainier-2.1.1-kinf'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac rainier file: ' + testpath)
            found = True
        # check for  .kindle-info files from 1.4
        testpath = home + '/Library/Application Support/Kindle/storage/.kindle-info'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac kindle-info file: ' + testpath)
            found = True
        # check for  .kindle-info file from 1.2.2
        testpath = home + '/Library/Application Support/Amazon/Kindle/storage/.kindle-info'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac kindle-info file: ' + testpath)
            found = True
        # check for  .kindle-info file from 1.0 beta 1 (27214)
        testpath = home + '/Library/Application Support/Amazon/Kindle for Mac/storage/.kindle-info'
        if os.path.isfile(testpath):
            k_info_files.append(testpath)
            print('Found k4Mac kindle-info file: ' + testpath)
            found = True
        if not found:
            print('No k4Mac kindle-info/rainier/kinf2011 files have been found.')
        return k_info_files

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
        with open(k_info_file, 'rb') as infoReader:
            filedata = infoReader.read()

        data = filedata[:-1]
        # noinspection PyUnusedLocal
        items = data.split(b'/')
        id_strings = get_id_strings()
        print("trying username ", self.get_username(), " on file ", k_info_file)
        for id_string in id_strings:
            print("trying IDString:", id_string)
            # noinspection PyBroadException
            try:
                db = {}
                items = data.split(b'/')

                # the headerblob is the encrypted information needed to build the entropy string
                headerblob = items.pop(0)
                # print ("headerblob: ",headerblob)
                encrypted_value = self.decode(headerblob, charMap1)
                # print ("encryptedvalue: ",encryptedValue)
                cleartext = self.unprotect_header_data(encrypted_value)
                # print ("cleartext: ",cleartext)

                # now extract the pieces in the same way
                pattern = re.compile(
                    br'''\[Version:(\d+)]\[Build:(\d+)]\[Cksum:([^]]+)]\[Guid:([{}a-z0-9\-]+)]''', re.IGNORECASE)
                for m in re.finditer(pattern, cleartext):
                    version = int(m.group(1))
                    build = m.group(2)
                    guid = m.group(4)

                # print ("version",version)
                # print ("build",build)
                # print ("guid",guid,"\n")

                # noinspection PyUnboundLocalVariable
                if version == 5:  # .kinf2011: identical to K4PC, except the build number gets multiplied
                    # noinspection PyUnboundLocalVariable
                    entropy = str(0x2df * int(build)).encode('utf-8') + guid
                    cud = CryptUnprotectData(self, entropy, id_string)
                    # print ("entropy",entropy)
                    # print ("cud",cud)

                elif version == 6:  # .kinf2018: identical to K4PC
                    salt = str(0x6d8 * int(build)).encode('utf-8') + guid
                    sp = self.get_username() + b'+@#$%+' + id_string
                    passwd = self.encode(self.sha256(sp), charMap5)
                    key = PBKDF2(passwd, salt, count=10000, dkLen=0x400)[:32]

                    # print ("salt",salt)
                    # print ("sp",sp)
                    # print ("passwd",passwd)
                    # print ("key",key)

                # loop through the item records until all are processed
                while len(items) > 0:

                    # get the first item record
                    item = items.pop(0)

                    # the first 32 chars of the first record of a group
                    # is the MD5 hash of the key name encoded by charMap5
                    keyhash = item[0:32]
                    # noinspection PyUnusedLocal
                    keyname = b'unknown'

                    # unlike K4PC the keyhash is not used in generating entropy
                    # entropy = SHA1(keyhash) + added_entropy
                    # entropy = added_entropy

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

                    keyname = b'unknown'
                    for name in names:
                        if self.encode_hash(name, testMap8) == keyhash:
                            keyname = name
                            break
                    if keyname == b'unknown':
                        keyname = keyhash

                    # the testMap8 encoded contents data has had a length
                    # of chars (always odd) cut off of the front and moved
                    # to the end to prevent decoding using testMap8 from
                    # working properly, and thereby preventing the ensuing
                    # CryptUnprotectData call from succeeding.

                    # The offset into the testMap8 encoded contents seems to be:
                    # len(contents) - largest prime number less than or equal to int(len(content)/3)
                    # (in other words split 'about' 2/3rds of the way through)

                    # move first offsets chars to end to align for decode by testMap8
                    encdata = b''.join(edlst)
                    contlen = len(encdata)

                    # now properly split and recombine
                    # by moving noffset chars from the start of the
                    # string to the end of the string
                    noffset = contlen - self.primes(int(contlen / 3))[-1]
                    pfx = encdata[0:noffset]
                    encdata = encdata[noffset:]
                    encdata = encdata + pfx

                    # noinspection PyUnboundLocalVariable
                    if version == 5:
                        # decode using testMap8 to get the CryptProtect Data
                        encrypted_value = self.decode(encdata, testMap8)
                        # noinspection PyUnboundLocalVariable
                        cleartext = cud.decrypt(self, encrypted_value)

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

                    # print keyname
                    # print cleartext
                    if len(cleartext) > 0:
                        db[keyname] = cleartext

                if len(db) > 6:
                    break

            except Exception:
                print(traceback.format_exc())
                pass
        # noinspection PyUnboundLocalVariable
        if len(db) > 6:
            # store values used in decryption
            # noinspection PyUnboundLocalVariable
            print("Decrypted key file using IDString '{0:s}' and UserName '{1:s}'".format(id_string.decode('utf-8'),
                                                                                          self.get_username().decode(
                                                                                              'utf-8')))
            db[b'IDString'] = id_string
            db[b'UserName'] = self.get_username()
        else:
            print("Couldn't decrypt file.")
            db = {}
        return db
