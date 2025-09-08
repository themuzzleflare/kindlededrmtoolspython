#  Copyright © 2025 Paul Tavitian.

import os
import shutil
import traceback
import zipfile

from io import BytesIO

__license__ = 'GPL v3'
__version__ = '2.0'

from dedrmtools.book import Book
from dedrmtools.kfxdedrm.drmion import DrmIon
from dedrmtools.kfxdedrm.drmionvoucher import DrmIonVoucher


class KFXZipBook(Book):
    def __init__(self, infile):
        self.infile = infile
        self.voucher = None
        self.decrypted = {}

    def get_pid_meta_info(self):
        return None, None

    def process_book(self, totalpids):
        with zipfile.ZipFile(self.infile, 'r') as zf:
            for filename in zf.namelist():
                with zf.open(filename) as fh:
                    data = fh.read(8)
                    if data != b'\xeaDRMION\xee':
                        continue
                    data += fh.read()
                    if self.voucher is None:
                        self.decrypt_voucher(totalpids)
                    print("Decrypting KFX DRMION: {0}".format(filename))
                    outfile = BytesIO()
                    DrmIon(BytesIO(data[8:-8]), lambda name: self.voucher).parse(outfile)
                    self.decrypted[filename] = outfile.getvalue()

        if not self.decrypted:
            print("The .kfx-zip archive does not contain an encrypted DRMION file")

    def decrypt_voucher(self, totalpids):
        with zipfile.ZipFile(self.infile, 'r') as zf:
            for info in zf.infolist():
                with zf.open(info.filename) as fh:
                    data = fh.read(4)
                    if data != b'\xe0\x01\x00\xea':
                        continue

                    data += fh.read()
                    if b'ProtectedData' in data:
                        break  # found DRM voucher
            else:
                raise Exception("The .kfx-zip archive contains an encrypted DRMION file without a DRM voucher")

        print("Decrypting KFX DRM voucher: {0}".format(info.filename))

        for pid in [''] + totalpids:
            # Belt and braces. PIDs should be unicode strings, but just in case...
            if isinstance(pid, bytes):
                pid = pid.decode('ascii')
            for dsn_len, secret_len in [(0, 0), (16, 0), (16, 40), (32, 0), (32, 40), (40, 0), (40, 40)]:
                if len(pid) == dsn_len + secret_len:
                    break  # split pid into DSN and account secret
            else:
                continue

            # noinspection PyBroadException
            try:
                voucher = DrmIonVoucher(BytesIO(data), pid[:dsn_len], pid[dsn_len:])
                voucher.parse()
                voucher.decryptvoucher()
                break
            except:
                traceback.print_exc()
                pass
        else:
            raise Exception("Failed to decrypt KFX DRM voucher with any key")

        print("KFX DRM voucher successfully decrypted")

        license_type = voucher.getlicensetype()
        if license_type != "Purchase":
            # raise Exception(("This book is licensed as {0}. "
            #        'These tools are intended for use on purchased books.').format(license_type))
            print("Warning: This book is licensed as {0}. "
                  "These tools are intended for use on purchased books. Continuing ...".format(license_type))

        self.voucher = voucher

    def get_book_title(self):
        return os.path.splitext(os.path.split(self.infile)[1])[0]

    def get_book_extension(self):
        return '.kfx-zip'

    def get_book_type(self):
        return 'KFX-ZIP'

    def cleanup(self):
        pass

    def get_file(self, outpath):
        if not self.decrypted:
            shutil.copyfile(self.infile, outpath)
        else:
            with zipfile.ZipFile(self.infile, 'r') as zif:
                with zipfile.ZipFile(outpath, 'w') as zof:
                    for info in zif.infolist():
                        zof.writestr(info, self.decrypted.get(info.filename, zif.read(info.filename)))
