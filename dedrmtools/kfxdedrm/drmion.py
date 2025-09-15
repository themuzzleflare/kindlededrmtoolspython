# coding=utf-8
#  Copyright © 2025 Paul Tavitian.

# noinspection PyCompatibility
import lzma

try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES

from dedrmtools.kfxdedrm.binaryionparser import BinaryIonParser
from dedrmtools.kfxdedrm.ionutils import IonUtils


# asserts must always raise exceptions for proper functioning
def _assert(test, msg="Exception"):
    if not test:
        raise Exception(msg)


class DrmIon(object):
    ion = None
    voucher = None
    vouchername = ""
    key = b""
    onvoucherrequired = None

    def __init__(self, ionstream, onvoucherrequired):
        self.ion = BinaryIonParser(ionstream)
        IonUtils.addprottable(self.ion)
        self.onvoucherrequired = onvoucherrequired

    def parse(self, outpages):
        self.ion.reset()

        _assert(self.ion.hasnext(), "DRMION envelope is empty")
        _assert(self.ion.next() == IonUtils.TID_SYMBOL and self.ion.gettypename() == "doctype",
                "Expected doctype symbol")
        _assert(self.ion.next() == IonUtils.TID_LIST and self.ion.gettypename() in ["com.amazon.drm.Envelope@1.0",
                                                                                    "com.amazon.drm.Envelope@2.0"],
                "Unknown type encountered in DRMION envelope, expected Envelope, got %s" % self.ion.gettypename())

        while True:
            if self.ion.gettypename() == "enddoc":
                break

            self.ion.stepin()
            while self.ion.hasnext():
                self.ion.next()

                if self.ion.gettypename() in ["com.amazon.drm.EnvelopeMetadata@1.0",
                                              "com.amazon.drm.EnvelopeMetadata@2.0"]:
                    self.ion.stepin()
                    while self.ion.hasnext():
                        self.ion.next()
                        if self.ion.getfieldname() != "encryption_voucher":
                            continue

                        if self.vouchername == "":
                            self.vouchername = self.ion.stringvalue()
                            self.voucher = self.onvoucherrequired(self.vouchername)
                            self.key = self.voucher.secretkey
                            _assert(self.key is not None, "Unable to obtain secret key from voucher")
                        else:
                            _assert(self.vouchername == self.ion.stringvalue(),
                                    "Unexpected: Different vouchers required for same file?")

                    self.ion.stepout()

                elif self.ion.gettypename() in ["com.amazon.drm.EncryptedPage@1.0", "com.amazon.drm.EncryptedPage@2.0"]:
                    decompress = False
                    decrypt = True
                    ct = None
                    civ = None
                    self.ion.stepin()
                    while self.ion.hasnext():
                        self.ion.next()
                        if self.ion.gettypename() == "com.amazon.drm.Compressed@1.0":
                            decompress = True
                        if self.ion.getfieldname() == "cipher_text":
                            ct = self.ion.lobvalue()
                        elif self.ion.getfieldname() == "cipher_iv":
                            civ = self.ion.lobvalue()

                    if ct is not None and civ is not None:
                        self.processpage(ct, civ, outpages, decompress, decrypt)
                    self.ion.stepout()

                elif self.ion.gettypename() in ["com.amazon.drm.PlainText@1.0", "com.amazon.drm.PlainText@2.0"]:
                    decompress = False
                    decrypt = False
                    plaintext = None
                    self.ion.stepin()
                    while self.ion.hasnext():
                        self.ion.next()
                        if self.ion.gettypename() == "com.amazon.drm.Compressed@1.0":
                            decompress = True
                        if self.ion.getfieldname() == "data":
                            plaintext = self.ion.lobvalue()

                    if plaintext is not None:
                        self.processpage(plaintext, None, outpages, decompress, decrypt)
                    self.ion.stepout()

            self.ion.stepout()
            if not self.ion.hasnext():
                break
            self.ion.next()

    def print_(self, lst):
        self.ion.print_(lst)

    def processpage(self, ct, civ, outpages, decompress, decrypt):
        if decrypt:
            aes = AES.new(self.key[:16], AES.MODE_CBC, civ[:16])
            msg = IonUtils.pkcs7unpad(aes.decrypt(ct), 16)
        else:
            msg = ct

        if not decompress:
            outpages.write(msg)
            return

        _assert(msg[0] == 0, "LZMA UseFilter not supported")

        decomp = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        while not decomp.eof:
            segment = decomp.decompress(msg[1:])
            msg = b""  # Contents were internally buffered after the first call
            outpages.write(segment)
