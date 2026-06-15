# coding=utf-8
#  Copyright © 2025-2026 Paul Tavitian.

import hashlib
import hmac
from io import BytesIO

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


class DrmIonVoucher(object):
    envelope = None
    version = None
    voucher = None
    drmkey = None
    license_type = "Unknown"

    encalgorithm = ""
    enctransformation = ""
    hashalgorithm = ""

    lockparams = None

    ciphertext = b""
    cipheriv = b""
    secretkey = b""

    def __init__(self, voucherenv, dsn, secret):
        self.dsn, self.secret = dsn, secret

        if isinstance(dsn, str):
            self.dsn = dsn.encode('ASCII')

        if isinstance(secret, str):
            self.secret = secret.encode('ASCII')

        self.lockparams = []

        self.envelope = BinaryIonParser(voucherenv)
        IonUtils.addprottable(self.envelope)

    def decryptvoucher(self):
        shared = ("PIDv3" + self.encalgorithm + self.enctransformation + self.hashalgorithm).encode('ASCII')

        self.lockparams.sort()
        for param in self.lockparams:
            if param == "ACCOUNT_SECRET":
                shared += param.encode('ASCII') + self.secret
            elif param == "CLIENT_ID":
                shared += param.encode('ASCII') + self.dsn
            else:
                _assert(False, "Unknown lock parameter: %s" % param)

        # i know that version maps to scramble pretty much 1 to 1, but there was precendent where they changed it, so...
        sharedsecrets = [IonUtils.obfuscate(shared, self.version), IonUtils.obfuscate2(shared, self.version),
                         IonUtils.obfuscate3(shared, self.version),
                         IonUtils.process_v9708(shared), IonUtils.process_v1031(shared), IonUtils.process_v2069(shared),
                         IonUtils.process_v9041(shared),
                         IonUtils.process_v3646(shared), IonUtils.process_v6052(shared), IonUtils.process_v9479(shared),
                         IonUtils.process_v9888(shared),
                         IonUtils.process_v4648(shared), IonUtils.process_v5683(shared)]

        decrypted = False
        # noinspection PyUnresolvedReferences
        lastexception = None  # type: Exception | None
        for sharedsecret in sharedsecrets:
            key = hmac.new(sharedsecret, b"PIDv3", digestmod=hashlib.sha256).digest()
            aes = AES.new(key[:32], AES.MODE_CBC, self.cipheriv[:16])
            try:
                b = aes.decrypt(self.ciphertext)
                b = IonUtils.pkcs7unpad(b, 16)
                self.drmkey = BinaryIonParser(BytesIO(b))
                IonUtils.addprottable(self.drmkey)

                _assert(
                    self.drmkey.hasnext() and self.drmkey.next() == IonUtils.TID_LIST and self.drmkey.gettypename() == "com.amazon.drm.KeySet@1.0",
                    "Expected KeySet, got %s" % self.drmkey.gettypename())
                decrypted = True

                print("Decryption succeeded")
                break
            except Exception as ex:
                lastexception = ex
                print("Decryption failed, trying next fallback ")
        if not decrypted:
            raise lastexception

        self.drmkey.stepin()
        while self.drmkey.hasnext():
            self.drmkey.next()
            if self.drmkey.gettypename() != "com.amazon.drm.SecretKey@1.0":
                continue

            self.drmkey.stepin()
            while self.drmkey.hasnext():
                self.drmkey.next()
                if self.drmkey.getfieldname() == "algorithm":
                    _assert(self.drmkey.stringvalue() == "AES",
                            "Unknown cipher algorithm: %s" % self.drmkey.stringvalue())
                elif self.drmkey.getfieldname() == "format":
                    _assert(self.drmkey.stringvalue() == "RAW", "Unknown key format: %s" % self.drmkey.stringvalue())
                elif self.drmkey.getfieldname() == "encoded":
                    self.secretkey = self.drmkey.lobvalue()

            self.drmkey.stepout()
            break

        self.drmkey.stepout()

    def parse(self):
        self.envelope.reset()
        _assert(self.envelope.hasnext(), "Envelope is empty")
        _assert(self.envelope.next() == IonUtils.TID_STRUCT and str.startswith(self.envelope.gettypename(),
                                                                               "com.amazon.drm.VoucherEnvelope@"),
                "Unknown type encountered in envelope, expected VoucherEnvelope")
        self.version = int(self.envelope.gettypename().split('@')[1][:-2])

        self.envelope.stepin()
        while self.envelope.hasnext():
            self.envelope.next()
            field = self.envelope.getfieldname()
            if field == "voucher":
                self.voucher = BinaryIonParser(BytesIO(self.envelope.lobvalue()))
                IonUtils.addprottable(self.voucher)
                continue
            elif field != "strategy":
                continue

            _assert(self.envelope.gettypename() == "com.amazon.drm.PIDv3@1.0",
                    "Unknown strategy: %s" % self.envelope.gettypename())

            self.envelope.stepin()
            while self.envelope.hasnext():
                self.envelope.next()
                field = self.envelope.getfieldname()
                if field == "encryption_algorithm":
                    self.encalgorithm = self.envelope.stringvalue()
                elif field == "encryption_transformation":
                    self.enctransformation = self.envelope.stringvalue()
                elif field == "hashing_algorithm":
                    self.hashalgorithm = self.envelope.stringvalue()
                elif field == "lock_parameters":
                    self.envelope.stepin()
                    while self.envelope.hasnext():
                        _assert(self.envelope.next() == IonUtils.TID_STRING, "Expected string list for lock_parameters")
                        self.lockparams.append(self.envelope.stringvalue())
                    self.envelope.stepout()

            self.envelope.stepout()

        self.parsevoucher()

    def parsevoucher(self):
        _assert(self.voucher.hasnext(), "Voucher is empty")
        _assert(
            self.voucher.next() == IonUtils.TID_STRUCT and self.voucher.gettypename() == "com.amazon.drm.Voucher@1.0",
            "Unknown type, expected Voucher")

        self.voucher.stepin()
        while self.voucher.hasnext():
            self.voucher.next()

            if self.voucher.getfieldname() == "cipher_iv":
                self.cipheriv = self.voucher.lobvalue()
            elif self.voucher.getfieldname() == "cipher_text":
                self.ciphertext = self.voucher.lobvalue()
            elif self.voucher.getfieldname() == "license":
                _assert(self.voucher.gettypename() == "com.amazon.drm.License@1.0",
                        "Unknown license: %s" % self.voucher.gettypename())
                self.voucher.stepin()
                while self.voucher.hasnext():
                    self.voucher.next()
                    if self.voucher.getfieldname() == "license_type":
                        self.license_type = self.voucher.stringvalue()
                self.voucher.stepout()

    def printenvelope(self, lst):
        self.envelope.print_(lst)

    def printkey(self, lst):
        if self.voucher is None:
            self.parse()
        if self.drmkey is None:
            self.decryptvoucher()

        self.drmkey.print_(lst)

    def printvoucher(self, lst):
        if self.voucher is None:
            self.parse()

        self.voucher.print_(lst)

    def getlicensetype(self):
        return self.license_type
