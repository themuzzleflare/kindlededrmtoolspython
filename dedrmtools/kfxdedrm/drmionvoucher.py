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

        # pyrefly: ignore [missing-attribute]
        self.lockparams.sort()
        # pyrefly: ignore [not-iterable]
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
            # pyrefly: ignore [bad-raise]
            raise lastexception

        # pyrefly: ignore [missing-attribute]
        self.drmkey.stepin()
        # pyrefly: ignore [missing-attribute]
        while self.drmkey.hasnext():
            # pyrefly: ignore [missing-attribute]
            self.drmkey.next()
            # pyrefly: ignore [missing-attribute]
            if self.drmkey.gettypename() != "com.amazon.drm.SecretKey@1.0":
                continue

            # pyrefly: ignore [missing-attribute]
            self.drmkey.stepin()
            # pyrefly: ignore [missing-attribute]
            while self.drmkey.hasnext():
                # pyrefly: ignore [missing-attribute]
                self.drmkey.next()
                # pyrefly: ignore [missing-attribute]
                if self.drmkey.getfieldname() == "algorithm":
                    # pyrefly: ignore [missing-attribute]
                    _assert(self.drmkey.stringvalue() == "AES",
                            # pyrefly: ignore [missing-attribute]
                            "Unknown cipher algorithm: %s" % self.drmkey.stringvalue())
                # pyrefly: ignore [missing-attribute]
                elif self.drmkey.getfieldname() == "format":
                    # pyrefly: ignore [missing-attribute]
                    _assert(self.drmkey.stringvalue() == "RAW", "Unknown key format: %s" % self.drmkey.stringvalue())
                # pyrefly: ignore [missing-attribute]
                elif self.drmkey.getfieldname() == "encoded":
                    # pyrefly: ignore [missing-attribute]
                    self.secretkey = self.drmkey.lobvalue()

            # pyrefly: ignore [missing-attribute]
            self.drmkey.stepout()
            break

        # pyrefly: ignore [missing-attribute]
        self.drmkey.stepout()

    def parse(self):
        # pyrefly: ignore [missing-attribute]
        self.envelope.reset()
        # pyrefly: ignore [missing-attribute]
        _assert(self.envelope.hasnext(), "Envelope is empty")
        # pyrefly: ignore [missing-attribute]
        _assert(self.envelope.next() == IonUtils.TID_STRUCT and str.startswith(self.envelope.gettypename(),
                                                                               "com.amazon.drm.VoucherEnvelope@"),
                "Unknown type encountered in envelope, expected VoucherEnvelope")
        # pyrefly: ignore [missing-attribute]
        self.version = int(self.envelope.gettypename().split('@')[1][:-2])

        # pyrefly: ignore [missing-attribute]
        self.envelope.stepin()
        # pyrefly: ignore [missing-attribute]
        while self.envelope.hasnext():
            # pyrefly: ignore [missing-attribute]
            self.envelope.next()
            # pyrefly: ignore [missing-attribute]
            field = self.envelope.getfieldname()
            if field == "voucher":
                # pyrefly: ignore [missing-attribute]
                self.voucher = BinaryIonParser(BytesIO(self.envelope.lobvalue()))
                IonUtils.addprottable(self.voucher)
                continue
            elif field != "strategy":
                continue

            # pyrefly: ignore [missing-attribute]
            _assert(self.envelope.gettypename() == "com.amazon.drm.PIDv3@1.0",
                    # pyrefly: ignore [missing-attribute]
                    "Unknown strategy: %s" % self.envelope.gettypename())

            # pyrefly: ignore [missing-attribute]
            self.envelope.stepin()
            # pyrefly: ignore [missing-attribute]
            while self.envelope.hasnext():
                # pyrefly: ignore [missing-attribute]
                self.envelope.next()
                # pyrefly: ignore [missing-attribute]
                field = self.envelope.getfieldname()
                if field == "encryption_algorithm":
                    # pyrefly: ignore [missing-attribute]
                    self.encalgorithm = self.envelope.stringvalue()
                elif field == "encryption_transformation":
                    # pyrefly: ignore [missing-attribute]
                    self.enctransformation = self.envelope.stringvalue()
                elif field == "hashing_algorithm":
                    # pyrefly: ignore [missing-attribute]
                    self.hashalgorithm = self.envelope.stringvalue()
                elif field == "lock_parameters":
                    # pyrefly: ignore [missing-attribute]
                    self.envelope.stepin()
                    # pyrefly: ignore [missing-attribute]
                    while self.envelope.hasnext():
                        # pyrefly: ignore [missing-attribute]
                        _assert(self.envelope.next() == IonUtils.TID_STRING, "Expected string list for lock_parameters")
                        # pyrefly: ignore [missing-attribute]
                        self.lockparams.append(self.envelope.stringvalue())
                        # pyrefly: ignore [missing-attribute]
                    self.envelope.stepout()

            # pyrefly: ignore [missing-attribute]
            self.envelope.stepout()

        self.parsevoucher()

    def parsevoucher(self):
        # pyrefly: ignore [missing-attribute]
        _assert(self.voucher.hasnext(), "Voucher is empty")
        _assert(
            # pyrefly: ignore [missing-attribute]
            self.voucher.next() == IonUtils.TID_STRUCT and self.voucher.gettypename() == "com.amazon.drm.Voucher@1.0",
            "Unknown type, expected Voucher")

        # pyrefly: ignore [missing-attribute]
        self.voucher.stepin()
        # pyrefly: ignore [missing-attribute]
        while self.voucher.hasnext():
            # pyrefly: ignore [missing-attribute]
            self.voucher.next()

            # pyrefly: ignore [missing-attribute]
            if self.voucher.getfieldname() == "cipher_iv":
                # pyrefly: ignore [missing-attribute]
                self.cipheriv = self.voucher.lobvalue()
            # pyrefly: ignore [missing-attribute]
            elif self.voucher.getfieldname() == "cipher_text":
                # pyrefly: ignore [missing-attribute]
                self.ciphertext = self.voucher.lobvalue()
            # pyrefly: ignore [missing-attribute]
            elif self.voucher.getfieldname() == "license":
                # pyrefly: ignore [missing-attribute]
                _assert(self.voucher.gettypename() == "com.amazon.drm.License@1.0",
                        # pyrefly: ignore [missing-attribute]
                        "Unknown license: %s" % self.voucher.gettypename())
                # pyrefly: ignore [missing-attribute]
                self.voucher.stepin()
                # pyrefly: ignore [missing-attribute]
                while self.voucher.hasnext():
                    # pyrefly: ignore [missing-attribute]
                    self.voucher.next()
                    # pyrefly: ignore [missing-attribute]
                    if self.voucher.getfieldname() == "license_type":
                        # pyrefly: ignore [missing-attribute]
                        self.license_type = self.voucher.stringvalue()
                # pyrefly: ignore [missing-attribute]
                self.voucher.stepout()

    def printenvelope(self, lst):
        # pyrefly: ignore [missing-attribute]
        self.envelope.print_(lst)

    def printkey(self, lst):
        if self.voucher is None:
            self.parse()
        if self.drmkey is None:
            self.decryptvoucher()

        # pyrefly: ignore [missing-attribute]
        # noinspection PyUnresolvedReferences
        self.drmkey.print_(lst)

    def printvoucher(self, lst):
        if self.voucher is None:
            self.parse()

        # pyrefly: ignore [missing-attribute]
        # noinspection PyUnresolvedReferences
        self.voucher.print_(lst)

    def getlicensetype(self):
        return self.license_type
