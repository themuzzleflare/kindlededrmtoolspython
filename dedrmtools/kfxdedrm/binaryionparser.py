# coding=utf-8
#  Copyright © 2025-2026 Paul Tavitian.

import os
import os.path
import struct

__license__ = 'GPL v3'
__version__ = '3.0'

from dedrmtools.kfxdedrm.containerrec import ContainerRec
from dedrmtools.kfxdedrm.ioncatalogitem import IonCatalogItem
from dedrmtools.kfxdedrm.parserstate import ParserState
from dedrmtools.kfxdedrm.symboltable import SymbolTable
from dedrmtools.kfxdedrm.ionutils import *
from dedrmtools.kfxdedrm.symboltoken import SymbolToken
from dedrmtools.kfxdedrm.systemsymbols import SystemSymbols

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.py3compat import bchr
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Util.py3compat import bchr

try:
    # lzma library from calibre 4.6.0 or later
    import calibre_lzma.lzma1 as calibre_lzma
except ImportError:
    calibre_lzma = None
    # lzma library from calibre 2.35.0 or later
    try:
        import lzma.lzma1 as calibre_lzma
    except ImportError:
        calibre_lzma = None
        try:
            import lzma
        except ImportError:
            # Need pip backports.lzma on Python <3.3
            try:
                # noinspection PyPackageRequirements
                from backports import lzma
            except ImportError:
                # Windows-friendly choice: pylzma wheels
                # noinspection PyUnresolvedReferences,PyPackageRequirements
                import pylzma as lzma


# asserts must always raise exceptions for proper functioning
def _assert(test, msg="Exception"):
    if not test:
        raise Exception(msg)


class BinaryIonParser(object):
    eof = False
    state = None
    localremaining = 0
    needhasnext = False
    isinstruct = False
    valuetid = 0
    valuefieldid = 0
    parenttid = 0
    valuelen = 0
    valueisnull = False
    valueistrue = False
    value = None
    didimports = False

    def __init__(self, stream):
        self.annotations = []
        self.catalog = []

        self.stream = stream
        self.initpos = stream.tell()
        self.reset()
        self.symbols = SymbolTable()

    def reset(self):
        self.state = ParserState.BeforeTID
        self.needhasnext = True
        self.localremaining = -1
        self.eof = False
        self.isinstruct = False
        # noinspection PyAttributeOutsideInit
        self.containerstack = []
        self.stream.seek(self.initpos)

    def addtocatalog(self, name, version, symbols):
        self.catalog.append(IonCatalogItem(name, version, symbols))

    def hasnext(self):
        while self.needhasnext and not self.eof:
            self.hasnextraw()
            if len(self.containerstack) == 0 and not self.valueisnull:
                if self.valuetid == IonUtils.TID_SYMBOL:
                    if self.value == IonUtils.SID_ION_1_0:
                        self.needhasnext = True
                elif self.valuetid == IonUtils.TID_STRUCT:
                    for a in self.annotations:
                        if a == IonUtils.SID_ION_SYMBOL_TABLE:
                            self.parsesymboltable()
                            self.needhasnext = True
                            break
        return not self.eof

    def hasnextraw(self):
        self.clearvalue()
        while self.valuetid == -1 and not self.eof:
            self.needhasnext = False
            if self.state == ParserState.BeforeField:
                _assert(self.valuefieldid == IonUtils.SID_UNKNOWN)

                self.valuefieldid = self.readfieldid()
                if self.valuefieldid != IonUtils.SID_UNKNOWN:
                    self.state = ParserState.BeforeTID
                else:
                    self.eof = True

            elif self.state == ParserState.BeforeTID:
                self.state = ParserState.BeforeValue
                self.valuetid = self.readtypeid()
                if self.valuetid == -1:
                    self.state = ParserState.EOF
                    self.eof = True
                    break

                if self.valuetid == IonUtils.TID_TYPEDECL:
                    if self.valuelen == 0:
                        self.checkversionmarker()
                    else:
                        self.loadannotations()

            elif self.state == ParserState.BeforeValue:
                self.skip(self.valuelen)
                self.state = ParserState.AfterValue

            elif self.state == ParserState.AfterValue:
                if self.isinstruct:
                    self.state = ParserState.BeforeField
                else:
                    self.state = ParserState.BeforeTID

            else:
                _assert(self.state == ParserState.EOF)

    def next(self):
        if self.hasnext():
            self.needhasnext = True
            return self.valuetid
        else:
            return -1

    def push(self, typeid, nextposition, nextremaining):
        self.containerstack.append(ContainerRec(nextpos=nextposition, tid=typeid, remaining=nextremaining))

    def stepin(self):
        _assert(self.valuetid in [IonUtils.TID_STRUCT, IonUtils.TID_LIST, IonUtils.TID_SEXP] and not self.eof,
                "valuetid=%s eof=%s" % (self.valuetid, self.eof))
        _assert((not self.valueisnull or self.state == ParserState.AfterValue) and
                (self.valueisnull or self.state == ParserState.BeforeValue))

        nextrem = self.localremaining
        if nextrem != -1:
            nextrem -= self.valuelen
            if nextrem < 0:
                nextrem = 0
        self.push(self.parenttid, self.stream.tell() + self.valuelen, nextrem)

        self.isinstruct = (self.valuetid == IonUtils.TID_STRUCT)
        if self.isinstruct:
            self.state = ParserState.BeforeField
        else:
            self.state = ParserState.BeforeTID

        self.localremaining = self.valuelen
        self.parenttid = self.valuetid
        self.clearvalue()
        self.needhasnext = True

    def stepout(self):
        rec = self.containerstack.pop()

        self.eof = False
        self.parenttid = rec.tid
        if self.parenttid == IonUtils.TID_STRUCT:
            self.isinstruct = True
            self.state = ParserState.BeforeField
        else:
            self.isinstruct = False
            self.state = ParserState.BeforeTID
        self.needhasnext = True

        self.clearvalue()
        curpos = self.stream.tell()
        if rec.nextpos > curpos:
            self.skip(rec.nextpos - curpos)
        else:
            _assert(rec.nextpos == curpos)

        self.localremaining = rec.remaining

    def read(self, count=1):
        if self.localremaining != -1:
            self.localremaining -= count
            _assert(self.localremaining >= 0)

        result = self.stream.read(count)
        if len(result) == 0:
            raise EOFError()
        return result

    def readfieldid(self):
        if self.localremaining != -1 and self.localremaining < 1:
            return -1

        try:
            return self.readvaruint()
        except EOFError:
            return -1

    def readtypeid(self):
        if self.localremaining != -1:
            if self.localremaining < 1:
                return -1
            self.localremaining -= 1

        b = self.stream.read(1)
        if len(b) < 1:
            return -1
        b = ord(b)
        result = b >> 4
        ln = b & 0xF

        if ln == IonUtils.LEN_IS_VAR_LEN:
            ln = self.readvaruint()
        elif ln == IonUtils.LEN_IS_NULL:
            ln = 0
            self.state = ParserState.AfterValue
        elif result == IonUtils.TID_NULL:
            # Must have LEN_IS_NULL
            _assert(False)
        elif result == IonUtils.TID_BOOLEAN:
            _assert(ln <= 1)
            self.valueistrue = (ln == 1)
            ln = 0
            self.state = ParserState.AfterValue
        elif result == IonUtils.TID_STRUCT:
            if ln == 1:
                ln = self.readvaruint()

        self.valuelen = ln
        return result

    def readvarint(self):
        b = ord(self.read())
        negative = ((b & 0x40) != 0)
        result = (b & 0x3F)

        i = 0
        while (b & 0x80) == 0 and i < 4:
            b = ord(self.read())
            result = (result << 7) | (b & 0x7F)
            i += 1

        _assert(i < 4 or (b & 0x80) != 0, "int overflow")

        if negative:
            return -result
        return result

    def readvaruint(self):
        b = ord(self.read())
        result = (b & 0x7F)

        i = 0
        while (b & 0x80) == 0 and i < 4:
            b = ord(self.read())
            result = (result << 7) | (b & 0x7F)
            i += 1

        _assert(i < 4 or (b & 0x80) != 0, "int overflow")

        return result

    def readdecimal(self):
        if self.valuelen == 0:
            return 0.

        rem = self.localremaining - self.valuelen
        self.localremaining = self.valuelen
        exponent = self.readvarint()

        _assert(self.localremaining > 0, "Only exponent in ReadDecimal")
        _assert(self.localremaining <= 8, "Decimal overflow")

        signed = False
        b = [ord(x) for x in self.read(self.localremaining)]
        if (b[0] & 0x80) != 0:
            b[0] = b[0] & 0x7F
            signed = True

        # Convert variably sized network order integer into 64-bit little endian
        j = 0
        vb = [0] * 8
        for i in range(len(b), -1, -1):
            vb[i] = b[j]
            j += 1

        v = struct.unpack("<Q", b"".join(bchr(x) for x in vb))[0]

        result = v * (10 ** exponent)
        if signed:
            result = -result

        self.localremaining = rem
        return result

    def skip(self, count):
        if self.localremaining != -1:
            self.localremaining -= count
            if self.localremaining < 0:
                raise EOFError()

        self.stream.seek(count, os.SEEK_CUR)

    def parsesymboltable(self):
        self.next()  # shouldn't do anything?

        _assert(self.valuetid == IonUtils.TID_STRUCT)

        if self.didimports:
            return

        self.stepin()

        fieldtype = self.next()
        while fieldtype != -1:
            if not self.valueisnull:
                _assert(self.valuefieldid == IonUtils.SID_IMPORTS, "Unsupported symbol table field id")

                if fieldtype == IonUtils.TID_LIST:
                    self.gatherimports()

            fieldtype = self.next()

        self.stepout()
        self.didimports = True

    def gatherimports(self):
        self.stepin()

        t = self.next()
        while t != -1:
            if not self.valueisnull and t == IonUtils.TID_STRUCT:
                self.readimport()

            t = self.next()

        self.stepout()

    def readimport(self):
        version = -1
        maxid = -1
        name = ""

        self.stepin()

        t = self.next()
        while t != -1:
            if not self.valueisnull and self.valuefieldid != IonUtils.SID_UNKNOWN:
                if self.valuefieldid == IonUtils.SID_NAME:
                    name = self.stringvalue()
                elif self.valuefieldid == IonUtils.SID_VERSION:
                    version = self.intvalue()
                elif self.valuefieldid == IonUtils.SID_MAX_ID:
                    maxid = self.intvalue()

            t = self.next()

        self.stepout()

        if name == "" or name == SystemSymbols.ION:
            return

        if version < 1:
            version = 1

        table = self.findcatalogitem(name)
        if maxid < 0:
            _assert(table is not None and version == table.version, "Import %s lacks maxid" % name)
            maxid = len(table.symnames)

        if table is not None:
            self.symbols.import_(table, min(maxid, len(table.symnames)))
            if len(table.symnames) < maxid:
                self.symbols.importunknown(name + "-unknown", maxid - len(table.symnames))
        else:
            self.symbols.importunknown(name, maxid)

    def intvalue(self):
        _assert(self.valuetid in [IonUtils.TID_POSINT, IonUtils.TID_NEGINT], "Not an int")

        self.preparevalue()
        return self.value

    def stringvalue(self):
        _assert(self.valuetid == IonUtils.TID_STRING, "Not a string")

        if self.valueisnull:
            return ""

        self.preparevalue()
        return self.value

    def symbolvalue(self):
        _assert(self.valuetid == IonUtils.TID_SYMBOL, "Not a symbol")

        self.preparevalue()
        result = self.symbols.findbyid(self.value)
        if result == "":
            # noinspection PyStringFormat
            result = "SYMBOL#%d" % self.value
        return result

    def lobvalue(self):
        _assert(self.valuetid in [IonUtils.TID_CLOB, IonUtils.TID_BLOB], "Not a LOB type: %s" % self.getfieldname())

        if self.valueisnull:
            return None

        result = self.read(self.valuelen)
        self.state = ParserState.AfterValue
        return result

    def decimalvalue(self):
        _assert(self.valuetid == IonUtils.TID_DECIMAL, "Not a decimal")

        self.preparevalue()
        return self.value

    def preparevalue(self):
        if self.value is None:
            self.loadscalarvalue()

    def loadscalarvalue(self):
        if self.valuetid not in [IonUtils.TID_NULL, IonUtils.TID_BOOLEAN, IonUtils.TID_POSINT, IonUtils.TID_NEGINT,
                                 IonUtils.TID_FLOAT, IonUtils.TID_DECIMAL, IonUtils.TID_TIMESTAMP,
                                 IonUtils.TID_SYMBOL, IonUtils.TID_STRING]:
            return

        if self.valueisnull:
            self.value = None
            return

        if self.valuetid == IonUtils.TID_STRING:
            self.value = self.read(self.valuelen).decode("UTF-8")

        elif self.valuetid in (IonUtils.TID_POSINT, IonUtils.TID_NEGINT, IonUtils.TID_SYMBOL):
            if self.valuelen == 0:
                self.value = 0
            else:
                _assert(self.valuelen <= 4, "int too long: %d" % self.valuelen)
                v = 0
                for i in range(self.valuelen - 1, -1, -1):
                    v = (v | (ord(self.read()) << (i * 8)))

                if self.valuetid == IonUtils.TID_NEGINT:
                    self.value = -v
                else:
                    self.value = v

        elif self.valuetid == IonUtils.TID_DECIMAL:
            self.value = self.readdecimal()

        # else:
        #    _assert(False, "Unhandled scalar type %d" % self.valuetid)

        self.state = ParserState.AfterValue

    def clearvalue(self):
        self.valuetid = -1
        self.value = None
        self.valueisnull = False
        self.valuefieldid = IonUtils.SID_UNKNOWN
        self.annotations = []

    def loadannotations(self):
        ln = self.readvaruint()
        maxpos = self.stream.tell() + ln
        while self.stream.tell() < maxpos:
            self.annotations.append(self.readvaruint())
        self.valuetid = self.readtypeid()

    def checkversionmarker(self):
        for i in IonUtils.VERSION_MARKER:
            _assert(self.read() == i, "Unknown version marker")

        self.valuelen = 0
        self.valuetid = IonUtils.TID_SYMBOL
        self.value = IonUtils.SID_ION_1_0
        self.valueisnull = False
        self.valuefieldid = IonUtils.SID_UNKNOWN
        self.state = ParserState.AfterValue

    def findcatalogitem(self, name):
        for result in self.catalog:
            if result.name == name:
                return result
        return None

    def forceimport(self, symbols):
        item = IonCatalogItem("Forced", 1, symbols)
        self.symbols.import_(item, len(symbols))

    def getfieldname(self):
        if self.valuefieldid == IonUtils.SID_UNKNOWN:
            return ""
        return self.symbols.findbyid(self.valuefieldid)

    def getfieldnamesymbol(self):
        return SymbolToken(self.getfieldname(), self.valuefieldid)

    def gettypename(self):
        if len(self.annotations) == 0:
            return ""

        return self.symbols.findbyid(self.annotations[0])

    @staticmethod
    def printlob(b):
        if b is None:
            return "null"

        result = ""
        for i in b:
            result += ("%02x " % ord(i))

        if len(result) > 0:
            result = result[:-1]
        return result

    def ionwalk(self, supert, indent, lst):
        while self.hasnext():
            if supert == IonUtils.TID_STRUCT:
                l = self.getfieldname() + ":"
            else:
                l = ""

            t = self.next()
            if t in [IonUtils.TID_STRUCT, IonUtils.TID_LIST]:
                if l != "":
                    lst.append(indent + l)
                l = self.gettypename()
                if l != "":
                    lst.append(indent + l + "::")
                if t == IonUtils.TID_STRUCT:
                    lst.append(indent + "{")
                else:
                    lst.append(indent + "[")

                self.stepin()
                self.ionwalk(t, indent + "  ", lst)
                self.stepout()

                if t == IonUtils.TID_STRUCT:
                    lst.append(indent + "}")
                else:
                    lst.append(indent + "]")

            else:
                if t == IonUtils.TID_STRING:
                    l += ('"%s"' % self.stringvalue())
                elif t in [IonUtils.TID_CLOB, IonUtils.TID_BLOB]:
                    l += ("{%s}" % self.printlob(self.lobvalue()))
                elif t == IonUtils.TID_POSINT:
                    l += str(self.intvalue())
                elif t == IonUtils.TID_SYMBOL:
                    tn = self.gettypename()
                    if tn != "":
                        tn += "::"
                    l += tn + self.symbolvalue()
                elif t == IonUtils.TID_DECIMAL:
                    l += str(self.decimalvalue())
                else:
                    l += ("TID %d" % t)
                lst.append(indent + l)

    def print_(self, lst):
        self.reset()
        self.ionwalk(-1, "", lst)
