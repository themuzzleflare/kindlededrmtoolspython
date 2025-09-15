# coding=utf-8
#  Copyright © 2025 Paul Tavitian.

from dedrmtools.kfxdedrm.ionutils import IonUtils
from dedrmtools.kfxdedrm.systemsymbols import SystemSymbols


class SymbolTable(object):
    table = None

    # noinspection PyTypeChecker
    def __init__(self):
        self.table = [None] * IonUtils.SID_ION_1_0_MAX
        self.table[IonUtils.SID_ION] = SystemSymbols.ION
        self.table[IonUtils.SID_ION_1_0] = SystemSymbols.ION_1_0
        self.table[IonUtils.SID_ION_SYMBOL_TABLE] = SystemSymbols.ION_SYMBOL_TABLE
        self.table[IonUtils.SID_NAME] = SystemSymbols.NAME
        self.table[IonUtils.SID_VERSION] = SystemSymbols.VERSION
        self.table[IonUtils.SID_IMPORTS] = SystemSymbols.IMPORTS
        self.table[IonUtils.SID_SYMBOLS] = SystemSymbols.SYMBOLS
        self.table[IonUtils.SID_MAX_ID] = SystemSymbols.MAX_ID
        self.table[IonUtils.SID_ION_SHARED_SYMBOL_TABLE] = SystemSymbols.ION_SHARED_SYMBOL_TABLE

    def findbyid(self, sid):
        if sid < 1:
            raise ValueError("Invalid symbol id")

        if sid < len(self.table):
            return self.table[sid]
        else:
            return ""

    def import_(self, table, maxid):
        for i in range(maxid):
            self.table.append(table.symnames[i])

    def importunknown(self, name, maxid):
        for i in range(maxid):
            # noinspection PyTypeChecker
            self.table.append("%s#%d" % (name, i + 1))
