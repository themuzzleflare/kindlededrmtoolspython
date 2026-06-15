# coding=utf-8
#  Copyright © 2025-2026 Paul Tavitian.

# common str:  "PIDv3AESAES/CBC/PKCS5PaddingHmacSHA256"
class Workspace(object):
    def __init__(self, initial_list):
        self.work = initial_list

    def shuffle(self, shuflist):
        ll = len(shuflist)
        rt = []
        for i in range(ll):
            rt.append(self.work[shuflist[i]])
        self.work = rt

    def sbox(self, table, matrix, skplist=None):  # table is list of 4-byte integers
        if skplist is None:
            skplist = []
        offset = 0
        nwork = list(self.work)
        wo = 0
        toff = 0
        while offset < 0x6000:
            uv5 = table[toff + nwork[wo + 0]]
            uv1 = table[toff + nwork[wo + 1] + 0x100]
            uv2 = table[toff + nwork[wo + 2] + 0x200]
            uv3 = table[toff + nwork[wo + 3] + 0x300]
            moff = 0
            if 0 in skplist:
                moff += 0x400
            else:
                nib1 = matrix[moff + offset + (uv1 >> 0x1c) | ((uv5 >> 0x18) & 0xf0)]
                moff += 0x100
                nib2 = matrix[moff + offset + (uv3 >> 0x1c) | ((uv2 >> 0x18) & 0xf0)]
                moff += 0x100
                nib3 = matrix[moff + offset + ((uv1 >> 0x18) & 0xf) | ((uv5 >> 0x14) & 0xf0)]
                moff += 0x100
                nib4 = matrix[moff + offset + ((uv3 >> 0x18) & 0xf) | ((uv2 >> 0x14) & 0xf0)]
                moff += 0x100
            # noinspection PyUnboundLocalVariable
            rnib1 = matrix[moff + offset + nib1 * 0x10 + nib2]
            moff += 0x100
            # noinspection PyUnboundLocalVariable
            rnib2 = matrix[moff + offset + nib3 * 0x10 + nib4]
            moff += 0x100
            nwork[wo + 0] = rnib1 * 0x10 + rnib2
            if 1 in skplist:
                moff += 0x400
            else:
                nib1 = matrix[moff + offset + ((uv1 >> 0x14) & 0xf) | ((uv5 >> 0x10) & 0xf0)]
                moff += 0x100
                nib2 = matrix[moff + offset + ((uv3 >> 0x14) & 0xf) | ((uv2 >> 0x10) & 0xf0)]
                moff += 0x100
                nib3 = matrix[moff + offset + ((uv1 >> 0x10) & 0xf) | ((uv5 >> 0xc) & 0xf0)]
                moff += 0x100
                nib4 = matrix[moff + offset + ((uv3 >> 0x10) & 0xf) | ((uv2 >> 0xc) & 0xf0)]
                moff += 0x100

            rnib1 = matrix[moff + offset + nib1 * 0x10 + nib2]
            moff += 0x100
            rnib2 = matrix[moff + offset + nib3 * 0x10 + nib4]
            moff += 0x100
            nwork[wo + 1] = rnib1 * 0x10 + rnib2
            if 2 in skplist:
                moff += 0x400
            else:
                nib1 = matrix[moff + offset + ((uv1 >> 0xc) & 0xf) | ((uv5 >> 0x8) & 0xf0)]
                moff += 0x100
                nib2 = matrix[moff + offset + ((uv3 >> 0xc) & 0xf) | ((uv2 >> 0x8) & 0xf0)]
                moff += 0x100
                nib3 = matrix[moff + offset + ((uv1 >> 0x8) & 0xf) | ((uv5 >> 0x4) & 0xf0)]
                moff += 0x100
                nib4 = matrix[moff + offset + ((uv3 >> 0x8) & 0xf) | ((uv2 >> 0x4) & 0xf0)]
                moff += 0x100
            rnib1 = matrix[moff + offset + nib1 * 0x10 + nib2]
            moff += 0x100
            rnib2 = matrix[moff + offset + nib3 * 0x10 + nib4]
            moff += 0x100
            nwork[wo + 2] = rnib1 * 0x10 + rnib2
            if 3 in skplist:
                moff += 0x400
            else:
                nib1 = matrix[moff + offset + ((uv1 >> 0x4) & 0xf) | (uv5 & 0xf0)]
                moff += 0x100
                nib2 = matrix[moff + offset + ((uv3 >> 0x4) & 0xf) | (uv2 & 0xf0)]
                moff += 0x100
                nib3 = matrix[moff + offset + (uv1 & 0xf) | ((uv5 << 4) & 0xf0)]
                moff += 0x100
                nib4 = matrix[moff + offset + (uv3 & 0xf) | ((uv2 << 4) & 0xf0)]
                moff += 0x100
            ##############
            rnib1 = matrix[moff + offset + nib1 * 0x10 + nib2]
            moff += 0x100
            rnib2 = matrix[moff + offset + nib3 * 0x10 + nib4]
            moff += 0x100
            nwork[wo + 3] = rnib1 * 0x10 + rnib2
            offset = offset + 0x1800
            wo += 4
            toff += 0x400
        self.work = nwork

    def lookup(self, ltable):
        for a in range(len(self.work)):
            self.work[a] = ltable[a]

    def exlookup(self, ltable):
        lookoffs = 0
        for a in range(len(self.work)):
            self.work[a] = ltable[self.work[a] + lookoffs]
            lookoffs += 0x100

    def mask(self, chunk):
        out = []
        for a in range(len(chunk)):
            self.work[a] = self.work[a] ^ chunk[a]
            out.append(self.work[a])
        return out
