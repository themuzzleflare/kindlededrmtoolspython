# coding=utf-8
__license__ = 'GPL v3'
__version__ = '6.0'

#  Copyright © 2025 Paul Tavitian.

import getopt
import os
import re
import sys
import time
import traceback

from dedrmtools.kfxdedrm.kfxdedrm import KFXZipBook
from dedrmtools.mobidedrm.mobidedrm import MobiBook
from dedrmtools.topazextract.topazextract import TopazBook
from kindlekeys import kgenpids

try:
    import html.entities as htmlentitydefs
except ImportError:
    # noinspection PyUnresolvedReferences
    import htmlentitydefs

import json


class DrmException(Exception):
    pass


# cleanup unicode filenames
# borrowed from calibre from calibre/src/calibre/__init__.py
# added in removal of control (<32) chars
# and removal of . at start and end
# and with some (heavily edited) code from Paul Durrant's kindlenamer.py
# and some improvements suggested by jhaisley
def cleanup_name(name):
    # substitute filename unfriendly characters
    name = name.replace("<", "[").replace(">", "]").replace(" : ", " – ").replace(": ", " – ").replace(":",
                                                                                                       "—").replace("/",
                                                                                                                    "_").replace(
        "\\", "_").replace("|", "_").replace("\"", "\'").replace("*", "_").replace("?", "")
    # white space to single space, delete leading and trailing while space
    name = re.sub(r"\s", " ", name).strip()
    # delete control characters
    name = "".join(char for char in name if ord(char) >= 32)
    # delete non-ascii characters
    name = "".join(char for char in name if ord(char) <= 126)
    # remove leading dots
    while len(name) > 0 and name[0] == ".":
        name = name[1:]
    # remove trailing dots (Windows doesn't like them)
    while name.endswith("."):
        name = name[:-1]
    if len(name) == 0:
        name = "DecryptedBook"
    return name


# must be passed unicode
def unescape(text):
    def fixup(m):
        # noinspection PyShadowingNames
        text = m.group(0)
        if text[:2] == "&#":
            # character reference
            try:
                if text[:3] == "&#x":
                    return chr(int(text[3:-1], 16))
                else:
                    return chr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                # noinspection PyShadowingNames
                text = chr(htmlentitydefs.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text  # leave as is

    return re.sub("&#?\\w+;", fixup, text)


def get_decrypted_book(infile, k_databases, serials, pids, starttime=time.time()):
    # handle the obvious cases at the beginning
    if not os.path.isfile(infile):
        raise DrmException("Input file does not exist.")

    mobi = True
    magic8 = open(infile, 'rb').read(8)
    if magic8 == b'\xeaDRMION\xee':
        raise DrmException(
            "The .kfx DRMION file cannot be decrypted by itself. A .kfx-zip archive containing a DRM voucher is required.")

    magic3 = magic8[:3]
    if magic3 == b'TPZ':
        mobi = False

    if magic8[:4] == b'PK\x03\x04':
        mb = KFXZipBook(infile)
    elif mobi:
        mb = MobiBook(infile)
    else:
        mb = TopazBook(infile)

    # noinspection PyBroadException
    try:
        bookname = unescape(mb.get_book_title())
        print("Decrypting {1} ebook: {0}".format(bookname, mb.get_book_type()))
    except:
        print("Decrypting {0} ebook.".format(mb.get_book_type()))

    # copy list of pids
    totalpids = list(pids)
    # extend PID list with book-specific PIDs from seriala and kDatabases
    md1, md2 = mb.get_pid_meta_info()
    totalpids.extend(kgenpids.get_pid_list(md1, md2, serials, k_databases))
    # remove any duplicates
    totalpids = list(set(totalpids))
    print("Found {1:d} keys to try after {0:.1f} seconds".format(time.time() - starttime, len(totalpids)))
    # print totalpids

    try:
        mb.process_book(totalpids)
    except:
        mb.cleanup()
        raise

    print("Decryption succeeded after {0:.1f} seconds".format(time.time() - starttime))
    return mb


# kDatabaseFiles is a list of files created by kindlekey
def decrypt_book(infile, outdir, k_database_files, serials, pids):
    starttime = time.time()
    k_databases = []
    for dbfile in k_database_files:
        kindle_database = {}
        try:
            with open(dbfile, 'r') as keyfilein:
                kindle_database = json.loads(keyfilein.read())
            k_databases.append([dbfile, kindle_database])
        except Exception as e:
            print("Error getting database from file {0:s}: {1:s}".format(dbfile, e))
            traceback.print_exc()

    try:
        book = get_decrypted_book(infile, k_databases, serials, pids, starttime)
    except Exception as e:
        print("Error decrypting book after {1:.1f} seconds: {0}".format(e.args[0], time.time() - starttime))
        traceback.print_exc()
        return 1

    # Try to infer a reasonable name
    orig_fn_root = os.path.splitext(os.path.basename(infile))[0]
    if (
            re.match('^B[A-Z0-9]{9}(_EBOK|_EBSP|_sample)?$', orig_fn_root) or
            re.match('^[0-9A-F-]{36}$', orig_fn_root)
    ):  # Kindle for PC / Mac / Android / Fire / iOS
        clean_title = cleanup_name(book.get_book_title())
        outfilename = "{}_{}".format(orig_fn_root, clean_title)
    else:  # E Ink Kindle, which already uses a reasonable name
        outfilename = orig_fn_root

    # avoid excessively long file names
    if len(outfilename) > 150:
        outfilename = outfilename[:99] + "--" + outfilename[-49:]

    outfilename = outfilename + "_nodrm"
    outfile = os.path.join(outdir, outfilename + book.get_book_extension())

    book.get_file(outfile)
    print("Saved decrypted book {1:s} after {0:.1f} seconds".format(time.time() - starttime, outfilename))

    if isinstance(book, TopazBook):
        zipname = os.path.join(outdir, outfilename + "_SVG.zip")
        # noinspection PyUnresolvedReferences
        book.get_svg_zip(zipname)
        print("Saved SVG ZIP Archive for {1:s} after {0:.1f} seconds".format(time.time() - starttime, outfilename))

    # remove internal temporary directory of Topaz pieces
    book.cleanup()
    return 0


def usage(progname):
    print("Removes DRM protection from Mobipocket, Amazon KF8, Amazon Print Replica and Amazon Topaz ebooks")
    print("Usage:")
    print(
        "    {0} [-k <kindle.k4i>] [-p <comma separated PIDs>] [-s <comma separated Kindle serial numbers>] <infile> <outdir>".format(
            progname))


#
# Main
#
def cli_main():
    argv = sys.argv
    progname = os.path.basename(argv[0])
    print("K4MobiDeDrm v{0}.\nCopyright © 2008-2020 Apprentice Harper et al.".format(__version__))

    try:
        opts, args = getopt.getopt(argv[1:], "k:p:s:h")
    except getopt.GetoptError as err:
        print("Error in options or arguments: {0}".format(err.args[0]))
        usage(progname)
        sys.exit(2)
    # noinspection PyUnboundLocalVariable
    if len(args) < 2:
        usage(progname)
        sys.exit(2)

    infile = args[0]
    outdir = args[1]
    k_database_files = []
    serials = []
    pids = []

    # noinspection PyUnboundLocalVariable
    for o, a in opts:
        if o == "-h":
            usage(progname)
            sys.exit(0)
        if o == "-k":
            if a is None:
                raise DrmException("Invalid parameter for -k")
            k_database_files.append(a)
        if o == "-p":
            if a is None:
                raise DrmException("Invalid parameter for -p")
            pids = a.encode('utf-8').split(b',')
        if o == "-s":
            if a is None:
                raise DrmException("Invalid parameter for -s")
            serials = a.split(',')

    return decrypt_book(infile, outdir, k_database_files, serials, pids)


if __name__ == '__main__':
    sys.exit(cli_main())
