from __future__ import print_function

__version__ = '6.0'

#  Copyright © 2025 Paul Tavitian.

import getopt
import os
import sys
import traceback

from dedrmtools.book import Book
from dedrmtools.kindlekeys import kgenpids


class DrmException(Exception):
    pass


class TopazBook(Book):
    # noinspection PyUnusedLocal
    def __init__(self, filename):
        pass

    def get_pid_meta_info(self):
        return None, None

    def get_book_title(self):
        return ""

    def process_book(self, pidlst):
        pass

    def get_file(self, zipname):
        pass

    def get_book_type(self):
        return "Topaz"

    def get_book_extension(self):
        return ".htmlz"

    def cleanup(self):
        pass

    def get_svg_zip(self, zipname):
        pass


def usage(progname):
    print("Removes DRM protection from Topaz ebooks and extracts the contents")
    print("Usage:")
    print(
        "    {0} [-k <kindle.k4i>] [-p <comma separated PIDs>] [-s <comma separated Kindle serial numbers>] <infile> <outdir>".format(
            progname))


# Main
def cli_main():
    argv = sys.argv
    progname = os.path.basename(argv[0])
    print("TopazExtract v{0}.".format(__version__))

    try:
        opts, args = getopt.getopt(argv[1:], "k:p:s:x")
    except getopt.GetoptError as err:
        print("Error in options or arguments: {0}".format(err.args[0]))
        usage(progname)
        return 1
    if len(args) < 2:
        usage(progname)
        return 1

    infile = args[0]
    outdir = args[1]
    if not os.path.isfile(infile):
        print("Input File {0} Does Not Exist.".format(infile))
        return 1

    if not os.path.exists(outdir):
        print("Output Directory {0} Does Not Exist.".format(outdir))
        return 1

    k_database_files = []
    serials = []
    pids = []

    for o, a in opts:
        if o == '-k':
            if a is None:
                raise DrmException("Invalid parameter for -k")
            k_database_files.append(a)
        if o == '-p':
            if a is None:
                raise DrmException("Invalid parameter for -p")
            pids = a.split(',')
        if o == '-s':
            if a is None:
                raise DrmException("Invalid parameter for -s")
            serials = [serial.replace(" ", "") for serial in a.split(',')]

    bookname = os.path.splitext(os.path.basename(infile))[0]

    tb = TopazBook(infile)
    title = tb.get_book_title()
    print("Processing Book: {0}".format(title))
    md1, md2 = tb.get_pid_meta_info()
    pids.extend(kgenpids.get_pid_list(md1, md2, serials, k_database_files))

    # noinspection PyBroadException
    try:
        print("Decrypting Book")
        tb.process_book(pids)

        print("   Creating HTML ZIP Archive")
        zipname = os.path.join(outdir, bookname + "_nodrm.htmlz")
        tb.get_file(zipname)

        print("   Creating SVG ZIP Archive")
        zipname = os.path.join(outdir, bookname + "_SVG.zip")
        tb.get_svg_zip(zipname)

        # removing internal temporary directory of pieces
        tb.cleanup()

    except DrmException:
        print("Decryption failed\n{0}".format(traceback.format_exc()))

        # noinspection PyBroadException
        try:
            tb.cleanup()
        except:
            pass
        return 1

    except Exception:
        print("Decryption failed\n{0}".format(traceback.format_exc()))
        # noinspection PyBroadException
        try:
            tb.cleanup()
        except:
            pass
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(cli_main())
