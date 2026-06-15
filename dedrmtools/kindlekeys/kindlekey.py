# coding=utf-8
__license__ = 'GPL v3'
__version__ = '3.1'

#  Copyright © 2026 Paul Tavitian.

import getopt
import json
import os
import sys

from dedrmtools.kindlekeys.kindlekeygen import KindleKey


#  Copyright © 2025 Paul Tavitian.

class DrmException(Exception):
    pass


def usage(progname):
    print("Finds, decrypts and saves the default Kindle For Mac/PC encryption keys.")
    print("Keys are saved to the current directory, or a specified output directory.")
    print("If a file name is passed instead of a directory, only the first key is saved, in that file.")
    print("Usage:")
    print("    {0:s} [-h] [-k <kindle.info>] [<outpath>]".format(progname))


def cli_main():
    argv = sys.argv
    progname = os.path.basename(argv[0])
    print("{0} v{1}\nCopyright © 2010-2020 by some_updates, Apprentice Harper et al.".format(progname, __version__))

    try:
        opts, args = getopt.getopt(argv[1:], "hk:")
    except getopt.GetoptError as err:
        print("Error in options or arguments: {0}".format(err.args[0]))
        usage(progname)
        sys.exit(2)

    files = []
    # noinspection PyUnboundLocalVariable
    for o, a in opts:
        if o == "-h":
            usage(progname)
            sys.exit(0)
        if o == "-k":
            files = [a]

    # noinspection PyUnboundLocalVariable
    if len(args) > 1:
        usage(progname)
        sys.exit(2)

    if len(args) == 1:
        # save to the specified file or directory
        outpath = args[0]
        if not os.path.isabs(outpath):
            outpath = os.path.abspath(outpath)
    else:
        # save to the same directory as the script
        outpath = os.path.dirname(argv[0])

    # make sure the outpath is canonical
    outpath = os.path.realpath(os.path.normpath(outpath))

    if not KindleKey.get_instance().getkey(outpath, files):
        print("Could not retrieve Kindle for Mac/PC key.")
    return 0


def gui_main():
    try:
        # noinspection PyCompatibility
        import tkinter
        # noinspection PyCompatibility
        import tkinter.constants
        # noinspection PyCompatibility
        import tkinter.messagebox
        import traceback
    except ImportError:
        return cli_main()

    class ExceptionDialog(tkinter.Frame):
        # noinspection PyShadowingNames
        def __init__(self, root, text):
            tkinter.Frame.__init__(self, root, border=5)
            # noinspection PyTypeChecker
            label = tkinter.Label(self, text="Unexpected error:",
                                  anchor=tkinter.constants.W, justify=tkinter.constants.LEFT)
            # noinspection PyTypeChecker
            label.pack(fill=tkinter.constants.X, expand=0)
            self.text = tkinter.Text(self)
            # noinspection PyTypeChecker
            self.text.pack(fill=tkinter.constants.BOTH, expand=1)

            self.text.insert(tkinter.constants.END, text)

    argv = sys.argv
    root = tkinter.Tk()
    root.withdraw()
    progpath, progname = os.path.split(argv[0])
    success = False
    # noinspection PyBroadException
    try:
        keys = KindleKey.get_instance().kindlekeys()
        keycount = 0
        for key in keys:
            while True:
                keycount += 1
                outfile = os.path.join(progpath, "kindlekey{0:d}.k4i".format(keycount))
                if not os.path.exists(outfile):
                    break

            with open(outfile, 'w') as keyfileout:
                keyfileout.write(json.dumps(key))
            success = True
            tkinter.messagebox.showinfo(progname, "Key successfully retrieved to {0}".format(outfile))
    except DrmException as e:
        tkinter.messagebox.showerror(progname, "Error: {0}".format(str(e)))
    except Exception:
        root.wm_state('normal')
        root.title(progname)
        text = traceback.format_exc()
        # noinspection PyTypeChecker
        ExceptionDialog(root, text).pack(fill=tkinter.constants.BOTH, expand=1)
        root.mainloop()
    if not success:
        return 1
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(cli_main())
    sys.exit(gui_main())
