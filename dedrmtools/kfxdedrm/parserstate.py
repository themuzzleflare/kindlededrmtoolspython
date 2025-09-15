# coding=utf-8
#  Copyright © 2025 Paul Tavitian.

class ParserState:
    def __init__(self):
        pass

    Invalid, BeforeField, BeforeTID, BeforeValue, AfterValue, EOF = 1, 2, 3, 4, 5, 6
