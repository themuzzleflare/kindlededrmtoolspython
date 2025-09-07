#  Copyright © 2025 Paul Tavitian.

class ParserState:
    Invalid, BeforeField, BeforeTID, BeforeValue, AfterValue, EOF = 1, 2, 3, 4, 5, 6
