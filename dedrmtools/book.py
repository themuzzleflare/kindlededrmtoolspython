#  Copyright © 2025 Paul Tavitian.

from abc import ABC, abstractmethod


class Book(ABC):
    @abstractmethod
    def cleanup(self):
        pass

    @abstractmethod
    def get_book_title(self) -> str:
        pass

    @abstractmethod
    def get_book_extension(self) -> str:
        pass

    @abstractmethod
    def get_pid_meta_info(self):
        pass

    @abstractmethod
    def get_book_type(self) -> str:
        pass

    @abstractmethod
    def get_file(self, outpath):
        pass

    @abstractmethod
    def process_book(self, totalpids):
        pass
