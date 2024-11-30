from abc import ABC, abstractmethod

import pathlib

class IEncoder(ABC):
    @abstractmethod
    def __call__(self, message: bytes) -> bytes:
        raise NotImplementedError