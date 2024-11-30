from abc import ABC, abstractmethod

import pathlib 

class IDecoder(ABC):
    @abstractmethod
    def __call__(self, data: bytes) -> bytes:
        raise NotImplementedError