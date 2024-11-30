from abc import ABC, abstractmethod

class IHasher(ABC):
    @abstractmethod
    def __call__(self, data: bytes) -> bytes:
        raise NotImplementedError