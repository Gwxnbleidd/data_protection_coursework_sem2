from abc import ABC, abstractmethod

class IPrimeNumberGenerator(ABC):
    @abstractmethod
    def __call__(self, count_nums: int) -> int:
        raise NotImplementedError