import os
import struct

from .common import bit_size
from .transform import bytes2int


def read_random_bits(nbits: int) -> bytes:
    nbytes, rbits = divmod(nbits, 8)

    # Get the random bytes
    randomdata = os.urandom(nbytes)

    # Add the remaining random bits
    if rbits > 0:
        randomvalue = ord(os.urandom(1))
        randomvalue >>= 8 - rbits
        randomdata = struct.pack("B", randomvalue) + randomdata

    return randomdata


def read_random_int(nbits: int) -> int:
    randomdata = read_random_bits(nbits)
    value = bytes2int(randomdata)

    # Ensure that the number is large enough to just fill out the required
    # number of bits.
    value |= 1 << (nbits - 1)

    return value


def read_random_odd_int(nbits: int) -> int:
    value = read_random_int(nbits)

    # Make sure it's odd
    return value | 1


def randint(maxvalue: int) -> int:
    bit_size = bit_size(maxvalue)

    tries = 0
    while True:
        value = read_random_int(bit_size)
        if value <= maxvalue:
            break

        if tries % 10 == 0 and tries:
            # After a lot of tries to get the right number of bits but still
            # smaller than maxvalue, decrease the number of bits by 1. That'll
            # dramatically increase the chances to get a large enough number.
            bit_size -= 1
        tries += 1

    return value
