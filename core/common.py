import typing


class NotRelativePrimeError(ValueError):
    def __init__(self, a: int, b: int, d: int, msg: str = "") -> None:
        super().__init__(msg or "%d and %d are not relatively prime, divider=%i" % (a, b, d))
        self.a = a
        self.b = b
        self.d = d


def bit_size(num: int) -> int:
    try:
        return num.bit_length()
    except AttributeError as ex:
        raise TypeError("bit_size(num) only supports integers, not %r" % type(num)) from ex


def byte_size(number: int) -> int:
    if number == 0:
        return 1
    return ceil_div(bit_size(number), 8)


def ceil_div(num: int, div: int) -> int:
    quanta, mod = divmod(num, div)
    if mod:
        quanta += 1
    return quanta


def extended_gcd(a: int, b: int) -> typing.Tuple[int, int, int]:
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo original b
    if ly < 0:
        ly += oa  # If neg wrap modulo original a
    return a, lx, ly  # Return only positive values


def inverse(x: int, n: int) -> int:
    (divider, inv, _) = extended_gcd(x, n)

    if divider != 1:
        raise NotRelativePrimeError(x, n, divider)

    return inv


def crt(a_values: typing.Iterable[int], modulo_values: typing.Iterable[int]) -> int:
    m = 1
    x = 0

    for modulo in modulo_values:
        m *= modulo

    for (m_i, a_i) in zip(modulo_values, a_values):
        M_i = m // m_i
        inv = inverse(M_i, m_i)

        x = (x + a_i * M_i * inv) % m

    return x
