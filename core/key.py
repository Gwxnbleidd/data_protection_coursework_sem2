import abc
import threading
import typing
import warnings

from .prime import are_relatively_prime, getprime
from .pem import load_pem, save_pem
from .common import inverse, bit_size, NotRelativePrimeError
from .randnum import randint


DEFAULT_EXPONENT = 65537


T = typing.TypeVar("T", bound="AbstractKey")


class AbstractKey(metaclass=abc.ABCMeta):
    __slots__ = ("n", "e", "blindfac", "blindfac_inverse", "mutex")

    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

        self.blindfac = self.blindfac_inverse = -1

        self.mutex = threading.Lock()

    @classmethod
    @abc.abstractmethod
    def _load_pkcs1_pem(cls: typing.Type[T], keyfile: bytes) -> T:
        pass

    @classmethod
    @abc.abstractmethod
    def _load_pkcs1_der(cls: typing.Type[T], keyfile: bytes) -> T:
        pass

    @abc.abstractmethod
    def _save_pkcs1_pem(self) -> bytes:
        pass

    @abc.abstractmethod
    def _save_pkcs1_der(self) -> bytes:
        pass

    @classmethod
    def load_pkcs1(cls: typing.Type[T], keyfile: bytes, format: str = "PEM") -> T:
        pass

        methods = {
            "PEM": cls._load_pkcs1_pem,
            "DER": cls._load_pkcs1_der,
        }

        method = cls._assert_format_exists(format, methods)
        return method(keyfile)

    @staticmethod
    def _assert_format_exists(
        file_format: str, methods: typing.Mapping[str, typing.Callable]
    ) -> typing.Callable:
        try:
            return methods[file_format]
        except KeyError as ex:
            formats = ", ".join(sorted(methods.keys()))
            raise ValueError(
                "Unsupported format: %r, try one of %s" % (file_format, formats)
            ) from ex

    def save_pkcs1(self, format: str = "PEM") -> bytes:
        methods = {
            "PEM": self._save_pkcs1_pem,
            "DER": self._save_pkcs1_der,
        }

        method = self._assert_format_exists(format, methods)
        return method()

    def blind(self, message: int) -> typing.Tuple[int, int]:
        blindfac, blindfac_inverse = self._update_blinding_factor()
        blinded = (message * pow(blindfac, self.e, self.n)) % self.n
        return blinded, blindfac_inverse

    def unblind(self, blinded: int, blindfac_inverse: int) -> int:
        return (blindfac_inverse * blinded) % self.n

    def _initial_blinding_factor(self) -> int:
        for _ in range(1000):
            blind_r = randint(self.n - 1)
            if are_relatively_prime(self.n, blind_r):
                return blind_r
        raise RuntimeError("unable to find blinding factor")

    def _update_blinding_factor(self) -> typing.Tuple[int, int]:
        with self.mutex:
            if self.blindfac < 0:
                # Compute initial blinding factor, which is rather slow to do.
                self.blindfac = self._initial_blinding_factor()
                self.blindfac_inverse = inverse(self.blindfac, self.n)
            else:
                # Reuse previous blinding factor.
                self.blindfac = pow(self.blindfac, 2, self.n)
                self.blindfac_inverse = pow(self.blindfac_inverse, 2, self.n)

            return self.blindfac, self.blindfac_inverse


class PublicKey(AbstractKey):
    __slots__ = ()

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return "PublicKey(%i, %i)" % (self.n, self.e)

    def __getstate__(self) -> typing.Tuple[int, int]:
        return self.n, self.e

    def __setstate__(self, state: typing.Tuple[int, int]) -> None:
        self.n, self.e = state
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PublicKey):
            return False

        return self.n == other.n and self.e == other.e

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PublicKey":
        from pyasn1.codec.der import decoder
        from rsa.asn1 import AsnPubKey

        (priv, _) = decoder.decode(keyfile, asn1Spec=AsnPubKey())
        return cls(n=int(priv["modulus"]), e=int(priv["publicExponent"]))

    def _save_pkcs1_der(self) -> bytes:
        """Saves the public key in PKCS#1 DER format.

        :returns: the DER-encoded public key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder
        from rsa.asn1 import AsnPubKey

        # Create the ASN object
        asn_key = AsnPubKey()
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PublicKey":
        der = load_pem(keyfile, "RSA PUBLIC KEY")
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self) -> bytes:
        der = self._save_pkcs1_der()
        return save_pem(der, "RSA PUBLIC KEY")

    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile: bytes) -> "PublicKey":
        der = load_pem(keyfile, "PUBLIC KEY")
        return cls.load_pkcs1_openssl_der(der)

    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile: bytes) -> "PublicKey":
        from rsa.asn1 import OpenSSLPubKey
        from pyasn1.codec.der import decoder
        from pyasn1.type import univ

        (keyinfo, _) = decoder.decode(keyfile, asn1Spec=OpenSSLPubKey())

        if keyinfo["header"]["oid"] != univ.ObjectIdentifier("1.2.840.113549.1.1.1"):
            raise TypeError("This is not a DER-encoded OpenSSL-compatible public key")

        return cls._load_pkcs1_der(keyinfo["key"][1:])


class PrivateKey(AbstractKey):
    __slots__ = ("d", "p", "q", "exp1", "exp2", "coef")

    def __init__(self, n: int, e: int, d: int, p: int, q: int) -> None:
        AbstractKey.__init__(self, n, e)
        self.d = d
        self.p = p
        self.q = q

        # Calculate exponents and coefficient.
        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coef = inverse(q, p)

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return "PrivateKey(%i, %i, %i, %i, %i)" % (
            self.n,
            self.e,
            self.d,
            self.p,
            self.q,
        )

    def __getstate__(self) -> typing.Tuple[int, int, int, int, int, int, int, int]:
        return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef

    def __setstate__(self, state: typing.Tuple[int, int, int, int, int, int, int, int]) -> None:
        self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PrivateKey):
            return False

        return (
            self.n == other.n
            and self.e == other.e
            and self.d == other.d
            and self.p == other.p
            and self.q == other.q
            and self.exp1 == other.exp1
            and self.exp2 == other.exp2
            and self.coef == other.coef
        )

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))

    def blinded_decrypt(self, encrypted: int) -> int:
        # Blinding and un-blinding should be using the same factor
        blinded, blindfac_inverse = self.blind(encrypted)

        # Instead of using the core functionality, use the Chinese Remainder
        # Theorem and be 2-4x faster. This the same as:
        #
        # decrypted = rsa.core.decrypt_int(blinded, self.d, self.n)
        s1 = pow(blinded, self.exp1, self.p)
        s2 = pow(blinded, self.exp2, self.q)
        h = ((s1 - s2) * self.coef) % self.p
        decrypted = s2 + self.q * h

        return self.unblind(decrypted, blindfac_inverse)


    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PrivateKey":
        from pyasn1.codec.der import decoder

        (priv, _) = decoder.decode(keyfile)

        if priv[0] != 0:
            raise ValueError("Unable to read this file, version %s != 0" % priv[0])

        as_ints = map(int, priv[1:6])
        key = cls(*as_ints)

        exp1, exp2, coef = map(int, priv[6:9])

        if (key.exp1, key.exp2, key.coef) != (exp1, exp2, coef):
            warnings.warn(
                "You have provided a malformed keyfile. Either the exponents "
                "or the coefficient are incorrect. Using the correct values "
                "instead.",
                UserWarning,
            )

        return key

    def _save_pkcs1_der(self) -> bytes:
        from pyasn1.type import univ, namedtype
        from pyasn1.codec.der import encoder

        class AsnPrivKey(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("version", univ.Integer()),
                namedtype.NamedType("modulus", univ.Integer()),
                namedtype.NamedType("publicExponent", univ.Integer()),
                namedtype.NamedType("privateExponent", univ.Integer()),
                namedtype.NamedType("prime1", univ.Integer()),
                namedtype.NamedType("prime2", univ.Integer()),
                namedtype.NamedType("exponent1", univ.Integer()),
                namedtype.NamedType("exponent2", univ.Integer()),
                namedtype.NamedType("coefficient", univ.Integer()),
            )

        # Create the ASN object
        asn_key = AsnPrivKey()
        asn_key.setComponentByName("version", 0)
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)
        asn_key.setComponentByName("privateExponent", self.d)
        asn_key.setComponentByName("prime1", self.p)
        asn_key.setComponentByName("prime2", self.q)
        asn_key.setComponentByName("exponent1", self.exp1)
        asn_key.setComponentByName("exponent2", self.exp2)
        asn_key.setComponentByName("coefficient", self.coef)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PrivateKey":
        der = load_pem(keyfile, b"RSA PRIVATE KEY")
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self) -> bytes:
        der = self._save_pkcs1_der()
        return save_pem(der, b"RSA PRIVATE KEY")


def find_p_q(
    nbits: int,
    getprime_func: typing.Callable[[int], int] = getprime,
    accurate: bool = True,
) -> typing.Tuple[int, int]:
    total_bits = nbits * 2

    # Make sure that p and q aren't too close or the factoring programs can
    # factor n.
    shift = nbits // 16
    pbits = nbits + shift
    qbits = nbits - shift

    # Choose the two initial primes
    p = getprime_func(pbits)
    q = getprime_func(qbits)

    def is_acceptable(p: int, q: int) -> bool:
        if p == q:
            return False

        if not accurate:
            return True

        # Make sure we have just the right amount of bits
        found_size = bit_size(p * q)
        return total_bits == found_size

    # Keep choosing other primes until they match our requirements.
    change_p = False
    while not is_acceptable(p, q):
        # Change p on one iteration and q on the other
        if change_p:
            p = getprime_func(pbits)
        else:
            q = getprime_func(qbits)

        change_p = not change_p

    # We want p > q as described on
    # http://www.di-mgt.com.au/rsa_alg.html#crt
    return max(p, q), min(p, q)


def calculate_keys_custom_exponent(p: int, q: int, exponent: int) -> typing.Tuple[int, int]:
    phi_n = (p - 1) * (q - 1)

    try:
        d = inverse(exponent, phi_n)
    except NotRelativePrimeError as ex:
        raise NotRelativePrimeError(
            exponent,
            phi_n,
            ex.d,
            msg="e (%d) and phi_n (%d) are not relatively prime (divider=%i)"
            % (exponent, phi_n, ex.d),
        ) from ex

    if (exponent * d) % phi_n != 1:
        raise ValueError(
            "e (%d) and d (%d) are not mult. inv. modulo " "phi_n (%d)" % (exponent, d, phi_n)
        )

    return exponent, d


def calculate_keys(p: int, q: int) -> typing.Tuple[int, int]:
    return calculate_keys_custom_exponent(p, q, DEFAULT_EXPONENT)


def gen_keys(
    nbits: int,
    getprime_func: typing.Callable[[int], int],
    accurate: bool = True,
    exponent: int = DEFAULT_EXPONENT,
) -> typing.Tuple[int, int, int, int]:
    # Regenerate p and q values, until calculate_keys doesn't raise a
    # ValueError.
    while True:
        (p, q) = find_p_q(nbits // 2, getprime_func, accurate)
        try:
            (e, d) = calculate_keys_custom_exponent(p, q, exponent=exponent)
            break
        except ValueError:
            pass

    return p, q, e, d


def newkeys(
    nbits: int,
    accurate: bool = True,
    poolsize: int = 1,
    exponent: int = DEFAULT_EXPONENT,
) -> typing.Tuple[PublicKey, PrivateKey]:
    if nbits < 16:
        raise ValueError("Key too small")

    if poolsize < 1:
        raise ValueError("Pool size (%i) should be >= 1" % poolsize)

    # Determine which getprime function to use
    if poolsize > 1:
        from rsa import parallel

        def getprime_func(nbits: int) -> int:
            return parallel.getprime(nbits, poolsize=poolsize)

    else:
        getprime_func = rsa.prime.getprime

    # Generate the key components
    (p, q, e, d) = gen_keys(nbits, getprime_func, accurate=accurate, exponent=exponent)

    # Create the key objects
    n = p * q

    return (PublicKey(n, e), PrivateKey(n, e, d, p, q))


__all__ = ["PublicKey", "PrivateKey", "newkeys"]

if __name__ == "__main__":
    import doctest

    try:
        for count in range(100):
            (failures, tests) = doctest.testmod()
            if failures:
                break

            if (count % 10 == 0 and count) or count == 1:
                print("%i times" % count)
    except KeyboardInterrupt:
        print("Aborted")
    else:
        print("Doctests done")
