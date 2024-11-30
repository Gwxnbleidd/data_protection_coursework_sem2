import hashlib
import os
import typing
from hmac import compare_digest

from .common import byte_size
from .transform import bytes2int, int2bytes
from .core import encrypt_int, decrypt_int
from .key import PublicKey, PrivateKey

if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
else:
    HashType = typing.Any

HASH_ASN1 = {
    "MD5": b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    "SHA-1": b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "SHA-224": b"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c",
    "SHA-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    "SHA-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    "SHA-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
    "SHA3-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00\x04\x20",
    "SHA3-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00\x04\x30",
    "SHA3-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00\x04\x40",
}

HASH_METHODS: typing.Dict[str, typing.Callable[[], HashType]] = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512,
}
"""Hash methods supported by this library."""


class CryptoError(Exception):
    pass


class DecryptionError(CryptoError):
    pass


class VerificationError(CryptoError):
    pass


def _pad_for_encryption(message: bytes, target_length: int) -> bytes:
    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        raise OverflowError(
            "%i bytes needed for message, but there is only"
            " space for %i" % (msglength, max_msglength)
        )

    # Get random padding
    padding = b""
    padding_length = target_length - msglength - 3

    # We remove 0-bytes, so we'll end up with less padding than we've asked for,
    # so keep adding data until we're at the correct length.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)

        # Always read at least 8 bytes more than we need, and trim off the rest
        # after removing the 0-bytes. This increases the chance of getting
        # enough bytes, especially when needed_bytes is small
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b"\x00", b"")
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_length

    return b"".join([b"\x00\x02", padding, b"\x00", message])


def _pad_for_signing(message: bytes, target_length: int) -> bytes:
    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        raise OverflowError(
            "%i bytes needed for message, but there is only"
            " space for %i" % (msglength, max_msglength)
        )

    padding_length = target_length - msglength - 3

    return b"".join([b"\x00\x01", padding_length * b"\xff", b"\x00", message])


def encrypt(message: bytes, pub_key: PublicKey) -> bytes:
    keylength = byte_size(pub_key.n)
    padded = _pad_for_encryption(message, keylength)

    payload = bytes2int(padded)
    encrypted = encrypt_int(payload, pub_key.e, pub_key.n)
    block = int2bytes(encrypted, keylength)

    return block


def decrypt(crypto: bytes, priv_key: PrivateKey) -> bytes:
    blocksize = byte_size(priv_key.n)
    encrypted = bytes2int(crypto)
    decrypted = priv_key.blinded_decrypt(encrypted)
    cleartext = int2bytes(decrypted, blocksize)

    # Detect leading zeroes in the crypto. These are not reflected in the
    # encrypted value (as leading zeroes do not influence the value of an
    # integer). This fixes CVE-2020-13757.
    if len(crypto) > blocksize:
        # This is operating on public information, so doesn't need to be constant-time.
        raise DecryptionError("Decryption failed")

    # If we can't find the cleartext marker, decryption failed.
    cleartext_marker_bad = not compare_digest(cleartext[:2], b"\x00\x02")

    # Find the 00 separator between the padding and the message
    sep_idx = cleartext.find(b"\x00", 2)

    # sep_idx indicates the position of the `\x00` separator that separates the
    # padding from the actual message. The padding should be at least 8 bytes
    # long (see https://tools.ietf.org/html/rfc8017#section-7.2.2 step 3), which
    # means the separator should be at least at index 10 (because of the
    # `\x00\x02` marker that precedes it).
    sep_idx_bad = sep_idx < 10

    anything_bad = cleartext_marker_bad | sep_idx_bad
    if anything_bad:
        raise DecryptionError("Decryption failed")

    return cleartext[sep_idx + 1 :]


def sign_hash(hash_value: bytes, priv_key: PrivateKey, hash_method: str) -> bytes:
    # Get the ASN1 code for this hash method
    if hash_method not in HASH_ASN1:
        raise ValueError("Invalid hash method: %s" % hash_method)
    asn1code = HASH_ASN1[hash_method]

    # Encrypt the hash with the private key
    cleartext = asn1code + hash_value
    keylength = byte_size(priv_key.n)
    padded = _pad_for_signing(cleartext, keylength)

    payload = bytes2int(padded)
    encrypted = priv_key.blinded_decrypt(payload)
    block = int2bytes(encrypted, keylength)

    return block


def sign(message: bytes, priv_key: PrivateKey, hash_method: str) -> bytes:
    msg_hash = compute_hash(message, hash_method)
    return sign_hash(msg_hash, priv_key, hash_method)


def verify(message: bytes, signature: bytes, pub_key: PublicKey) -> str:
    keylength = byte_size(pub_key.n)
    if len(signature) != keylength:
        raise VerificationError("Verification failed")
    
    encrypted = bytes2int(signature)
    decrypted = encrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = int2bytes(decrypted, keylength)

    # Get the hash method
    method_name = _find_method_hash(clearsig)
    message_hash = compute_hash(message, method_name)

    # Reconstruct the expected padded hash
    cleartext = HASH_ASN1[method_name] + message_hash
    expected = _pad_for_signing(cleartext, keylength)

    # Compare with the signed one
    if expected != clearsig:
        raise VerificationError("Verification failed")

    return method_name


def find_signature_hash(signature: bytes, pub_key: PublicKey) -> str:
    keylength = byte_size(pub_key.n)
    encrypted = bytes2int(signature)
    decrypted = decrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = int2bytes(decrypted, keylength)

    return _find_method_hash(clearsig)


def yield_fixedblocks(infile: typing.BinaryIO, blocksize: int) -> typing.Iterator[bytes]:
    while True:
        block = infile.read(blocksize)

        read_bytes = len(block)
        if read_bytes == 0:
            break

        yield block

        if read_bytes < blocksize:
            break


def compute_hash(message: typing.Union[bytes, typing.BinaryIO], method_name: str) -> bytes:
    if method_name not in HASH_METHODS:
        raise ValueError("Invalid hash method: %s" % method_name)

    method = HASH_METHODS[method_name]
    hasher = method()

    if isinstance(message, bytes):
        hasher.update(message)
    else:
        assert hasattr(message, "read") and hasattr(message.read, "__call__")
        # read as 1K blocks
        for block in yield_fixedblocks(message, 1024):
            hasher.update(block)

    return hasher.digest()


def _find_method_hash(clearsig: bytes) -> str:
    for (hashname, asn1code) in HASH_ASN1.items():
        if asn1code in clearsig:
            return hashname

    raise VerificationError("Verification failed")
