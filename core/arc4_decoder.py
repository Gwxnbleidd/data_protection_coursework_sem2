from .idecoder import IDecoder

import string

from Crypto.Cipher import ARC4

from overrides import override 

ASCII_SYMBOLS = string.ascii_letters
ARC4_CHIPHER_KEY_LEN = 32

def _transform_key_for_salsa_chipher(key: str) -> str:
    if len(key) > ARC4_CHIPHER_KEY_LEN:
        return key[:ARC4_CHIPHER_KEY_LEN]
    
    return key + ASCII_SYMBOLS[:ARC4_CHIPHER_KEY_LEN - len(key)]

class ARC4Decoder(IDecoder):
    def __init__(self, key: str):
        key = _transform_key_for_salsa_chipher(key)
        self.cipher = ARC4.new(key=key.encode())
        
    @override
    def __call__(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)
