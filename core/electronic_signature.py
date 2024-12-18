import pathlib
from dataclasses import dataclass

import rsa

from .file_info import FileInfo
from .idecoder import IDecoder
from .iencoder import IEncoder

SPECIAL_PHRASE_TO_CHECK_CORRECT_DECODING = b"RSA PRIVATE KEY"
SPECIAL_DELIMETER = b"special_delimeter"

@dataclass
class VerifyStatus:
    status: bool 
    user_name: str 

class ElectronicSignature:
    def __init__(self, key_size=None):
        if key_size:
            self.public_key, self.private_key = rsa.newkeys(key_size)

    def set_encoder(self, encoder: IEncoder):
        self.encoder = encoder

    def set_decoder(self, decoder: IDecoder):
        self.decoder = decoder

    def sign(self, doc_name: pathlib.Path):
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()
        self.signed_val = rsa.sign(file_info_json.encode(), self.private_key, "SHA-1")

    def save_signature(self, user_name: str, signature_file_name: pathlib.Path):
        with open(signature_file_name, "wb") as f:
            f.write(user_name.encode() + SPECIAL_DELIMETER)
            f.write(self.signed_val)

    def verify(self, doc_name: pathlib.Path, signature_file_name: pathlib.Path, public_key_file: pathlib.Path) -> VerifyStatus:
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()
        with open(signature_file_name, "rb") as f:
            data = f.read()
        with open(public_key_file, "rb") as f:
            public_key_val = f.read()
        user_name, signature = data.split(SPECIAL_DELIMETER)
        self.public_key = rsa.PublicKey.load_pkcs1(public_key_val, "DER")
        try:
            rsa.verify(file_info_json.encode(), signature, self.public_key)
            return VerifyStatus(True, user_name.decode())
        except Exception:
            return VerifyStatus(False, user_name.decode())
        
    def save_keys(self, folder_name: pathlib.Path):
        folder_name.mkdir(parents=True, exist_ok=True)
        self._save_public_key(folder_name / "public_key")
        self._save_private_key(folder_name / "private_key")

    def load_keys(self, folder_name: pathlib.Path) -> bool:
        self._load_public_key(folder_name / "public_key")
        return self._load_private_key(folder_name / "private_key")

    def _save_public_key(self, public_key_path: pathlib.Path):
        with open(public_key_path, "wb") as f:
            f.write(self.public_key.save_pkcs1("DER"))
    
    def _save_private_key(self, private_key_path: pathlib.Path):
        with open(private_key_path, "wb") as f:
            f.write(self.encoder(SPECIAL_PHRASE_TO_CHECK_CORRECT_DECODING + self.private_key.save_pkcs1("DER")))

    def _load_public_key(self, public_key_file_name: pathlib.Path):
        with open(public_key_file_name, "rb") as f:
            data = f.read()
        self.public_key = rsa.PublicKey.load_pkcs1(data, "DER")
    
    def _load_private_key(self, private_key_file_name: pathlib.Path) -> bool:
        with open(private_key_file_name, "rb") as f:
            data = f.read()
        decoded_data = self.decoder(data)
        if SPECIAL_PHRASE_TO_CHECK_CORRECT_DECODING not in decoded_data:
            return False
        self.private_key = rsa.PrivateKey.load_pkcs1(decoded_data[len(SPECIAL_PHRASE_TO_CHECK_CORRECT_DECODING):], "DER")
        return True