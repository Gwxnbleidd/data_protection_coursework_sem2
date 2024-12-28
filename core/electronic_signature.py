import pathlib
from dataclasses import dataclass

from core import my_rsa
from .file_info import FileInfo


SPECIAL_DELIMETER = "special_delimeter"

@dataclass
class VerifyStatus:
    status: bool 
    user_name: str 

class ElectronicSignature:
    def __init__(self, key_size = None):
        if key_size:
            self.public_key, self.private_key = my_rsa.generate_keypair(key_size // 2, key_size // 2, key_size)


    def sign(self, doc_name: pathlib.Path):
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()
        self.signed_val = my_rsa.sign(self.private_key, file_info_json)

    def save_signature(self, user_name: str, signature_file_name: pathlib.Path):
        with open(signature_file_name, "w") as f:
            f.write(user_name + SPECIAL_DELIMETER)
            f.write(self.signed_val)

    def verify(self, doc_name: pathlib.Path, signature_file_name: pathlib.Path, public_key_file: pathlib.Path) -> VerifyStatus:
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()
        with open(signature_file_name, "r") as f:
            data = f.read()
        user_name, signature = data.split(SPECIAL_DELIMETER)
        self._load_public_key(public_key_file)
        if my_rsa.verify(self.public_key, signature, file_info_json):
            return VerifyStatus(True, user_name)
        else:
            return VerifyStatus(False, user_name)
        
    def save_keys(self, folder_name: pathlib.Path):
        folder_name.mkdir(parents=True, exist_ok=True)
        self._save_public_key(folder_name / "public_key")
        self._save_private_key(folder_name / "private_key")

    def load_keys(self, folder_name: pathlib.Path):
        self._load_public_key(folder_name / "public_key")
        return self._load_private_key(folder_name / "private_key")

    def _save_public_key(self, public_key_path: pathlib.Path):
        with open(public_key_path, "w") as f:
            f.write(','.join([str(el) for el in self.public_key]))
    
    def _save_private_key(self, private_key_path: pathlib.Path):
        with open(private_key_path, "w") as f:
            f.write(','.join([str(el) for el in self.private_key]))

    def _load_public_key(self, public_key_file_name: pathlib.Path):
        with open(public_key_file_name, "r") as f:
            data = f.read()
        self.public_key = tuple(map(int, data.split(',')))
    
    def _load_private_key(self, private_key_file_name: pathlib.Path):
        with open(private_key_file_name, "r") as f:
            data = f.read()
        self.private_key = tuple(map(int, data.split(',')))