import hashlib
import pathlib
import pickle
from dataclasses import dataclass

from core import my_rsa
from core.file_info import FileInfo


SPECIAL_DELIMETER = b"special_delimeter"


@dataclass
class VerifyStatus:
    status: bool
    user_name: str


class ElectronicSignature:
    def __init__(self, key_size=None):
        if key_size:
            self.public_key, self.private_key = my_rsa.generate_keypair(key_size // 2, key_size // 2, key_size)

    def sign(self, doc_name: pathlib.Path):
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()
        self.signed_val = my_rsa.sign(self.private_key, file_info_json)

    def save_signature(self, user_name: str, signature_file_name: pathlib.Path):
        with open(signature_file_name, "wb") as f:
            f.write(user_name.encode() + SPECIAL_DELIMETER)
            f.write(self.signed_val.encode())

    def verify(self, doc_name: pathlib.Path, signature_file_name: pathlib.Path, public_key_file: pathlib.Path) -> VerifyStatus:
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()
        with open(signature_file_name, "rb") as f:
            data = f.read()
        user_name, signature = data.split(SPECIAL_DELIMETER)
        user_name = user_name.decode()
        signature = signature.decode()
        self._load_public_key(public_key_file)
        if my_rsa.verify(self.public_key, signature, file_info_json):
            return VerifyStatus(True, user_name)
        else:
            return VerifyStatus(False, user_name)

    def save_keys(self, folder_name: pathlib.Path, password: str):
        folder_name.mkdir(parents=True, exist_ok=True)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self._save_public_key(folder_name / "public_key")
        self._save_private_key(folder_name / "private_key", password_hash)

    def load_keys(self, folder_name: pathlib.Path, password: str):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self._load_public_key(folder_name / "public_key")
        if not self._load_private_key(folder_name / "private_key", password_hash):
            raise ValueError("Incorrect password")

    def _save_public_key(self, public_key_path: pathlib.Path):
        with open(public_key_path, "wb") as f:
            pickle.dump(self.public_key, f)

    def _save_private_key(self, private_key_path: pathlib.Path, password_hash: str):
        with open(private_key_path, "wb") as f:
            pickle.dump((self.private_key, password_hash), f)

    def _load_public_key(self, public_key_file_name: pathlib.Path):
        with open(public_key_file_name, "rb") as f:
            public_key = pickle.load(f)
            self.public_key = public_key

    def _load_private_key(self, private_key_file_name: pathlib.Path, password_hash: str):
        with open(private_key_file_name, "rb") as f:
            private_key, stored_password_hash = pickle.load(f)
            if stored_password_hash == password_hash:
                self.private_key = private_key
                return True
            else:
                return False
