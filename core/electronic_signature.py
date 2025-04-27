import hashlib
import pathlib
import pickle
from dataclasses import dataclass

from core import fiat_shamir_signature as es
from core.file_info import FileInfo


@dataclass
class VerifyStatus:
    status: bool
    user_name: str


class ElectronicSignature:
    def __init__(self):
        self.public_key, self.private_key = es.generate_keypair(1024, t=8)

    def sign(self, doc_name: pathlib.Path):
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()
        self.signed_val = es.sign(self.private_key, file_info_json)

    def save_signature(self, user_name: str, signature_file: pathlib.Path):
        signature_data = {
            'username': user_name,
            'signature': self.signed_val
        }
        with open(signature_file, 'wb') as f:
            pickle.dump(signature_data, f)

    def verify(self, doc_name: pathlib.Path, signature_file: pathlib.Path,
               public_key_file: pathlib.Path) -> VerifyStatus:
        file_info = FileInfo.collect(doc_name)
        file_info_json = file_info.to_json()

        with open(signature_file, 'rb') as f:
            signature_data = pickle.load(f)

        self._load_public_key(public_key_file)

        if es.verify(self.public_key, signature_data['signature'], file_info_json):
            return VerifyStatus(True, signature_data['username'])
        return VerifyStatus(False, signature_data['username'])

    def save_keys(self, folder: pathlib.Path, password: str):
        folder.mkdir(parents=True, exist_ok=True)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self._save_public_key(folder / "public_key.pk")
        self._save_private_key(folder / "private_key.sk", password_hash)

    def load_keys(self, folder_name: pathlib.Path, password: str):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self._load_public_key(folder_name / "public_key.pk")
        if not self._load_private_key(folder_name / "private_key.sk", password_hash):
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
