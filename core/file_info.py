import os
import pathlib
import json
from dataclasses import asdict, dataclass

@dataclass
class FileInfo:
    st_mode: int 
    st_ino: int 
    st_dev: int 
    st_nlink: int 
    st_uid: int 
    st_gid: int 
    st_size: int 
    st_atime: int 
    st_mtime: int 
    st_ctime: int 

    def to_dict(self) -> dict[str, int]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def collect(file_name: pathlib.Path) -> "FileInfo":
        file_props = os.stat(file_name)
        return FileInfo(
            st_mode=file_props.st_mode,
            st_ino=file_props.st_ino,
            st_dev=file_props.st_dev,
            st_nlink=file_props.st_nlink,
            st_uid=file_props.st_uid,
            st_gid=file_props.st_gid,
            st_size=file_props.st_size,
            st_atime=file_props.st_atime,
            st_mtime=file_props.st_mtime,
            st_ctime=file_props.st_ctime,
        )