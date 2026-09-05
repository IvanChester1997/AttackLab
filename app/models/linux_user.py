from dataclasses import dataclass


@dataclass
class LinuxUser:
    username: str
    uid: int
    gid: int
    home: str
    shell: str
