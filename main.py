import struct
import socket

class IP:
    def __init__(
        self,
        version: int = 4,
        ihl: int = 5,
        tos: int = 0,
        total_length: int = 0,
        identification: int = 0,
        flags: int = 0,
        fragment_offset: int = 0,
        ttl: int = 64,
        protocol: int = 0,
        checksum: int = 0,
        src: str = "0.0.0.0",
        dst: str = "0.0.0.0",
    ):
        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src = src
        self.dst = dst

        self._socket = socket.socket(
            socket.AF_INET, 
            socket.SOCK_RAW, 
            socket.IPPROTO_RAW
        )

    @staticmethod
    def header_fields() -> tuple:
        return (
            "version",
            "ihl",
            "tos",
            "total_length",
            "identification",
            "flags",
            "fragment_offset",
            "ttl",
            "protocol",
            "checksum",
            "src",
            "dst",
        )
    
    def _build_header(self):
        src_bytes = socket.inet_aton(self.src)
        dst_bytes = socket.inet_aton(self.dst)
        ver_ihl = (self.version << 4) | self.ihl
        flags_frag = (self.flags << 13) | self.fragment_offset

        header = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            self.tos,
            self.total_length,
            self.identification,
            flags_frag,
            self.ttl,
            self.protocol,
            self.checksum,
            src_bytes,
            dst_bytes,
        )
        return header
    
    def send(self, payload: bytes = b"") -> None:
        header = self._build_header()
        packet = header + payload
        self._socket.sendto(packet, (self.dst, 0))
