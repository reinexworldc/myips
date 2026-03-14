import struct

class IP:
    
    # Return the IP packet structure (RFC-791)
    def header_format() -> dict[str, int | None]:
        return {
            "version": 4,
            "ihl": 4,
            "type_of_service": 8,
            "total_length": 16,
            "identification": 16,
            "flags": 3,
            "fragments_offset": 13,
            "time_to_live": 8,
            "protocol": 8,
            "header_checksum": 16,
            "source_address": 32,
            "destination_address": 32,
            "options": None,
        }
