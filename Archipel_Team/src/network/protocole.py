import struct
import hmac
import hashlib

# Spécification minimale
MAGIC = b"ARCH"  # 4 bytes
PACKET_FORMAT = "!4sB32sI"  # Magic, Type, NodeID, PayloadLen


def build_packet(pkt_type, node_id_bytes, payload, secret_key):
    """Construit un paquet binaire Archipel"""
    payload_len = len(payload)
    # Header : Magic (4), Type (1), Node ID (32), Payload Len (4)
    header = struct.pack(PACKET_FORMAT, MAGIC, pkt_type, node_id_bytes, payload_len)

    packet_without_sig = header + payload

    # Signature HMAC-SHA256 (32 bytes) pour l'intégrité
    signature = hmac.new(secret_key, packet_without_sig, hashlib.sha256).digest()

    return packet_without_sig + signature