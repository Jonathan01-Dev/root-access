import struct
import hmac
import hashlib
import os

# Spécification minimale
MAGIC = b"ARCH"  # 4 bytes
PACKET_FORMAT = "!4sB32sI"  # Magic, Type, NodeID, PayloadLen


# added later: helper to pack/verify with optional encryption

def build_packet(pkt_type, node_id_bytes, payload, secret_key, hmac_key=None, encrypt_key=None):
    """Construit un paquet binaire Archipel.

    - `secret_key` est la clé utilisée pour l'HMAC si `hmac_key` n'est pas fournie.
    - `hmac_key` si fourni est utilisé pour l'HMAC à la place de `secret_key`.
    - `encrypt_key` si fourni sera utilisé pour chiffrer `payload` avec AES-256-GCM
      avant de construire le paquet. Dans ce cas, la charge utile envoyée sera :
      <nonce 12 bytes> + <ciphertext> + <tag 16 bytes>.
    """
    if encrypt_key is not None:
        # AES-GCM encrypt
        from Crypto.Cipher import AES
        nonce = os.urandom(12)
        cipher = AES.new(encrypt_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        payload = nonce + ciphertext + tag
    payload_len = len(payload)
    # Header : Magic (4), Type (1), Node ID (32), Payload Len (4)
    header = struct.pack(PACKET_FORMAT, MAGIC, pkt_type, node_id_bytes, payload_len)

    packet_without_sig = header + payload

    if hmac_key is None:
        hmac_key = secret_key
    signature = hmac.new(hmac_key, packet_without_sig, hashlib.sha256).digest()

    return packet_without_sig + signature


def verify_hmac(data, key):
    """Verify the HMAC-SHA256 at end of `data` using `key`."""
    if len(data) < 32:
        return False
    recv_sig = data[-32:]
    computed = hmac.new(key, data[:-32], hashlib.sha256).digest()
    return hmac.compare_digest(recv_sig, computed)


def decrypt_payload(enc_payload, key):
    """Decrypt a payload that was encrypted with AES-256-GCM using `key`.

    The format is nonce(12) + ciphertext + tag(16).
    """
    from Crypto.Cipher import AES
    nonce = enc_payload[:12]
    tag = enc_payload[-16:]
    ciphertext = enc_payload[12:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
