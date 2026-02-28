# Archipel Protocol Spec (v1 - Hackathon)

## Transport

- Discovery: UDP Multicast `239.255.42.99:6000`
- Data: TCP unicast (default `7777`, configurable)

## Packet layout

```
MAGIC(4) | TYPE(1) | NODE_ID(32) | PAYLOAD_LEN(4) | PAYLOAD(variable) | HMAC_SHA256(32)
```

- `MAGIC`: `ARCH`
- `NODE_ID`: public identifier (32 bytes serialized/truncated for packet header)
- `HMAC_SHA256`: packet integrity check

## Packet types

- `0x01` HELLO
- `0x02` PEER_LIST
- `0x03` MSG
- `0x04` CHUNK_REQ
- `0x05` CHUNK_DATA
- `0x06` MANIFEST
- `0x07` ACK (reserved)

## Discovery

- Every node sends HELLO every 30 seconds.
- A peer is considered stale after 90 seconds without update.
- Peer table is persisted locally.

## E2E crypto

- Identity: Ed25519 key pair.
- Encryption channel: NaCl Box (Curve25519 key agreement + authenticated stream cipher).
- Message payloads are encrypted before sending.
- No central CA. Trust model is TOFU + explicit local trust flag.

## File transfer

- Manifest advertises `file_id`, size, chunk metadata and hashes.
- Receiver requests chunks with `CHUNK_REQ(file_id, chunk_idx)`.
- Sender replies with `CHUNK_DATA` including chunk data and hash.
- Receiver verifies SHA-256 per chunk before writing.

