import socket
import threading
import time
import json
import struct
import os
import re
import ipaddress
from .protocole import build_packet, PACKET_FORMAT

# Configuration conforme au document technique
MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
# dÃ©faut, mais peut Ãªtre surchargÃ© via variable d'environnement pour tests
TCP_PORT = int(os.environ.get('TCP_PORT', '7777'))

# types de paquet
TYPE_HELLO     = 0x01
TYPE_PEER_LIST = 0x02
TYPE_MSG       = 0x03
TYPE_CHUNK_REQ = 0x04
TYPE_CHUNK_DATA= 0x05
TYPE_MANIFEST  = 0x06

# handshake / keep-alive types (TCP)
TYPE_HS_HELLO       = 0x10
TYPE_HS_HELLO_REPLY = 0x11
TYPE_HS_AUTH        = 0x12
TYPE_HS_AUTH_OK     = 0x13
TYPE_PING           = 0x07
TYPE_PONG           = 0x08
TYPE_REVOCATION     = 0x09


class ArchipelNode:
    def __init__(self, identity=None, tcp_port=None, db_file=None, local_ip=None):
        # allow overriding the TCP port per-instance (for tests/multi-nodes)
        self.tcp_port = tcp_port if tcp_port is not None else TCP_PORT
        # identite : tuple (signing_priv, verify_pub)
        if identity is None:
            # essayer de charger clés depuis disque
            self.signing_key, self.verify_key = self.load_identity()
        else:
            self.signing_key, self.verify_key = identity

        # dérivalés Curve25519 pour chiffrement
        self.curve_priv = self.signing_key.to_curve25519_private_key()
        self.curve_pub = self.verify_key.to_curve25519_public_key()
        self.node_uid = self.verify_key.encode().hex()
        self.node_id = self.node_uid  # node_id = clé publique en hex

        self.peer_table = {}  # Module 1.2: Table de pairs
        # table additionnelle pour la réputation et fichiers partagés, mise à jour
        # lorsque des manifests sont reçus ou des chunks réussis/échoués.
        # chaque entrée sera un dict contenant ip, tcp_port, last_seen, pubkey,
        # trusted, shared_files(list), reputation(float)
        # stockage des manifests reÃ§us (file_id -> manifest dict)
        self.manifests = {}
        self.message_log = []
        self.event_log = []

        # connexions TCP persistantes et clés de session après handshake
        self.peer_connections = {}   # peer_id -> socket
        self.session_keys = {}       # peer_id -> aes-gcm key bytes
        self.peer_last_ping = {}     # peer_id -> timestamp of last received PONG

        # download manager (SprintÂ 4)
        from transfer.manager import DownloadManager
        self.dl_manager = DownloadManager(self)

        self.running = True
        self.db_file = db_file or "peer_table.json"
        self.local_ip = local_ip or os.environ.get("ARCHIPEL_LOCAL_IP")
        self.local_ips = self._resolve_local_ips()
        self.load_peers()  # Charger les pairs existants au dÃ©marrage

    def _packet_node_id_bytes(self):
        return bytes.fromhex(self.node_uid)

    def _log_event(self, level, text):
        item = {"ts": int(time.time()), "level": level, "text": text}
        self.event_log.append(item)
        if len(self.event_log) > 200:
            self.event_log = self.event_log[-200:]

    def _resolve_local_ip(self):
        """Best-effort local IP selection without any internet dependency."""
        ips = self._resolve_local_ips()
        if ips:
            return ips[0]
        return "0.0.0.0"

    def _resolve_local_ips(self):
        """Return candidate local IPv4 interfaces for multicast."""
        if self.local_ip:
            return [self.local_ip]

        found = []
        try:
            # Route-based selection without internet traffic.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((MCAST_GRP, MCAST_PORT))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                found.append(ip)
        except Exception:
            pass
        try:
            candidates = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            for cand in candidates:
                ip = cand[4][0]
                if not ip.startswith("127."):
                    found.append(ip)
        except Exception:
            pass
        # Keep private IPv4 first and de-duplicate while preserving order.
        uniq = []
        for ip in found:
            if ip not in uniq:
                uniq.append(ip)

        def score(ip):
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_private:
                    return 99
                # Prefer 192.168.x.x for common LAN demos, then 10.x, then 172.16/12.
                if ip.startswith("192.168."):
                    return 0
                if ip.startswith("10."):
                    return 1
                if ip.startswith("172."):
                    return 2
                return 5
            except Exception:
                return 100

        uniq.sort(key=score)
        return uniq

    def _same_subnet(self, ip_a, ip_b):
        """Simple /24 subnet check for LAN filtering."""
        try:
            a = ipaddress.ip_address(ip_a)
            b = ipaddress.ip_address(ip_b)
            if a.version != 4 or b.version != 4:
                return False
            return ".".join(ip_a.split(".")[:3]) == ".".join(ip_b.split(".")[:3])
        except Exception:
            return False

    def _is_local_candidate_ip(self, ip):
        return any(self._same_subnet(ip, local) or ip == local for local in self.local_ips)

    @staticmethod
    def _is_valid_node_id(node_id):
        if not node_id or len(node_id) > 64:
            return False
        if re.match(r"^[0-9a-f]{64}$", node_id):
            return True
        return re.match(r"^[A-Za-z0-9_-]+$", node_id) is not None

    # --- UTILS : encryption / session management ---
    def _recv_exact(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _derive_session_key(self, shared):
        # HKDF-SHA256 per spec
        from Crypto.Protocol.KDF import HKDF
        return HKDF(shared, 32, b"", b"archipel-v1", hashlib.sha256)

    def _encrypt_payload(self, key, plaintext: bytes) -> bytes:
        from Crypto.Cipher import AES
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ct + tag

    def _decrypt_payload(self, key, data: bytes) -> bytes:
        from Crypto.Cipher import AES
        nonce = data[:12]
        tag = data[-16:]
        ct = data[12:-16]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    def _update_reputation(self, peer_id, success: bool):
        entry = self.peer_table.get(peer_id)
        if not entry:
            return
        rep = entry.get("reputation", 0.0)
        # simple EWMA: success+=1, failure increments 0 weight
        if success:
            rep = min(1.0, rep + 0.1)
        else:
            rep = max(0.0, rep - 0.2)
        entry["reputation"] = rep

    def _keepalive_loop(self, peer_id):
        # sends ping every 15s on an established connection
        while self.running and peer_id in self.peer_connections:
            try:
                sock = self.peer_connections.get(peer_id)
                if not sock:
                    break
                pkt = build_packet(TYPE_PING, self._packet_node_id_bytes(), b"", self.signing_key.encode(), hmac_key=self.session_keys.get(peer_id))
                sock.sendall(pkt)
            except Exception:
                pass
            time.sleep(15)

    def _get_connection(self, peer_id):
        """Return an open socket to the given peer, performing handshake if needed."""
        if peer_id in self.peer_connections:
            return self.peer_connections[peer_id]
        info = self.peer_table.get(peer_id)
        if not info:
            raise KeyError(f"Pair inconnu: {peer_id}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((info['ip'], info['tcp_port']))
        # perform handshake as initiator
        try:
            session = self._handshake_initiator(peer_id, sock)
        except Exception as e:
            sock.close()
            raise
        if session:
            self.session_keys[peer_id] = session
        self.peer_connections[peer_id] = sock
        # reader and keepalive threads
        threading.Thread(target=self._connection_reader, args=(sock, peer_id), daemon=True).start()
        threading.Thread(target=self._keepalive_loop, args=(peer_id,), daemon=True).start()
        return sock

    def _handshake_initiator(self, peer_id, sock):
        """Perform client side of the handshake over given socket. Returns session key."""
        import nacl.public, nacl.signing, binascii
        # ephemeral key pair
        ep_priv = nacl.public.PrivateKey.generate()
        ep_pub = ep_priv.public_key.encode()
        # send HS_HELLO
        payload = json.dumps({"e_pub": ep_pub.hex(), "timestamp": int(time.time())}).encode()
        pkt = build_packet(TYPE_HS_HELLO, self._packet_node_id_bytes(), payload, self.signing_key.encode())
        sock.sendall(pkt)
        # await HS_HELLO_REPLY
        header = self._recv_exact(sock, struct.calcsize(PACKET_FORMAT))
        if not header or not header.startswith(b"ARCH"):
            raise RuntimeError("Invalid handshake reply")
        _, _, remote_id_bytes, payload_len = struct.unpack(PACKET_FORMAT, header)
        remote_id = remote_id_bytes.hex()
        payload = self._recv_exact(sock, payload_len)
        sig = self._recv_exact(sock, 32)
        pkt_type = header[4]
        if pkt_type != TYPE_HS_HELLO_REPLY:
            raise RuntimeError("Expected HS_HELLO_REPLY")
        msg = json.loads(payload.decode())
        remote_ep = bytes.fromhex(msg.get("e_pub", ""))
        remote_sig = bytes.fromhex(msg.get("sig", ""))
        # verify signature using permanent pubkey
        entry = self.peer_table.get(remote_id)
        if entry and entry.get("pubkey"):
            peer_verify = nacl.signing.VerifyKey(bytes.fromhex(entry['pubkey']))
            try:
                peer_verify.verify(remote_ep, remote_sig)
            except Exception:
                raise RuntimeError("Handshake signature verification failed")
        # derive shared secret
        from nacl.bindings import crypto_scalarmult
        shared = crypto_scalarmult(ep_priv.encode(), remote_ep)
        session_key = self._derive_session_key(shared)
        # send AUTH
        shared_hash = hashlib.sha256(shared).digest()
        auth_sig = self.signing_key.sign(shared_hash).signature
        pkt = build_packet(TYPE_HS_AUTH, self._packet_node_id_bytes(), json.dumps({"sig": auth_sig.hex()}).encode(), self.signing_key.encode())
        sock.sendall(pkt)
        # wait for AUTH_OK
        header = self._recv_exact(sock, struct.calcsize(PACKET_FORMAT))
        if not header:
            raise RuntimeError("Handshake failed (no auth ok)")
        if header[4] != TYPE_HS_AUTH_OK:
            raise RuntimeError("Handshake did not complete")
        return session_key

    def _handshake_responder(self, sock):
        """Perform server side of handshake on incoming socket.
        Returns (peer_id, session_key) or raises on failure.
        """
        import nacl.public, nacl.signing, binascii
        # wait for HS_HELLO
        header = self._recv_exact(sock, struct.calcsize(PACKET_FORMAT))
        if not header or not header.startswith(b"ARCH"):
            raise RuntimeError("Invalid handshake hello")
        pkt_type = header[4]
        if pkt_type != TYPE_HS_HELLO:
            raise RuntimeError("Expected HS_HELLO")
        _, _, remote_id_bytes, payload_len = struct.unpack(PACKET_FORMAT, header)
        remote_id = remote_id_bytes.hex()
        payload = self._recv_exact(sock, payload_len)
        sig = self._recv_exact(sock, 32)
        # extract ephemeral pub
        msg = json.loads(payload.decode())
        remote_ep = bytes.fromhex(msg.get("e_pub", ""))
        # generate our own ephemeral and reply
        ep_priv = nacl.public.PrivateKey.generate()
        ep_pub = ep_priv.public_key.encode()
        # sign our ephemeral public with permanent key
        sig_bytes = self.signing_key.sign(ep_pub).signature
        resp_payload = json.dumps({"e_pub": ep_pub.hex(), "sig": sig_bytes.hex()}).encode()
        pkt = build_packet(TYPE_HS_HELLO_REPLY, self._packet_node_id_bytes(), resp_payload, self.signing_key.encode())
        sock.sendall(pkt)
        # derive shared
        from nacl.bindings import crypto_scalarmult
        shared = crypto_scalarmult(ep_priv.encode(), remote_ep)
        session_key = self._derive_session_key(shared)
        # wait for AUTH
        header = self._recv_exact(sock, struct.calcsize(PACKET_FORMAT))
        if not header or header[4] != TYPE_HS_AUTH:
            raise RuntimeError("Handshake auth missing")
        _, _, _, payload_len = struct.unpack(PACKET_FORMAT, header)
        payload = self._recv_exact(sock, payload_len)
        sig = self._recv_exact(sock, 32)
        auth_msg = json.loads(payload.decode())
        auth_sig = bytes.fromhex(auth_msg.get("sig", ""))
        # verify signature of shared hash
        shared_hash = hashlib.sha256(shared).digest()
        # look up peer pubkey from peer_table if available
        pub = None
        if remote_id in self.peer_table:
            pub = self.peer_table[remote_id].get('pubkey')
        if pub:
            peer_verify = nacl.signing.VerifyKey(bytes.fromhex(pub))
            try:
                peer_verify.verify(shared_hash, auth_sig)
            except Exception:
                raise RuntimeError("Auth signature invalid")
        # send AUTH_OK
        pkt = build_packet(TYPE_HS_AUTH_OK, self._packet_node_id_bytes(), b"", self.signing_key.encode(), hmac_key=session_key)
        sock.sendall(pkt)
        return remote_id, session_key

    def _connection_reader(self, sock, peer_id=None):
        """Loop reading messages from a socket that is already associated to a peer_id."""
        try:
            while self.running:
                header = self._recv_exact(sock, struct.calcsize(PACKET_FORMAT))
                if not header:
                    break
                if not header.startswith(b"ARCH"):
                    continue
                _, _, remote_id_bytes, payload_len = struct.unpack(PACKET_FORMAT, header)
                payload = self._recv_exact(sock, payload_len)
                sig = self._recv_exact(sock, 32)
                remote_id = remote_id_bytes.hex()
                # verify HMAC using session key if exists else signing key
                key = self.session_keys.get(remote_id, self.signing_key.encode())
                if not verify_hmac(header + (payload or b"") + (sig or b""), key):
                    print("[!] HMAC verification failed for incoming packet")
                    continue
                pkt_type = header[4]
                if pkt_type == TYPE_PING:
                    # respond pong
                    pong = build_packet(TYPE_PONG, self._packet_node_id_bytes(), b"", self.signing_key.encode(), hmac_key=self.session_keys.get(remote_id))
                    sock.sendall(pong)
                    continue
                if pkt_type == TYPE_PONG:
                    self.peer_last_ping[remote_id] = time.time()
                    continue
                # decrypt if encrypted
                if remote_id in self.session_keys and payload:
                    try:
                        payload = self._decrypt_payload(self.session_keys[remote_id], payload)
                    except Exception as e:
                        print(f"[!] decrypt error: {e}")
                        continue
                # delegate to existing handler logic by temporarily reusing _handle_client
                # we mimic a fake socket with data to reuse code
                # simpler: call self._process_application_packet(remote_id, pkt_type, payload, sock, peer_id)
                self._process_tcp_message(remote_id, pkt_type, payload, sock, peer_id)
        except Exception as e:
            print(f"[!] connection reader error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
            if peer_id and peer_id in self.peer_connections:
                del self.peer_connections[peer_id]

    def _process_tcp_message(self, remote_id, pkt_type, payload, sock, addr_or_peer):
        """Extracted from original _handle_client: process a decrypted payload."""
        # recreate minimal version of previous logic for msg, manifest, chunk req/data
        try:
            if pkt_type == TYPE_REVOCATION:
                # peer announces its own key is revoked
                info = json.loads(payload.decode())
                raw = bytes.fromhex(info.get('payload',''))
                sig = bytes.fromhex(info.get('sig',''))
                # verify signature with peer's own public key if known
                if remote_id in self.peer_table and self.peer_table[remote_id].get('pubkey'):
                    import nacl.signing
                    verify = nacl.signing.VerifyKey(bytes.fromhex(self.peer_table[remote_id]['pubkey']))
                    try:
                        verify.verify(raw, sig)
                        print(f"[REVOCATION] received from {remote_id}")
                        # mark peer as not trusted and remove from table
                        self.peer_table[remote_id]['trusted'] = False
                        self.peer_table[remote_id]['revoked'] = True
                        self.save_peers()
                    except Exception:
                        print(f"[!] invalid revocation signature from {remote_id}")
                return
            if pkt_type == TYPE_MSG:
                if remote_id:
                    text = payload.decode(errors='ignore')
                    print(f"[MSG] {remote_id} -> {text}")
                    self.message_log.append({
                        "ts": int(time.time()),
                        "direction": "in",
                        "peer": remote_id,
                        "text": text,
                    })
                    if len(self.message_log) > 200:
                        self.message_log = self.message_log[-200:]
            elif pkt_type == TYPE_MANIFEST:
                if remote_id:
                    manifest = json.loads(payload.decode())
                    print(f"[MANIFEST] reçu de {remote_id} id={manifest.get('file_id')}")
                    self.manifests[manifest['file_id']] = manifest
                    self.dl_manager.register_manifest(manifest, remote_id)
                    self._log_event("transfer", f"Manifest received from {remote_id}: {manifest.get('file_id')}")
                    # update peer shared files list
                    entry = self.peer_table.get(remote_id)
                    if entry:
                        entry.setdefault('shared_files', []).append(manifest['file_id'])
            elif pkt_type == TYPE_CHUNK_REQ:
                req = json.loads(payload.decode())
                fid = req['file_id']; idx = req['chunk_idx']
                reply_port = req.get('reply_port', TCP_PORT)
                print(f"[CHUNK_REQ] {addr_or_peer} file={fid} idx={idx} reply_port={reply_port}")
                m = self.manifests.get(fid)
                print(f"[DBG] manifest pour {fid}: {m is not None}")
                if m:
                    filepath = m.get('filepath')
                    print(f"[DBG] filepath: {filepath}, exists: {os.path.exists(filepath) if filepath else False}")
                    if filepath and os.path.exists(filepath):
                        with open(filepath,'rb') as f:
                            f.seek(idx * m['chunk_size'])
                            data_chunk = f.read(m['chunks'][idx]['size'])
                            resp = {"file_id": fid, "chunk_idx": idx, "data": data_chunk.hex(), "chunk_hash": m['chunks'][idx]['hash']}
                            node_id_bytes = self._packet_node_id_bytes()
                            packet = build_packet(TYPE_CHUNK_DATA, node_id_bytes, json.dumps(resp).encode(), self.signing_key.encode(), hmac_key=self.session_keys.get(remote_id), encrypt_key=self.session_keys.get(remote_id))
                            requester_ip = addr_or_peer if isinstance(addr_or_peer, str) else addr_or_peer[0]
                            try:
                                with socket.create_connection((requester_ip, reply_port), timeout=5) as response_sock:
                                    response_sock.sendall(packet)
                                    print(f"[DBG] CHUNK_DATA sent back to {requester_ip}:{reply_port}, size={len(data_chunk)}")
                            except Exception as e2:
                                print(f"[!] Erreur envoi CHUNK_DATA back: {e2}")
            elif pkt_type == TYPE_CHUNK_DATA:
                resp = json.loads(payload.decode())
                print(f"[CHUNK_DATA] reçu idx={resp['chunk_idx']} hash={resp['chunk_hash']}")
                if remote_id:
                    self.dl_manager.handle_chunk_data(resp, remote_id)
                    self._update_reputation(remote_id, success=True)
        except Exception as e:
            print(f"[!] processing tcp message failed: {e}")
    def save_peers(self):
        """Sauvegarde la table de pairs sur disque"""
        try:
            with open(self.db_file, "w") as f:
                json.dump(self.peer_table, f)
        except Exception as e:
            print(f"[!] Erreur sauvegarde : {e}")

    # --- MODULE CRYPTO : IDENTITE ---
    def load_identity(self):
        """Charge une paire de clÃ©s Ed25519 depuis disque ou en crÃ©e une nouvelle.

        Le chemin du fichier peut Ãªtre personnalisÃ© avec la variable
        d'environnement `IDENTITY_FILE` pour permettre plusieurs nÅ“uds sur la
        mÃªme machine.
        """
        ident_file = os.environ.get('IDENTITY_FILE', 'identity.key')
        if os.path.exists(ident_file):
            try:
                import nacl.signing, binascii
                hexpriv = open(ident_file, "r").read().strip()
                priv = nacl.signing.SigningKey(binascii.unhexlify(hexpriv))
                return priv, priv.verify_key
            except Exception as e:
                print(f"[!] Impossible de charger identitÃ© : {e}")
        # gÃ©nÃ©rer nouvelle identitÃ©
        from crypto.identite import generate_identity
        priv, pub = generate_identity()
        # enregistrer la clÃ© privÃ©e en hex
        import binascii
        with open(ident_file, "w") as f:
            f.write(binascii.hexlify(priv.encode()).decode())
        return priv, pub

    def load_peers(self):
        """Charge la table de pairs depuis le disque"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, "r") as f:
                    raw = json.load(f)
                cleaned = {}
                if isinstance(raw, dict):
                    for pid, info in raw.items():
                        if not self._is_valid_node_id(pid):
                            continue
                        if not isinstance(info, dict):
                            continue
                        ip = info.get("ip")
                        port = info.get("tcp_port")
                        if not ip or not isinstance(port, int):
                            continue
                        cleaned[pid] = {
                            "ip": ip,
                            "tcp_port": port,
                            "last_seen": float(info.get("last_seen", 0) or 0),
                            "pubkey": info.get("pubkey"),
                            "trusted": bool(info.get("trusted", False)),
                            "trusted_at": int(info.get("trusted_at", 0) or 0),
                            "shared_files": info.get("shared_files", []),
                            "reputation": float(info.get("reputation", 0.0) or 0.0),
                        }
                self.peer_table = cleaned
                print(f"[*] {len(self.peer_table)} pairs chargÃ©s du disque.")
            except:
                self.peer_table = {}

    # --- MODULE 1.1 : DECOUVERTE (UDP) ---
    def _udp_announcer(self):
        """Emet un signal HELLO toutes les 30 secondes"""
        node_id_bytes = self._packet_node_id_bytes()
        send_ips = [self.local_ips[0]] if self.local_ips else ["0.0.0.0"]
        
        # Créer la socket UNE FOIS au lieu de la recréer à chaque fois
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        except Exception:
            pass

        while self.running:
            for local_ip in send_ips:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
                except Exception:
                    pass
                try:
                    # Payload avec timestamp pour le timeout et notre clÃ© publique
                    import binascii
                    payload = json.dumps({
                        "tcp_port": self.tcp_port,
                        "timestamp": int(time.time()),
                        "pubkey": binascii.hexlify(self.verify_key.encode()).decode(),
                    }).encode()
                    packet = build_packet(0x01, node_id_bytes, payload, self.signing_key.encode())
                    sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
                    print(f"[DBG] HELLO envoyÃ© depuis {local_ip} vers {MCAST_GRP}:{MCAST_PORT}")
                except Exception as e:
                    print(f"[!] Erreur Announcer({local_ip}): {e}")
            time.sleep(30)

    def _udp_listener(self):
        """Ecoute les HELLO et dÃ©clenche l'envoi de la PEER_LIST en TCP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', MCAST_PORT))

        joined = False
        # Join multicast on every detected local interface.
        for local_ip in (self.local_ips or []):
            try:
                mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(local_ip))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                joined = True
            except Exception:
                pass
        if not joined:
            try:
                mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                joined = True
            except Exception as e:
                print(f"[!] Erreur JOIN_MEMBERSHIP: {e}")

        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                # ne traiter que paquets commenÃ§ant par le magic
                if not data.startswith(b"ARCH"):
                    continue
                # Parser header/payload en utilisant la spÃ©cification du protocole
                try:
                    header_size = struct.calcsize(PACKET_FORMAT)
                    sig_len = 32
                    remote_id = data[5:37].hex()
                    payload_raw = data[header_size:len(data)-sig_len]
                    tcp_port = TCP_PORT
                    remote_pub = None
                    addr_ip = addr[0]
                    if payload_raw:
                        try:
                            info = json.loads(payload_raw.decode(errors='ignore'))
                            tcp_port = info.get('tcp_port', TCP_PORT)
                            if 'pubkey' in info:
                                remote_pub = str(info['pubkey']).lower()
                                if re.match(r"^[0-9a-f]{64}$", remote_pub):
                                    remote_id = remote_pub
                            addr_ip = addr[0]
                        except Exception:
                            addr_ip = addr[0]

                    if not self._is_valid_node_id(remote_id):
                        continue
                    if remote_id != self.node_uid:
                        # Ignore peers not in our local LAN scope.
                        if not self._is_local_candidate_ip(addr_ip):
                            continue
                        # Mise Ã  jour Peer Table (Module 1.2)
                        prev = self.peer_table.get(remote_id)
                        # check for pubkey change (MITM detection)
                        if prev and 'pubkey' in prev and remote_pub and prev.get('pubkey') and prev.get('pubkey') != remote_pub:
                            print(f"[!] PUBLIC KEY MISMATCH pour {remote_id} (possible MITM)")
                            self._log_event("security", f"Pubkey mismatch for {remote_id}")
                            # mark as untrusted
                            prev['trusted'] = False
                        entry = {
                            "ip": addr_ip,
                            "tcp_port": tcp_port,
                            "last_seen": time.time(),
                            # default fields
                            "shared_files": prev.get('shared_files', []) if prev else [],
                            "reputation": prev.get('reputation', 0.0) if prev else 0.0,
                        }
                        if remote_pub:
                            entry['pubkey'] = remote_pub
                        # preserve trusted flag if existed
                        if prev and prev.get('trusted'):
                            entry['trusted'] = True
                            entry['trusted_at'] = prev.get('trusted_at', int(time.time()))
                        self.peer_table[remote_id] = entry
                        self.save_peers()
                        if prev is None:
                            print(f"\n[+] Nouveau pair : {remote_id} @ {addr_ip}:{tcp_port}")
                            self._log_event("info", f"New peer: {remote_id} @ {addr_ip}:{tcp_port}")
                        elif prev.get("ip") != addr_ip or prev.get("tcp_port") != tcp_port:
                            print(f"\n[~] Pair mis Ã  jour : {remote_id} @ {addr_ip}:{tcp_port}")
                            self._log_event("info", f"Peer endpoint changed: {remote_id} @ {addr_ip}:{tcp_port}")

                        # Module 1.1 : RÃ©ponse PEER_LIST en unicast TCP
                        threading.Thread(target=self.send_peer_list, args=(addr_ip, tcp_port), daemon=True).start()
                except Exception as e:
                    print(f"[!] Erreur parsing UDP packet: {e}")
            except:
                pass

    # --- MODULE 1.1 & 1.3 : COMMUNICATION (TCP) ---
    def send_peer_list(self, target_ip, target_port):
        """Envoie la liste des pairs connus via TCP (non chiffrÃ©e)."""
        try:
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self._packet_node_id_bytes()
                # Type PEER_LIST
                payload = json.dumps(self.peer_table).encode()
                packet = build_packet(TYPE_PEER_LIST, node_id_bytes, payload, self.signing_key.encode())
                sock.sendall(packet)
        except Exception:
            pass  # Le pair n'est peut-Ãªtre pas encore prÃªt en TCP

    # --- MODULE 3.1/3.3 : MANIFEST & CHUNK TRANSFERT ---
    def send_manifest(self, target_ip, target_port, manifest):
        """Envoie le manifest Ã  un pair donnÃ© (via connection handshake)."""
        # try to determine peer_id by matching ip/port in table
        peer_id = None
        for pid, info in self.peer_table.items():
            if info.get('ip') == target_ip and info.get('tcp_port') == target_port:
                peer_id = pid
                break
        try:
            if peer_id:
                sock = self._get_connection(peer_id)
                session_key = self.session_keys.get(peer_id)
                node_id_bytes = self._packet_node_id_bytes()
                payload = json.dumps(manifest).encode()
                packet = build_packet(TYPE_MANIFEST, node_id_bytes, payload, self.signing_key.encode(), hmac_key=session_key, encrypt_key=session_key)
                sock.sendall(packet)
            else:
                # fallback to simple TCP send if peer unknown
                with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                    node_id_bytes = self._packet_node_id_bytes()
                    payload = json.dumps(manifest).encode()
                    packet = build_packet(TYPE_MANIFEST, node_id_bytes, payload, self.signing_key.encode())
                    sock.sendall(packet)
        except Exception as e:
            print(f"[!] Erreur send_manifest: {e}")

    def request_chunk(self, target_ip, target_port, file_id, chunk_idx):
        """Demande un chunk via TCP (avec handshake si possible)"""
        peer_id = None
        for pid, info in self.peer_table.items():
            if info.get('ip') == target_ip and info.get('tcp_port') == target_port:
                peer_id = pid
                break
        try:
            if peer_id:
                sock = self._get_connection(peer_id)
                session_key = self.session_keys.get(peer_id)
                node_id_bytes = self._packet_node_id_bytes()
                payload = json.dumps({"file_id": file_id, "chunk_idx": chunk_idx, "reply_port": self.tcp_port}).encode()
                packet = build_packet(TYPE_CHUNK_REQ, node_id_bytes, payload, self.signing_key.encode(), hmac_key=session_key, encrypt_key=session_key)
                sock.sendall(packet)
            else:
                with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                    node_id_bytes = self._packet_node_id_bytes()
                    payload = json.dumps({"file_id": file_id, "chunk_idx": chunk_idx, "reply_port": self.tcp_port}).encode()
                    packet = build_packet(TYPE_CHUNK_REQ, node_id_bytes, payload, self.signing_key.encode())
                    sock.sendall(packet)
        except Exception as e:
            print(f"[!] Erreur request_chunk: {e}")

    def send_file(self, peer_id, filepath):
        """CrÃ©e un manifest local et l'envoie Ã  un pair prÃ©cis."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(filepath)
        entry = self.peer_table.get(peer_id)
        if not entry:
            raise KeyError(f"Pair inconnu: {peer_id}")
        import transfer.manifest as mf
        manifest = mf.create_manifest(filepath)
        manifest["filepath"] = filepath
        manifest["sender_id"] = self.node_uid
        # Broadcast le manifest Ã  tous les pairs (pas de restriction allowed_peers)
        self.manifests[manifest["file_id"]] = manifest
        self.send_manifest(entry["ip"], entry["tcp_port"], manifest)
        self._log_event("info", f"Manifest sent to {peer_id}: {manifest['file_id']}")
        return manifest["file_id"]

    def available_files(self):
        """Retourne les manifests actuellement connus."""
        return list(self.dl_manager.sessions.keys())

    def trust_peer(self, peer_id):
        """Marque un pair comme approuvÃ© localement (TOFU simplifiÃ©)."""
        if peer_id not in self.peer_table:
            raise KeyError(f"Pair inconnu: {peer_id}")
        self.peer_table[peer_id]["trusted"] = True
        self.peer_table[peer_id]["trusted_at"] = int(time.time())
        self.save_peers()
        self._log_event("security", f"Peer trusted: {peer_id}")

    def sign_peer(self, peer_id):
        """Signer la clÃ© publique d'un pair pour propagation dans le Web of Trust.

        Retourne la signature hexadÃ©cimale.
        """
        info = self.peer_table.get(peer_id)
        if not info or 'pubkey' not in info:
            raise KeyError("Pair inconnu ou pas de clÃ© publique.")
        pub = bytes.fromhex(info['pubkey'])
        sig = self.signing_key.sign(pub).signature
        info.setdefault('signatures', {})[self.node_id] = sig.hex()
        self.save_peers()
        return sig.hex()

    def revoke_self(self):
        """GÃ©nÃ¨re et diffuse un message de rÃ©vocation de sa propre clÃ©"""
        rev = {
            'node_id': self.node_id,
            'timestamp': int(time.time())
        }
        payload = json.dumps(rev).encode()
        sig = self.signing_key.sign(payload).signature.hex()
        pkt = build_packet(TYPE_REVOCATION, self._packet_node_id_bytes(), json.dumps({'payload': payload.hex(), 'sig': sig}).encode(), self.signing_key.encode())
        # broadcast unencrypted to all peers
        for pid, info in list(self.peer_table.items()):
            try:
                sock = self._get_connection(pid)
                sock.sendall(pkt)
            except Exception:
                pass
        self._log_event("security", "Revocation message broadcast")

    def node_status(self):
        """Etat synthÃ©tique pour la CLI."""
        status = {
            "node_id": self.node_uid,
            "tcp_port": self.tcp_port,
            "peers": len(self.peer_table),
            "known_manifests": len(self.dl_manager.sessions),
            "downloads": {},
            "messages": self.message_log[-50:],
            "events": self.event_log[-100:],
        }
        for fid, sess in self.dl_manager.sessions.items():
            done, total = sess.progress()
            status["downloads"][fid] = {"done": done, "total": total, "file": sess.save_path}
        return status

    # --- MODULE 2.1 & 2.4 : CHIFFREMENT E2E ---
    def encrypt_for_peer(self, peer_id, plaintext: bytes) -> bytes:
        """Retourne des donnÃ©es chiffrÃ©es pour le pair donnÃ© en utilisant NaCl Box."""
        import nacl.public
        import nacl.signing
        entry = self.peer_table.get(peer_id)
        if not entry or 'pubkey' not in entry:
            raise ValueError("ClÃ© publique du pair inconnue")
        peer_pub = bytes.fromhex(entry['pubkey'])
        # convertir pubkey Ed25519 en Curve25519
        peer_verify = nacl.signing.VerifyKey(peer_pub)
        peer_curve = peer_verify.to_curve25519_public_key()
        box = nacl.public.Box(self.curve_priv, peer_curve)
        return box.encrypt(plaintext)

    def decrypt_from_peer(self, peer_id, ciphertext: bytes) -> bytes:
        import nacl.public
        import nacl.signing
        entry = self.peer_table.get(peer_id)
        if not entry or 'pubkey' not in entry:
            raise ValueError("ClÃ© publique du pair inconnue")
        peer_pub = bytes.fromhex(entry['pubkey'])
        peer_verify = nacl.signing.VerifyKey(peer_pub)
        peer_curve = peer_verify.to_curve25519_public_key()
        box = nacl.public.Box(self.curve_priv, peer_curve)
        return box.decrypt(ciphertext)

    def send_message(self, peer_id, message: str):
        """Envoie un message (après handshake) chiffrÃ© avec la clÃ© de session."""
        if peer_id not in self.peer_table:
            raise KeyError(f"Pair {peer_id} inconnu")
        payload = message.encode()
        try:
            sock = self._get_connection(peer_id)
            session_key = self.session_keys.get(peer_id)
            node_id_bytes = self._packet_node_id_bytes()
            packet = build_packet(TYPE_MSG, node_id_bytes, payload, self.signing_key.encode(), hmac_key=session_key, encrypt_key=session_key)
            sock.sendall(packet)
            self.message_log.append({
                "ts": int(time.time()),
                "direction": "out",
                "peer": peer_id,
                "text": message,
            })
            if len(self.message_log) > 200:
                self.message_log = self.message_log[-200:]
        except Exception as e:
            self._log_event("error", f"Message send failed to {peer_id}: {e}")
            raise RuntimeError(f"Erreur envoi message Ã  {peer_id}: {e}")

    def _tcp_server(self):
        """Serveur TCP gÃ©rant au moins 10 connexions (Module 1.3)"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.tcp_port))
        server.listen(10)
        print(f"[*] Serveur TCP d'Ã©coute activÃ© sur le port {self.tcp_port}")

        while self.running:
            try:
                client_sock, addr = server.accept()
                threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True).start()
            except:
                break

    def _handle_client(self, sock, addr):
        """Accept incoming TCP connection, perform handshake, and then read messages."""
        peer_id = None
        try:
            peer_id, session_key = self._handshake_responder(sock)
            if peer_id:
                self.session_keys[peer_id] = session_key
                self.peer_connections[peer_id] = sock
                threading.Thread(target=self._keepalive_loop, args=(peer_id,), daemon=True).start()
                # block until connection closes
                self._connection_reader(sock, peer_id)
        except Exception as e:
            print(f"[!] incoming handshake/connection failed from {addr}: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
            if peer_id and peer_id in self.peer_connections:
                del self.peer_connections[peer_id]

    # --- MODULE 1.1 : TIMEOUT 90s ---
    def _garbage_collector(self):
        """Supprime les nÅ“uds inactifs depuis plus de 90 secondes"""
        while self.running:
            now = time.time()
            to_delete = []
            for pid, info in self.peer_table.items():
                if now - info['last_seen'] > 90:
                    to_delete.append(pid)

            for pid in to_delete:
                print(f"\n[-] NÅ“ud {pid} dÃ©connectÃ© (Timeout 90s)")
                del self.peer_table[pid]

            if to_delete:
                self.save_peers()
            time.sleep(10)

    def start(self):
        """Lance les services rÃ©seau"""
        threading.Thread(target=self._udp_announcer, daemon=True).start()
        threading.Thread(target=self._udp_listener, daemon=True).start()
        threading.Thread(target=self._tcp_server, daemon=True).start()
        threading.Thread(target=self._garbage_collector, daemon=True).start()
        print(f"--- NÅ“ud Archipel [{self.node_id}] OpÃ©rationnel ---")


if __name__ == "__main__":
    # Test S1: Instanciation simple pour exécution locale
    node = ArchipelNode(tcp_port=7777)
    node.start()

    # thread affichant pÃ©riodiquement la table de pairs
    def status_loop():
        while node.running:
            print(f"\n[Peer Table] {len(node.peer_table)} pairs en ligne.")
            for pid, info in node.peer_table.items():
                pub = info.get('pubkey','')[:8]
                print(f" - {pid} ({info['ip']}:{info.get('tcp_port')}) pub={pub}...")
            time.sleep(15)

    threading.Thread(target=status_loop, daemon=True).start()

    # --- CLI interactif minimal et commandes Sprint4
    print("Commande: peers | msg <node_id> <texte> | send <peer_id> <file> | receive | download <file_id> [path] | status | trust <node_id> | quit")
    try:
        while True:
            try:
                cmd = input('> ').strip()
            except EOFError:
                break
            if not cmd:
                continue
            parts = cmd.split(' ', 3)
            if parts[0] == 'quit':
                break
            elif parts[0] == 'peers':
                for pid, info in node.peer_table.items():
                    print(pid, info)
            elif parts[0] == 'msg' and len(parts) >= 3:
                node.send_message(parts[1], parts[2])
            elif parts[0] == 'send' and len(parts) == 3:
                # send a file manifest to the specified peer
                try:
                    fid = node.send_file(parts[1], parts[2])
                    print(f"Manifest envoye; file_id={fid}")
                except Exception as e:
                    print(f"Erreur send: {e}")
            elif parts[0] == 'receive':
                if not node.dl_manager.sessions:
                    print("Aucun fichier annonce.")
                for fid, sess in node.dl_manager.sessions.items():
                    done, total = sess.progress()
                    print(f"{fid} | file={sess.save_path} | progress={done}/{total}")
            elif parts[0] == 'download' and len(parts) >= 2:
                fid = parts[1]
                path = parts[2] if len(parts) == 3 else None
                node.dl_manager.start_download(fid, path)
                print(f"Demarrage download {fid}")
            elif parts[0] == 'trust' and len(parts) == 2:
                try:
                    node.trust_peer(parts[1])
                    print(f"{parts[1]} marque comme trusted.")
                except Exception as e:
                    print(f"Erreur trust: {e}")
            elif parts[0] == 'download' and len(parts) >= 2:
                fid = parts[1]
                path = parts[2] if len(parts) == 3 else None
                try:
                    node.dl_manager.start_download(fid, path)
                    print(f"[DL] dÃ©marrage du tÃ©lÃ©chargement {fid}")
                except Exception as e:
                    print(f"[!] impossible de dÃ©marrer download: {e}")
            elif parts[0] == 'status':
                for fid, sess in node.dl_manager.sessions.items():
                    done, total = sess.progress()
                    print(f"{fid}: {done}/{total}")
            else:
                print("Usage: peers | msg <node_id> <texte> | manifest <file> | download <file_id> [path] | status | quit")
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[!] ArrÃªt du nÅ“ud...")
        node.running = False


