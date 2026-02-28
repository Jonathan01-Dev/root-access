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


class ArchipelNode:
    def __init__(self, node_id, identity=None, tcp_port=None, db_file=None, local_ip=None):
        self.node_id = node_id
        # allow overriding the TCP port per-instance (for tests/multi-nodes)
        self.tcp_port = tcp_port if tcp_port is not None else TCP_PORT
        # identite : tuple (signing_priv, verify_pub)
        if identity is None:
            # essayer de charger clÃ©s depuis disque
            self.signing_key, self.verify_key = self.load_identity()
        else:
            self.signing_key, self.verify_key = identity

        # dÃ©rivÃ©s Curve25519 pour chiffrement
        self.curve_priv = self.signing_key.to_curve25519_private_key()
        self.curve_pub = self.verify_key.to_curve25519_public_key()
        self.node_uid = self.verify_key.encode().hex()

        self.peer_table = {}  # Module 1.2: Table de pairs
        # stockage des manifests reÃ§us (file_id -> manifest dict)
        self.manifests = {}
        self.message_log = []
        self.event_log = []

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

    # --- MODULE 1.2 : PERSISTANCE ---
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

        while self.running:
            for local_ip in send_ips:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
                except Exception:
                    pass
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
                    packet = build_packet(0x01, node_id_bytes, payload, b"test_secret_key")
                    sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
                    print(f"[DBG] HELLO envoyÃ© depuis {local_ip} vers {MCAST_GRP}:{MCAST_PORT}")
                except Exception as e:
                    print(f"[!] Erreur Announcer({local_ip}): {e}")
                finally:
                    sock.close()
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
                        entry = {
                            "ip": addr_ip,
                            "tcp_port": tcp_port,
                            "last_seen": time.time()
                        }
                        if remote_pub:
                            entry['pubkey'] = remote_pub
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
                packet = build_packet(TYPE_PEER_LIST, node_id_bytes, payload, b"test_secret_key")
                sock.sendall(packet)
        except Exception:
            pass  # Le pair n'est peut-Ãªtre pas encore prÃªt en TCP

    # --- MODULE 3.1/3.3 : MANIFEST & CHUNK TRANSFERT ---
    def send_manifest(self, target_ip, target_port, manifest):
        """Envoie le manifest chiffrÃ© Ã  un pair donnÃ©"""
        try:
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self._packet_node_id_bytes()
                payload = json.dumps(manifest).encode()
                packet = build_packet(TYPE_MANIFEST, node_id_bytes, payload, b"test_secret_key")
                sock.sendall(packet)
        except Exception as e:
            print(f"[!] Erreur send_manifest: {e}")

    def request_chunk(self, target_ip, target_port, file_id, chunk_idx):
        """Demande un chunk via TCP"""
        try:
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self._packet_node_id_bytes()
                payload = json.dumps({"file_id": file_id, "chunk_idx": chunk_idx, "reply_port": self.tcp_port}).encode()
                packet = build_packet(TYPE_CHUNK_REQ, node_id_bytes, payload, b"test_secret_key")
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
        """Envoie un message chiffrÃ© (type 0x03) au pair identifiÃ©."""
        entry = self.peer_table.get(peer_id)
        if not entry:
            raise KeyError(f"Pair {peer_id} inconnu")
        target_ip = entry['ip']
        target_port = entry['tcp_port']
        try:
            ciphertext = self.encrypt_for_peer(peer_id, message.encode())
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self._packet_node_id_bytes()
                packet = build_packet(0x03, node_id_bytes, ciphertext, b"test_secret_key")
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
        """GÃ¨re les messages TCP entrants (TLV)"""
        with sock:
            try:
                header_size = struct.calcsize(PACKET_FORMAT)
                sig_len = 32

                def recv_exact(n):
                    buf = b""
                    while len(buf) < n:
                        chunk = sock.recv(n - len(buf))
                        if not chunk:
                            return None
                        buf += chunk
                    return buf

                header = recv_exact(header_size)
                if not header:
                    return
                if not header.startswith(b"ARCH"):
                    return
                try:
                    _, _, _, payload_len = struct.unpack(PACKET_FORMAT, header)
                except Exception:
                    return
                payload = recv_exact(payload_len)
                sig = recv_exact(sig_len)
                if payload is None or sig is None:
                    return
                data = header + payload + sig
                if data and data.startswith(b"ARCH"):
                    msg_type = data[4]
                    # Resolve remote_id from packet header first; fallback to key match then IP.
                    remote_id = data[5:37].hex()
                    if remote_id not in self.peer_table:
                        for pid, info in self.peer_table.items():
                            if info.get("pubkey") == remote_id:
                                remote_id = pid
                                break
                    if not remote_id or remote_id not in self.peer_table:
                        remote_id = None
                        for pid, info in self.peer_table.items():
                            if info.get('ip') == addr[0]:
                                remote_id = pid
                                break
                    if msg_type == TYPE_PEER_LIST:
                        # Keep PEER_LIST for compatibility but avoid polluting local view.
                        pass
                    elif msg_type == TYPE_MSG:
                        try:
                            if remote_id:
                                payload = data[struct.calcsize(PACKET_FORMAT):-32]
                                plaintext = self.decrypt_from_peer(remote_id, payload)
                                text = plaintext.decode(errors='ignore')
                                print(f"[MSG] {remote_id} -> {text}")
                                self.message_log.append({
                                    "ts": int(time.time()),
                                    "direction": "in",
                                    "peer": remote_id,
                                    "text": text,
                                })
                                if len(self.message_log) > 200:
                                    self.message_log = self.message_log[-200:]
                        except Exception as e:
                            print(f"[!] Erreur dÃ©cryptage message: {e}")
                    elif msg_type == TYPE_MANIFEST:
                        try:
                            if remote_id:
                                payload = data[struct.calcsize(PACKET_FORMAT):-32]
                                manifest = json.loads(payload.decode())
                                print(f"[MANIFEST] reÃ§u de {remote_id} id={manifest.get('file_id')}")
                                self.manifests[manifest['file_id']] = manifest
                                # inform download manager
                                self.dl_manager.register_manifest(manifest, remote_id)
                                self._log_event("transfer", f"Manifest received from {remote_id}: {manifest.get('file_id')}")
                        except Exception as e:
                            print(f"[!] Erreur manifest: {e}")
                    elif msg_type == TYPE_CHUNK_REQ:
                        try:
                            payload = data[struct.calcsize(PACKET_FORMAT):-32]
                            req = json.loads(payload.decode())
                            fid = req['file_id']; idx = req['chunk_idx']
                            reply_port = req.get('reply_port', TCP_PORT)
                            print(f"[CHUNK_REQ] {addr} file={fid} idx={idx} reply_port={reply_port}")
                            # rechercher manifest local
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
                                        packet = build_packet(TYPE_CHUNK_DATA, node_id_bytes, json.dumps(resp).encode(), b"test_secret_key")
                                        # Send back to the requester on a NEW connection
                                        requester_ip = addr[0]
                                        try:
                                            with socket.create_connection((requester_ip, reply_port), timeout=5) as response_sock:
                                                response_sock.sendall(packet)
                                                print(f"[DBG] CHUNK_DATA sent back to {requester_ip}:{reply_port}, size={len(data_chunk)}")
                                        except Exception as e2:
                                            print(f"[!] Erreur envoi CHUNK_DATA back: {e2}")
                        except Exception as e:
                            print(f"[!] Erreur CHUNK_REQ: {e}")
                            import traceback
                            traceback.print_exc()
                    elif msg_type == TYPE_CHUNK_DATA:
                        try:
                            payload = data[struct.calcsize(PACKET_FORMAT):-32]
                            resp = json.loads(payload.decode())
                            print(f"[CHUNK_DATA] reÃ§u idx={resp['chunk_idx']} hash={resp['chunk_hash']}")
                            # delegate to download manager
                            if remote_id:
                                self.dl_manager.handle_chunk_data(resp, remote_id)
                        except Exception as e:
                            print(f"[!] Erreur CHUNK_DATA: {e}")
            except Exception as e:
                print(f"[!] Erreur TCP client: {e}")

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
    # Test S1: Utiliser un ID basÃ© sur le temps pour lancer plusieurs instances sur le mÃªme PC
    import random

    TEST_ID = f"NODE_{random.randint(1000, 9999)}"

    node = ArchipelNode(TEST_ID)
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
    print("Commande: peers | msg <node_id> <texte> | manifest <file> | download <file_id> [path] | status | quit")
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
            elif parts[0] == 'manifest' and len(parts) == 2:
                # envoie le manifest d'un fichier au premier peer (demo)
                import transfer.manifest as mf
                manifest = mf.create_manifest(parts[1])
                manifest['filepath'] = parts[1]
                # broadcast to all known peers
                for pid, info in node.peer_table.items():
                    node.send_manifest(info['ip'], info['tcp_port'], manifest)
                print("Manifest envoyÃ©")
            elif parts[0] == 'chunk' and len(parts) == 4:
                _, dest, fid, idx = parts
                for pid, info in node.peer_table.items():
                    if pid == dest:
                        node.request_chunk(info['ip'], info['tcp_port'], fid, int(idx))
                        break
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


