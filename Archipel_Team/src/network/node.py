import socket
import threading
import time
import json
import struct
import os
from .protocole import build_packet, PACKET_FORMAT

# Configuration conforme au document technique
MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
# défaut, mais peut être surchargé via variable d'environnement pour tests
TCP_PORT = int(os.environ.get('TCP_PORT', '7777'))

# types de paquet
TYPE_HELLO     = 0x01
TYPE_PEER_LIST = 0x02
TYPE_MSG       = 0x03
TYPE_CHUNK_REQ = 0x04
TYPE_CHUNK_DATA= 0x05
TYPE_MANIFEST  = 0x06


class ArchipelNode:
    def __init__(self, node_id, identity=None, tcp_port=None):
        self.node_id = node_id
        # allow overriding the TCP port per-instance (for tests/multi-nodes)
        self.tcp_port = tcp_port if tcp_port is not None else TCP_PORT
        # identite : tuple (signing_priv, verify_pub)
        if identity is None:
            # essayer de charger clés depuis disque
            self.signing_key, self.verify_key = self.load_identity()
        else:
            self.signing_key, self.verify_key = identity

        # dérivés Curve25519 pour chiffrement
        self.curve_priv = self.signing_key.to_curve25519_private_key()
        self.curve_pub = self.verify_key.to_curve25519_public_key()

        self.peer_table = {}  # Module 1.2: Table de pairs
        # stockage des manifests reçus (file_id -> manifest dict)
        self.manifests = {}
        self.message_log = []
        self.event_log = []

        # download manager (Sprint 4)
        from transfer.manager import DownloadManager
        self.dl_manager = DownloadManager(self)

        self.running = True
        self.db_file = "peer_table.json"
        self.load_peers()  # Charger les pairs existants au démarrage

    def _log_event(self, level, text):
        item = {"ts": int(time.time()), "level": level, "text": text}
        self.event_log.append(item)
        if len(self.event_log) > 200:
            self.event_log = self.event_log[-200:]

    def _resolve_local_ip(self):
        """Best-effort local IP selection without any internet dependency."""
        try:
            candidates = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            for cand in candidates:
                ip = cand[4][0]
                if not ip.startswith("127."):
                    return ip
        except Exception:
            pass
        return "0.0.0.0"

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
        """Charge une paire de clés Ed25519 depuis disque ou en crée une nouvelle.

        Le chemin du fichier peut être personnalisé avec la variable
        d'environnement `IDENTITY_FILE` pour permettre plusieurs nœuds sur la
        même machine.
        """
        ident_file = os.environ.get('IDENTITY_FILE', 'identity.key')
        if os.path.exists(ident_file):
            try:
                import nacl.signing, binascii
                hexpriv = open(ident_file, "r").read().strip()
                priv = nacl.signing.SigningKey(binascii.unhexlify(hexpriv))
                return priv, priv.verify_key
            except Exception as e:
                print(f"[!] Impossible de charger identité : {e}")
        # générer nouvelle identité
        from crypto.identite import generate_identity
        priv, pub = generate_identity()
        # enregistrer la clé privée en hex
        import binascii
        with open(ident_file, "w") as f:
            f.write(binascii.hexlify(priv.encode()).decode())
        return priv, pub

    def load_peers(self):
        """Charge la table de pairs depuis le disque"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, "r") as f:
                    self.peer_table = json.load(f)
                print(f"[*] {len(self.peer_table)} pairs chargés du disque.")
            except:
                self.peer_table = {}

    # --- MODULE 1.1 : DECOUVERTE (UDP) ---
    def _udp_announcer(self):
        """Emet un signal HELLO toutes les 30 secondes"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        # Activer le loopback pour voir ses propres annonces en local
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        except Exception:
            pass

        # Sélectionner automatiquement l'interface locale pour le multicast
        try:
            local_ip = self._resolve_local_ip()
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        except Exception:
            local_ip = '0.0.0.0'
        node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]

        while self.running:
            try:
                # Payload avec timestamp pour le timeout et notre clé publique
                import binascii
                payload = json.dumps({
                    "tcp_port": self.tcp_port,
                    "timestamp": int(time.time()),
                    "pubkey": binascii.hexlify(self.verify_key.encode()).decode()
                }).encode()
                packet = build_packet(0x01, node_id_bytes, payload, b"test_secret_key")
                sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
                print(f"[DBG] HELLO envoyé depuis {local_ip} vers {MCAST_GRP}:{MCAST_PORT}")
            except Exception as e:
                print(f"[!] Erreur Announcer: {e}")
            time.sleep(30)

    def _udp_listener(self):
        """Ecoute les HELLO et déclenche l'envoi de la PEER_LIST en TCP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', MCAST_PORT))

        # Joindre le groupe multicast sur l'interface locale si possible
        try:
            local_ip = self._resolve_local_ip()
            mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(local_ip))
        except Exception:
            mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)

        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception as e:
            print(f"[!] Erreur JOIN_MEMBERSHIP: {e}")

        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                # ne traiter que paquets commençant par le magic
                if not data.startswith(b"ARCH"):
                    continue
                # Parser header/payload en utilisant la spécification du protocole
                try:
                    header_size = struct.calcsize(PACKET_FORMAT)
                    sig_len = 32
                    remote_id = data[5:37].decode(errors='ignore').strip('\0')
                    payload_raw = data[header_size:len(data)-sig_len]
                    tcp_port = TCP_PORT
                    remote_pub = None
                    if payload_raw:
                        try:
                            info = json.loads(payload_raw.decode(errors='ignore'))
                            tcp_port = info.get('tcp_port', TCP_PORT)
                            if 'pubkey' in info:
                                remote_pub = info['pubkey']
                        except Exception:
                            pass

                    if remote_id != self.node_id:
                        # Mise à jour Peer Table (Module 1.2)
                        entry = {
                            "ip": addr[0],
                            "tcp_port": tcp_port,
                            "last_seen": time.time()
                        }
                        if remote_pub:
                            entry['pubkey'] = remote_pub
                        self.peer_table[remote_id] = entry
                        self.save_peers()
                        print(f"\n[+] Nouveau pair : {remote_id} @ {addr[0]}:{tcp_port}")
                        self._log_event("info", f"Peer update: {remote_id} @ {addr[0]}:{tcp_port}")

                        # Module 1.1 : Réponse PEER_LIST en unicast TCP
                        threading.Thread(target=self.send_peer_list, args=(addr[0], tcp_port), daemon=True).start()
                except Exception as e:
                    print(f"[!] Erreur parsing UDP packet: {e}")
            except:
                pass

    # --- MODULE 1.1 & 1.3 : COMMUNICATION (TCP) ---
    def send_peer_list(self, target_ip, target_port):
        """Envoie la liste des pairs connus via TCP (non chiffrée)."""
        try:
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]
                # Type PEER_LIST
                payload = json.dumps(self.peer_table).encode()
                packet = build_packet(TYPE_PEER_LIST, node_id_bytes, payload, b"test_secret_key")
                sock.sendall(packet)
        except Exception:
            pass  # Le pair n'est peut-être pas encore prêt en TCP

    # --- MODULE 3.1/3.3 : MANIFEST & CHUNK TRANSFERT ---
    def send_manifest(self, target_ip, target_port, manifest):
        """Envoie le manifest chiffré à un pair donné"""
        try:
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]
                payload = json.dumps(manifest).encode()
                packet = build_packet(TYPE_MANIFEST, node_id_bytes, payload, b"test_secret_key")
                sock.sendall(packet)
        except Exception as e:
            print(f"[!] Erreur send_manifest: {e}")

    def request_chunk(self, target_ip, target_port, file_id, chunk_idx):
        """Demande un chunk via TCP"""
        try:
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]
                payload = json.dumps({"file_id": file_id, "chunk_idx": chunk_idx, "reply_port": self.tcp_port}).encode()
                packet = build_packet(TYPE_CHUNK_REQ, node_id_bytes, payload, b"test_secret_key")
                sock.sendall(packet)
        except Exception as e:
            print(f"[!] Erreur request_chunk: {e}")

    def send_file(self, peer_id, filepath):
        """Crée un manifest local et l'envoie à un pair précis."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(filepath)
        entry = self.peer_table.get(peer_id)
        if not entry:
            raise KeyError(f"Pair inconnu: {peer_id}")
        import transfer.manifest as mf
        manifest = mf.create_manifest(filepath)
        manifest["filepath"] = filepath
        manifest["sender_id"] = self.node_id
        self.manifests[manifest["file_id"]] = manifest
        self.send_manifest(entry["ip"], entry["tcp_port"], manifest)
        self._log_event("info", f"Manifest sent to {peer_id}: {manifest['file_id']}")
        return manifest["file_id"]

    def available_files(self):
        """Retourne les manifests actuellement connus."""
        return list(self.dl_manager.sessions.keys())

    def trust_peer(self, peer_id):
        """Marque un pair comme approuvé localement (TOFU simplifié)."""
        if peer_id not in self.peer_table:
            raise KeyError(f"Pair inconnu: {peer_id}")
        self.peer_table[peer_id]["trusted"] = True
        self.peer_table[peer_id]["trusted_at"] = int(time.time())
        self.save_peers()
        self._log_event("security", f"Peer trusted: {peer_id}")

    def node_status(self):
        """Etat synthétique pour la CLI."""
        status = {
            "node_id": self.node_id,
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
        """Retourne des données chiffrées pour le pair donné en utilisant NaCl Box."""
        import nacl.public
        import nacl.signing
        entry = self.peer_table.get(peer_id)
        if not entry or 'pubkey' not in entry:
            raise ValueError("Clé publique du pair inconnue")
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
            raise ValueError("Clé publique du pair inconnue")
        peer_pub = bytes.fromhex(entry['pubkey'])
        peer_verify = nacl.signing.VerifyKey(peer_pub)
        peer_curve = peer_verify.to_curve25519_public_key()
        box = nacl.public.Box(self.curve_priv, peer_curve)
        return box.decrypt(ciphertext)

    def send_message(self, peer_id, message: str):
        """Envoie un message chiffré (type 0x03) au pair identifié."""
        entry = self.peer_table.get(peer_id)
        if not entry:
            print(f"[!] Pair {peer_id} inconnu")
            return
        target_ip = entry['ip']
        target_port = entry['tcp_port']
        try:
            ciphertext = self.encrypt_for_peer(peer_id, message.encode())
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]
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
            print(f"[!] Erreur envoi message à {peer_id}: {e}")

    def _tcp_server(self):
        """Serveur TCP gérant au moins 10 connexions (Module 1.3)"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.tcp_port))
        server.listen(10)
        print(f"[*] Serveur TCP d'écoute activé sur le port {self.tcp_port}")

        while self.running:
            try:
                client_sock, addr = server.accept()
                threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True).start()
            except:
                break

    def _handle_client(self, sock, addr):
        """Gère les messages TCP entrants (TLV)"""
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
                    # Resolve remote_id from packet header first; fallback to peer_table by IP.
                    remote_id = data[5:37].decode(errors='ignore').strip('\0')
                    if not remote_id or remote_id not in self.peer_table:
                        remote_id = None
                        for pid, info in self.peer_table.items():
                            if info.get('ip') == addr[0]:
                                remote_id = pid
                                break
                    if msg_type == TYPE_PEER_LIST:
                        print(f"[TCP] Peer List reçue de {addr[0]}")
                        # fusion simplifiée des tables
                        try:
                            peers = json.loads(data[struct.calcsize(PACKET_FORMAT):-32].decode())
                            self.peer_table.update(peers)
                        except Exception:
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
                            print(f"[!] Erreur décryptage message: {e}")
                    elif msg_type == TYPE_MANIFEST:
                        try:
                            if remote_id:
                                payload = data[struct.calcsize(PACKET_FORMAT):-32]
                                manifest = json.loads(payload.decode())
                                print(f"[MANIFEST] reçu de {remote_id} id={manifest.get('file_id')}")
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
                                        node_id_bytes = self.node_id.encode().ljust(32,b'\0')[:32]
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
                            print(f"[CHUNK_DATA] reçu idx={resp['chunk_idx']} hash={resp['chunk_hash']}")
                            # delegate to download manager
                            if remote_id:
                                self.dl_manager.handle_chunk_data(resp, remote_id)
                        except Exception as e:
                            print(f"[!] Erreur CHUNK_DATA: {e}")
            except Exception as e:
                print(f"[!] Erreur TCP client: {e}")

    # --- MODULE 1.1 : TIMEOUT 90s ---
    def _garbage_collector(self):
        """Supprime les nœuds inactifs depuis plus de 90 secondes"""
        while self.running:
            now = time.time()
            to_delete = []
            for pid, info in self.peer_table.items():
                if now - info['last_seen'] > 90:
                    to_delete.append(pid)

            for pid in to_delete:
                print(f"\n[-] Nœud {pid} déconnecté (Timeout 90s)")
                del self.peer_table[pid]

            if to_delete:
                self.save_peers()
            time.sleep(10)

    def start(self):
        """Lance les services réseau"""
        threading.Thread(target=self._udp_announcer, daemon=True).start()
        threading.Thread(target=self._udp_listener, daemon=True).start()
        threading.Thread(target=self._tcp_server, daemon=True).start()
        threading.Thread(target=self._garbage_collector, daemon=True).start()
        print(f"--- Nœud Archipel [{self.node_id}] Opérationnel ---")


if __name__ == "__main__":
    # Test S1: Utiliser un ID basé sur le temps pour lancer plusieurs instances sur le même PC
    import random

    TEST_ID = f"NODE_{random.randint(1000, 9999)}"

    node = ArchipelNode(TEST_ID)
    node.start()

    # thread affichant périodiquement la table de pairs
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
                print("Manifest envoyé")
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
                    print(f"[DL] démarrage du téléchargement {fid}")
                except Exception as e:
                    print(f"[!] impossible de démarrer download: {e}")
            elif parts[0] == 'status':
                for fid, sess in node.dl_manager.sessions.items():
                    done, total = sess.progress()
                    print(f"{fid}: {done}/{total}")
            else:
                print("Usage: peers | msg <node_id> <texte> | manifest <file> | download <file_id> [path] | status | quit")
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[!] Arrêt du nœud...")
        node.running = False
