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


class ArchipelNode:
    def __init__(self, node_id, identity=None):
        self.node_id = node_id
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
        self.running = True
        self.db_file = "peer_table.json"
        self.load_peers()  # Charger les pairs existants au démarrage

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
            # Détermine l'IP locale en créant un socket UDP vers l'extérieur
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        except Exception:
            local_ip = '0.0.0.0'
        node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]

        while self.running:
            try:
                # Payload avec timestamp pour le timeout et notre clé publique
                import binascii
                payload = json.dumps({
                    "tcp_port": TCP_PORT,
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
            # Détecte IP locale pour l'interface multicast
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
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
                # Type 0x02 = PEER_LIST
                payload = json.dumps(self.peer_table).encode()
                packet = build_packet(0x02, node_id_bytes, payload, b"test_secret_key")
                sock.sendall(packet)
        except Exception:
            pass  # Le pair n'est peut-être pas encore prêt en TCP

    # --- MODULE 2.1 & 2.4 : CHIFFREMENT E2E ---
    def encrypt_for_peer(self, peer_id, plaintext: bytes) -> bytes:
        """Retourne des données chiffrées pour le pair donné en utilisant NaCl Box."""
        import nacl.public, nacl.encoding
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
        import nacl.public, nacl.encoding
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
        except Exception as e:
            print(f"[!] Erreur envoi message à {peer_id}: {e}")

    def _tcp_server(self):
        """Serveur TCP gérant au moins 10 connexions (Module 1.3)"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', TCP_PORT))
        server.listen(10)
        print(f"[*] Serveur TCP d'écoute activé sur le port {TCP_PORT}")

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
                data = sock.recv(4096)
                if data and data.startswith(b"ARCH"):
                    msg_type = data[4]
                    if msg_type == 0x02:  # Réception PEER_LIST
                        print(f"[TCP] Peer List reçue de {addr[0]}")
                        # Ici on pourrait fusionner les tables
                    elif msg_type == 0x03:  # Message chiffré
                        try:
                            # recuperer l'expéditeur à partir de l'adresse IP/port (simple)
                            remote_id = None
                            for pid, info in self.peer_table.items():
                                if info.get('ip') == addr[0]:
                                    remote_id = pid
                                    break
                            if not remote_id:
                                print(f"[TCP] Message reçu de pair inconnu {addr}")
                            else:
                                payload = data[struct.calcsize(PACKET_FORMAT):-32]
                                plaintext = self.decrypt_from_peer(remote_id, payload)
                                print(f"[MSG] {remote_id} -> {plaintext.decode(errors='ignore')}")
                        except Exception as e:
                            print(f"[!] Erreur décryptage message: {e}")
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

    # CLI interactif minimal
    print("Commande: peers | msg <node_id> <texte> | quit")
    try:
        while True:
            try:
                cmd = input('> ').strip()
            except EOFError:
                break
            if not cmd:
                continue
            parts = cmd.split(' ', 2)
            if parts[0] == 'quit':
                break
            elif parts[0] == 'peers':
                for pid, info in node.peer_table.items():
                    print(pid, info)
            elif parts[0] == 'msg' and len(parts) >= 3:
                node.send_message(parts[1], parts[2])
            else:
                print("Usage: peers | msg <node_id> <texte> | quit")
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[!] Arrêt du nœud...")
        node.running = False