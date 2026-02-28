import socket
import threading
import time
import json
import struct
import os
from protocole import build_packet, PACKET_FORMAT

# Configuration conforme au document technique
MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
TCP_PORT = 7777


class ArchipelNode:
    def __init__(self, node_id):
        self.node_id = node_id
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
                # Payload avec timestamp pour le timeout
                payload = json.dumps({
                    "tcp_port": TCP_PORT,
                    "timestamp": int(time.time())
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
                # Parser header/payload en utilisant la spécification du protocole
                try:
                    header_size = struct.calcsize(PACKET_FORMAT)
                    sig_len = 32
                    remote_id = data[5:37].decode(errors='ignore').strip('\0')
                    payload_raw = data[header_size:len(data)-sig_len]
                    tcp_port = TCP_PORT
                    if payload_raw:
                        try:
                            info = json.loads(payload_raw.decode(errors='ignore'))
                            tcp_port = info.get('tcp_port', TCP_PORT)
                        except Exception:
                            pass

                    if remote_id != self.node_id:
                        # Mise à jour Peer Table (Module 1.2)
                        self.peer_table[remote_id] = {
                            "ip": addr[0],
                            "tcp_port": tcp_port,
                            "last_seen": time.time()
                        }
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
        """Envoie la liste des pairs connus via TCP"""
        try:
            with socket.create_connection((target_ip, target_port), timeout=5) as sock:
                node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]
                # Type 0x02 = PEER_LIST
                payload = json.dumps(self.peer_table).encode()
                packet = build_packet(0x02, node_id_bytes, payload, b"test_secret_key")
                sock.sendall(packet)
        except:
            pass  # Le pair n'est peut-être pas encore prêt en TCP

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

    try:
        while True:
            # Affichage de l'état de la table toutes les 15s
            print(f"\n[Peer Table] {len(node.peer_table)} pairs en ligne.")
            for pid, info in node.peer_table.items():
                print(f" - {pid} ({info['ip']})")
            time.sleep(15)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du nœud...")
        node.running = False
