import socket
import threading
import time
import json
import struct
# Importation depuis le fichier protocole.py que tu as créé
from protocole import build_packet

MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
TCP_PORT = 7777


class ArchipelNode:
    def __init__(self, node_id):
        self.node_id = node_id
        self.peers = {}  # Peer Table : {node_id: {"ip": ip, "last_seen": time}}
        self.running = True

    # --- PARTIE UDP : DECOUVERTE ---
    def _udp_announcer(self):
        """Envoie des signaux HELLO toutes les 30 secondes"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        # On s'assure que le NodeID fait bien 32 octets pour le header
        node_id_bytes = self.node_id.encode().ljust(32, b'\0')[:32]

        while self.running:
            try:
                # Type 0x01 = HELLO
                payload = json.dumps({"tcp_port": TCP_PORT}).encode()
                # Signature de test pour le Sprint 1
                packet = build_packet(0x01, node_id_bytes, payload, b"test_key_32_bytes_00000000000000")
                sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
                # print(f"[UDP] Signal envoyé...") # Optionnel pour débug
            except Exception as e:
                print(f"[!] Erreur Announcer: {e}")
            time.sleep(30)

    def _udp_listener(self):
        """Ecoute les signaux des autres pairs sur le réseau local"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', MCAST_PORT))

        # Rejoindre le groupe multicast
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        print(f"[*] Écoute UDP activée sur {MCAST_GRP}:{MCAST_PORT}")

        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                # Extraction du Node ID (octets 5 à 37 selon notre format de paquet)
                remote_id_bytes = data[5:37]
                remote_id = remote_id_bytes.decode(errors='ignore').strip('\0')

                if remote_id != self.node_id:
                    self.peers[remote_id] = {"ip": addr[0], "last_seen": time.time()}
                    print(f"\n[+] Pair découvert : {remote_id} @ {addr[0]}")
            except Exception as e:
                pass

    # --- PARTIE TCP : SERVEUR DE MESSAGERIE ---
    def _tcp_server(self):
        """Serveur TCP gérant les connexions entrantes (Capacité 10+)"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', TCP_PORT))
        server.listen(10)
        print(f"[*] Serveur TCP en attente sur le port {TCP_PORT}")

        while self.running:
            try:
                client_sock, addr = server.accept()
                threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True).start()
            except:
                break

    def _handle_client(self, sock, addr):
        """Gère la réception de données d'un pair spécifique"""
        with sock:
            try:
                data = sock.recv(2048)
                if data:
                    print(f"\n[TCP] Données reçues de {addr}")
                    # Ici on ajoutera le parsing des messages au Sprint 2
            except Exception as e:
                print(f"[!] Erreur client TCP: {e}")

    def start(self):
        """Lance tous les services en parallèle"""
        threading.Thread(target=self._udp_announcer, daemon=True).start()
        threading.Thread(target=self._udp_listener, daemon=True).start()
        threading.Thread(target=self._tcp_server, daemon=True).start()
        print(f"--- Nœud Archipel [{self.node_id}] Démarré ---")


# --- POINT D'ENTRÉE DU PROGRAMME ---
if __name__ == "__main__":
    # Change cet ID pour tester avec un autre nom
    MON_ID = "AFRO_HACKER_01"

    node = ArchipelNode(MON_ID)
    node.start()

    # BOUCLE INFINIE pour maintenir le programme en vie
    try:
        while True:
            # Affiche le nombre de pairs connus toutes les 60s (optionnel)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du nœud en cours...")
        node.running = False