import socket
import threading
import time
import json
from protocole import build_packet # On réutilise le format du Sprint 0

MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
TCP_PORT = 7777

class ArchipelNode:
    def __init__(self, node_id):
        self.node_id = node_id
        self.peers = {} # Notre Peer Table : {node_id: {"ip": ip, "last_seen": time}}
        self.running = True

    # --- PARTIE UDP : DECOUVERTE ---
    def _udp_announcer(self):
        """Envoie des HELLO en boucle"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        while self.running:
            # Type 0x01 = HELLO
            # Pour l'instant payload simple, on chiffrera au Sprint 2
            payload = json.dumps({"tcp_port": TCP_PORT}).encode()
            # On utilise une clé de test pour la signature du Sprint 1
            packet = build_packet(0x01, self.node_id.encode()[:32], payload, b"test_key_32_bytes_00000000000000")
            sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
            time.sleep(30)

    def _udp_listener(self):
        """Ecoute les HELLO des autres"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.bind(('', MCAST_PORT))
        # Rejoindre le groupe multicast
        import struct
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        while self.running:
            data, addr = sock.recvfrom(1024)
            # Logique de parsing simplifiée pour le Sprint 1
            # On extrait le Node ID du paquet (octets 5 à 37 selon notre README)
            remote_id = data[5:37].hex()
            if remote_id != self.node_id:
                self.peers[remote_id] = {"ip": addr[0], "last_seen": time.time()}
                print(f"[*] Pair découvert : {remote_id[:8]} @ {addr[0]}")

    # --- PARTIE TCP : MESSAGERIE ---
    def _tcp_server(self):
        """Serveur acceptant jusqu'à 10 connexions"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', TCP_PORT))
        server.listen(10)
        while self.running:
            client_sock, addr = server.accept()
            # On lance un thread pour gérer ce client précis
            threading.Thread(target=self._handle_client, args=(client_sock, addr)).start()

    def _handle_client(self, sock, addr):
        with sock:
            data = sock.recv(1024)
            if data:
                print(f"[TCP] Message reçu de {addr}")

    def start(self):
        threading.Thread(target=self._udp_announcer, daemon=True).start()
        threading.Thread(target=self._udp_listener, daemon=True).start()
        threading.Thread(target=self._tcp_server, daemon=True).start()
        print(f"Node {self.node_id[:8]} démarré...")