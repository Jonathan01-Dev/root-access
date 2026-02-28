import socket
import threading


class ArchipelServer:
    def __init__(self, host='0.0.0.0', port=7777):
        self.host = host
        self.port = port
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def handle_client(self, conn, addr):
        print(f"[*] Connexion TCP établie avec {addr}")
        with conn:
            while True:
                # Lecture du Header TLV pour connaître la taille du message
                data = conn.recv(1024)
                if not data: break
                print(f"[*] Données reçues de {addr}: {data.hex()}")
                # Ici on ajoutera la logique de déballage et de chiffrement (Sprint 2)

    def start(self):
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(10)  # Minimum 10 connexions
        print(f"[*] Serveur TCP Archipel en attente sur le port {self.port}...")

        while True:
            conn, addr = self.server_sock.accept()
            # Un thread par connexion pour le parallélisme
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()