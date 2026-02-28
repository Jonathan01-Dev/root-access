# 🏝️ ARCHIPEL : Protocole P2P Souverain & Décentralisé

**Hackathon LBS 2026** | *Équipe Archipel*
"Une infrastructure résiliente pour une communication sans Internet."

---

## 1. Vision du Projet
Archipel est un protocole de communication décentralisé conçu pour survivre à une coupure totale des infrastructures globales. En utilisant un modèle **Zero-Connection**, chaque nœud du réseau devient un pilier autonome, assurant la découverte, le routage et le stockage des données sans aucun serveur central.

## 2. Choix Technologiques & Justifications (Sprint 0)
* **Langage :** **Python 3.10+**. Choisi pour sa rapidité de prototypage et sa gestion robuste des sockets multithreadés.
* **Transport Hybride :**
    * **UDP Multicast (Port 6000) :** Pour la découverte automatique et instantanée des pairs sur le réseau local (IP Groupe : `239.255.42.99`).
    * **TCP Sockets (Port 7777) :** Pour garantir l'intégrité et l'ordre des transferts de messages et de fichiers volumineux.
* **Sécurité :**
    * **Ed25519 (PyNaCl) :** Utilisé pour l'identité souveraine (clés publiques) et la signature numérique.
    * **AES-256-GCM :** Chiffrement authentifié pour la confidentialité des données (Sprint 2).

## 3. Architecture Technique
Le système suit un maillage décentralisé (Mesh Network) où chaque participant maintient une **Peer Table** dynamique.

```text
      [ Nœud Archipel A ]                     [ Nœud Archipel B ]
      |                 |                     |                 |
      |--- UDP HELLO -->| (Multicast:6000)    |<-- UDP HELLO ---|
      | (Public Key ID) |                     | (Public Key ID) |
      |                 |                     |                 |
      |                 | <== Connexion TCP ==>| (Unicast:7777)  |
      |  (Handshake)    |      (Messages)      | (File Chunks)   |