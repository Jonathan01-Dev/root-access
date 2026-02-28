# ARCHIPEL - Hackathon LBS

Protocole P2P local, sans serveur central, avec chiffrement de bout en bout.

## Architecture

- Decouverte: UDP multicast `239.255.42.99:6000` (HELLO toutes les 30s)
- Echange de donnees: TCP (port configurable, defaut `7777`)
- Identite: Ed25519 (PyNaCl)
- E2E: conversion Ed25519 -> Curve25519 + NaCl Box (X25519 + XSalsa20-Poly1305)
- Integrite paquet: HMAC-SHA256
- Transfert fichier: manifest + chunks + verification SHA-256

Schema simplifie:

```text
Node A --UDP HELLO--> Multicast Group <--UDP HELLO-- Node B
Node A <-------------- TCP unicast ---------------> Node B
          MSG, MANIFEST, CHUNK_REQ, CHUNK_DATA
```

## Format paquet Archipel v1

- Header: `MAGIC(4) | TYPE(1) | NODE_ID(32) | PAYLOAD_LEN(4)`
- Payload: variable (JSON ou binaire selon type)
- Signature: `HMAC-SHA256` (32 bytes)

Types utilises:

- `0x01` HELLO
- `0x02` PEER_LIST
- `0x03` MSG
- `0x04` CHUNK_REQ
- `0x05` CHUNK_DATA
- `0x06` MANIFEST

## Arborescence

```text
Archipel_Team/
  README.md
  src/
    main.py
    crypto/
    network/
    transfer/
    messaging/
```

## Installation

Prerequis:

- Python 3.10+
- pip

Installation:

```bash
cd Archipel_Team
pip install -r requirements.txt
```

Optionnel (IA):

- definir `GEMINI_API_KEY` pour activer les requetes Gemini

## Lancement

Demarrer un noeud:

```bash
cd Archipel_Team/src
python main.py start --port 7777 --identity-file idA.key --peer-db peer_table_A.json --ui --ui-port 8080 --no-ai
```

Demarrer un second noeud:

```bash
cd Archipel_Team/src
python main.py start --port 7778 --identity-file idB.key --peer-db peer_table_B.json --ui --ui-port 8081 --no-ai
```

Acces UI:

- `http://127.0.0.1:8080` (noeud A)
- `http://127.0.0.1:8081` (noeud B)

## Commandes CLI (Sprint 4)

Une fois `start` lance:

- `peers`
- `msg <node_id> <texte>`
- `msg @archipel-ai <question>` (si IA active)
- `/ask <question>` (si IA active)
- `send <node_id> <filepath>`
- `receive`
- `download <file_id> [output_path]`
- `status`
- `trust <node_id>`
- `quit`

## Guide de demo jury (< 5 min)

1. Lancer 2 ou 3 noeuds avec ports/identites differents.
2. Verifier la decouverte avec `peers`.
3. Envoyer un message chiffre avec `msg`.
4. Partager un fichier avec `send`.
5. Sur le pair receveur: `receive`, puis `download <file_id>`.
6. Verifier le statut avec `status`.
7. (Optionnel) Tester IA avec `/ask` si `GEMINI_API_KEY` est present.

## Securite et confiance

- TOFU: premier contact memorise la cle publique du pair.
- `trust <node_id>`: marque un pair comme approuve localement.
- Session chiffrante et signatures par cle d'identite.
- Aucun appel internet requis pour le fonctionnement P2P (mode `--no-ai`).

## Limitations connues

- Web of Trust simplifie (pas de graphe de signatures complet).
- Gestion de reprise et priorisation chunks encore basique.
- HMAC partage: secret statique dans ce prototype (a durcir pour prod).
- UI web locale simple (Flask), pas encore d'authentification d'interface.

## Contributions equipe

- Reseau P2P: discovery UDP + TCP transport
- Crypto: identite + chiffrement E2E
- Transfert: manifest + chunk manager
- Integration Sprint 4: CLI unifie + module IA optionnel + documentation

## Ressources projet (Point 5)

- Dependances Python: `requirements.txt`
- Variables d'environnement: `.env.example`
- Spec protocole: `docs/protocol-spec.md`
- Vue architecture: `docs/architecture.md`
- Script de passage demo: `demo/demo-steps.md`
