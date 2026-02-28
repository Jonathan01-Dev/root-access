import os
import hashlib


def create_manifest(filepath, chunk_size=524288):
    """Génère un manifest pour le fichier, en découpant en chunks.

    Retourne un dict tel que décrit dans la spec du sprint 3.
    """
    size = os.path.getsize(filepath)
    nb_chunks = (size + chunk_size - 1) // chunk_size
    file_id = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()

    chunks = []
    with open(filepath, 'rb') as f:
        for idx in range(nb_chunks):
            data = f.read(chunk_size)
            h = hashlib.sha256(data).hexdigest()
            chunks.append({"index": idx, "hash": h, "size": len(data)})

    manifest = {
        "file_id": file_id,
        "filename": os.path.basename(filepath),
        "size": size,
        "chunk_size": chunk_size,
        "nb_chunks": nb_chunks,
        "chunks": chunks,
        # sender will be ajouté par l'appelant
    }
    return manifest
