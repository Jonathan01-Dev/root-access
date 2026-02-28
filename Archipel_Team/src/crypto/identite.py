import nacl.signing
import binascii


def generate_identity():
    # Création de la clé privée (Ton secret, à ne partager avec PERSONNE)
    private_key = nacl.signing.SigningKey.generate()

    # Création de la clé publique (Ton nom sur le réseau, que tout le monde verra)
    public_key = private_key.verify_key

    # Transformation en texte (Hexadécimal) pour que ce soit lisible
    pub_hex = binascii.hexlify(public_key.encode()).decode()

    print("--- IDENTITY GENERATED ---")
    print(f"Ta clé publique (ID): {pub_hex}")
    print("--------------------------")

    return private_key, public_key


if __name__ == "__main__":
    generate_identity()