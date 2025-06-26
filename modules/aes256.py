from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2 # Gardé pour information si dérivation de clé était souhaitée
from Cryptodome.Hash import SHA256 # Pour hacher la clé si elle n'est pas de la bonne taille
import base64
import json

class AES256Cipher:
    """
    Fournit des fonctionnalités de chiffrement et de déchiffrement AES-256 en mode GCM.
    Prend une clé maître qui sera traitée pour obtenir une clé de 256 bits (32 bytes).
    """

    KEY_LENGTH = 32  # 256 bits

    def __init__(self, master_key: str):
        """
        Initialise le chiffreur avec une clé maître.
        La clé maître est convertie en bytes et hachée avec SHA256 si sa longueur
        n'est pas égale à KEY_LENGTH pour garantir 32 bytes.
        """
        if not isinstance(master_key, str):
            raise TypeError("La clé maître doit être une chaîne de caractères.")
        if not master_key:
            raise ValueError("La clé maître ne peut pas être vide.")

        master_key_bytes = master_key.encode('utf-8')
        
        # Si la clé n'est pas de la bonne taille, on la hache pour obtenir une clé de 32 bytes.
        # C'est une méthode simple pour s'assurer de la bonne longueur de clé pour AES-256.
        # Dans un scénario de production, si la clé est un mot de passe, l'utilisation de PBKDF2
        # avec un sel unique et stocké (par exemple avec les données chiffrées si le sel est dynamique)
        # serait plus robuste. Pour une clé fixe connue des deux côtés (agent/serveur),
        # un hachage direct est souvent suffisant pour ajuster la taille.
        if len(master_key_bytes) != self.KEY_LENGTH:
            # print(f"[AVERTISSEMENT] La clé fournie n'est pas de {self.KEY_LENGTH} bytes. Hachage SHA256 pour ajuster la taille.")
            self.key = SHA256.new(master_key_bytes).digest()
        else:
            self.key = master_key_bytes
        
        # Vérification finale pour s'assurer que la clé a bien la bonne longueur
        if len(self.key) != self.KEY_LENGTH:
            raise ValueError(f"La clé AES doit être de {self.KEY_LENGTH} bytes après traitement. Actuellement : {len(self.key)} bytes.")


    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Chiffre les données en utilisant AES-256 GCM.
        Retourne les données chiffrées sous forme de bytes.
        Le format de sortie est un blob Base64 encodé qui contient le nonce, le ciphertext et le tag,
        structurés en JSON.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Les données à chiffrer doivent être de type bytes.")

        cipher = AES.new(self.key, AES.MODE_GCM)
        nonce = cipher.nonce  # Le nonce est généré aléatoirement et est unique pour chaque chiffrement
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Nous allons encapsuler le nonce, le ciphertext et le tag dans un dictionnaire JSON
        # puis encoder l'ensemble en base64 pour faciliter la transmission.
        encrypted_data_package = {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
        return base64.b64encode(json.dumps(encrypted_data_package).encode('utf-8'))

    def decrypt(self, encrypted_b64_data: bytes) -> bytes:
        """
        Déchiffre les données en utilisant AES-256 GCM.
        Les données chiffrées sont attendues dans le format JSON base64 encodé produit par 'encrypt'.
        Lance une ValueError si les données sont altérées (échec de l'authentification du tag).
        """
        if not isinstance(encrypted_b64_data, bytes):
            raise TypeError("Les données chiffrées doivent être de type bytes (base64 encoded).")

        try:
            decoded_package_json = base64.b64decode(encrypted_b64_data).decode('utf-8')
            encrypted_data_package = json.loads(decoded_package_json)

            nonce = base64.b64decode(encrypted_data_package['nonce'])
            ciphertext = base64.b64decode(encrypted_data_package['ciphertext'])
            tag = base64.b64decode(encrypted_data_package['tag'])

            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            # Gérer les erreurs de déchiffrement ou de format invalide (tag mismatch, données corrompues)
            raise ValueError(f"Erreur lors du déchiffrement des données. Données corrompues, clé incorrecte ou format invalide: {e}")
        except Exception as e:
            raise Exception(f"Erreur inattendue lors du déchiffrement: {e}")


# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("[+] Test du module AES256Cipher...")

    # Clé de test (doit faire 16, 24 ou 32 bytes. Si différente, elle sera hachée en 32 bytes)
    test_key_str = "MaCleAESsecreteDe32BytesPourAES256!!" # 32 bytes
    # test_key_str = "UneCleDe20BytesTest" # 20 bytes, sera hachée en 32 bytes

    try:
        cipher = AES256Cipher(test_key_str)
        print(f"[*] Clé AES (bytes) utilisée: {cipher.key.hex()} (Longueur: {len(cipher.key)} bytes)")

        original_data = b"Ceci est un exemple de donnees tres sensibles a exfiltrer. Ne pas laisser trainer ! " * 5
        print(f"[*] Données originales : {original_data[:100]}... (Longueur: {len(original_data)} bytes)")

        # Chiffrement
        encrypted_data_b64 = cipher.encrypt(original_data)
        print(f"[*] Données chiffrées (Base64) : {encrypted_data_b64[:100]}... (Longueur: {len(encrypted_data_b64)} bytes)")

        # Déchiffrement
        decrypted_data = cipher.decrypt(encrypted_data_b64)
        print(f"[*] Données déchiffrées : {decrypted_data[:100]}... (Longueur: {len(decrypted_data)} bytes)")

        if original_data == decrypted_data:
            print("[+] Test de chiffrement/déchiffrement réussi ! Les données correspondent.")
        else:
            print("[-] Erreur : Les données originales et déchiffrées ne correspondent pas.")

        # Test d'une tentative de déchiffrement avec une clé incorrecte
        print("\n[*] Test avec une clé incorrecte...")
        wrong_key = "UneMauvaiseCleDechiffrement"
        try:
            wrong_cipher = AES256Cipher(wrong_key)
            wrong_cipher.decrypt(encrypted_data_b64)
            print("[-] Erreur: Déchiffrement réussi avec une mauvaise clé (ce qui est faux).")
        except ValueError as e:
            print(f"[+] Test de déchiffrement avec mauvaise clé réussi : {e}")
        except Exception as e:
            print(f"[-] Erreur inattendue avec mauvaise clé : {e}")

        # Test de données altérées
        print("\n[*] Test avec des données chiffrées altérées...")
        try:
            # Altérer quelques bytes dans les données chiffrées base64
            altered_data_b64 = bytearray(encrypted_data_b64)
            altered_data_b64[len(altered_data_b64) // 2] = ord('X') # Changer un byte au hasard
            cipher.decrypt(bytes(altered_data_b64))
            print("[-] Erreur: Déchiffrement réussi avec des données altérées (ce qui est faux).")
        except ValueError as e:
            print(f"[+] Test de déchiffrement avec données altérées réussi : {e}")
        except Exception as e:
            print(f"[-] Erreur inattendue avec données altérées : {e}")

        # Test de clé vide
        print("\n[*] Test avec une clé vide...")
        try:
            AES256Cipher("")
            print("[-] Erreur: Création de chiffreur avec clé vide réussie (ce qui est faux).")
        except ValueError as e:
            print(f"[+] Test de clé vide réussi: {e}")
        
    except Exception as e:
        print(f"[!] Une erreur inattendue est survenue lors du test général: {e}")

    print("\n[+] Fin des tests du module AES256Cipher.")
