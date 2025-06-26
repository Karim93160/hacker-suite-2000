# modules/compression.py

import zlib
import gzip
import io

class Compressor:
    """
    Fournit des fonctionnalités de compression et de décompression
    en utilisant les algorithmes Zlib et Gzip.
    """

    def __init__(self):
        # Le constructeur est simple, car les méthodes de compression/décompression
        # n'ont pas besoin d'état interne persistant au-delà de l'appel de fonction.
        pass

    def compress_zlib(self, data: bytes, level: int = -1) -> bytes:
        """
        Compresse les données en utilisant Zlib.
        :param data: Les données à compresser (bytes).
        :param level: Niveau de compression (0-9, ou -1 pour la valeur par défaut Z_DEFAULT_COMPRESSION).
                      Plus le niveau est élevé, plus la compression est forte (mais plus lente).
        :return: Les données compressées (bytes).
        :raises TypeError: Si les données ne sont pas de type bytes.
        """
        if not isinstance(data, bytes):
            raise TypeError("Les données à compresser doivent être de type bytes.")
        try:
            return zlib.compress(data, level)
        except zlib.error as e:
            print(f"[-] Erreur lors de la compression Zlib : {e}")
            raise

    def decompress_zlib(self, compressed_data: bytes) -> bytes:
        """
        Décompresse les données en utilisant Zlib.
        :param compressed_data: Les données compressées (bytes).
        :return: Les données décompressées (bytes).
        :raises zlib.error: Si les données sont corrompues ou ne sont pas au format Zlib.
        :raises TypeError: Si les données ne sont pas de type bytes.
        """
        if not isinstance(compressed_data, bytes):
            raise TypeError("Les données à décompresser doivent être de type bytes.")
        try:
            return zlib.decompress(compressed_data)
        except zlib.error as e:
            print(f"[-] Erreur lors de la décompression Zlib : {e}")
            raise

    def compress_gzip(self, data: bytes, level: int = 9) -> bytes:
        """
        Compresse les données en utilisant Gzip.
        :param data: Les données à compresser (bytes).
        :param level: Niveau de compression (0-9, 9 étant le plus fort et par défaut).
        :return: Les données compressées (bytes).
        :raises TypeError: Si les données ne sont pas de type bytes.
        """
        if not isinstance(data, bytes):
            raise TypeError("Les données à compresser doivent être de type bytes.")
        try:
            # GzipStream compress les données en mémoire
            with io.BytesIO() as bio:
                with gzip.GzipFile(fileobj=bio, mode='wb', compresslevel=level) as gzf:
                    gzf.write(data)
                return bio.getvalue()
        except Exception as e:
            print(f"[-] Erreur lors de la compression Gzip : {e}")
            raise

    def decompress_gzip(self, compressed_data: bytes) -> bytes:
        """
        Décompresse les données en utilisant Gzip.
        :param compressed_data: Les données compressées (bytes).
        :return: Les données décompressées (bytes).
        :raises OSError: Si les données sont corrompues ou ne sont pas au format Gzip.
        :raises TypeError: Si les données ne sont pas de type bytes.
        """
        if not isinstance(compressed_data, bytes):
            raise TypeError("Les données à décompresser doivent être de type bytes.")
        try:
            with io.BytesIO(compressed_data) as bio:
                with gzip.GzipFile(fileobj=bio, mode='rb') as gzf:
                    return gzf.read()
        except OSError as e: # GzipFile peut lever OSError pour des formats invalides
            print(f"[-] Erreur lors de la décompression Gzip : {e}")
            raise
        except Exception as e:
            print(f"[-] Erreur inattendue lors de la décompression Gzip : {e}")
            raise


# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("[+] Test du module Compressor...")
    compressor = Compressor()

    original_data_str = "Ceci est une longue chaîne de caractères qui sera compressée. Répétition, répétition, répétition ! " * 100
    original_data = original_data_str.encode('utf-8')

    print(f"[*] Données originales (longueur) : {len(original_data)} bytes")

    # --- Test Zlib ---
    print("\n--- Test Zlib ---")
    try:
        compressed_zlib = compressor.compress_zlib(original_data)
        print(f"[*] Données compressées Zlib (longueur) : {len(compressed_zlib)} bytes")
        print(f"[*] Ratio de compression Zlib : {len(original_data) / len(compressed_zlib):.2f}x")

        decompressed_zlib = compressor.decompress_zlib(compressed_zlib)
        print(f"[*] Données décompressées Zlib (longueur) : {len(decompressed_zlib)} bytes")

        if original_data == decompressed_zlib:
            print("[+] Test Zlib réussi : Les données originales et décompressées correspondent.")
        else:
            print("[-] Erreur Zlib : Les données ne correspondent pas après décompression.")

        # Test d'erreur Zlib
        print("\n[*] Test d'erreur Zlib (données corrompues)...")
        try:
            corrupted_zlib = bytearray(compressed_zlib)
            corrupted_zlib[len(corrupted_zlib) // 2] = 0x00 # Altérer un byte
            compressor.decompress_zlib(bytes(corrupted_zlib))
            print("[-] Erreur : Décompression Zlib de données corrompues réussie (ce qui est faux).")
        except zlib.error as e:
            print(f"[+] Test d'erreur Zlib réussi : {e}")
        except Exception as e:
            print(f"[-] Erreur inattendue avec Zlib corrompu : {e}")

    except Exception as e:
        print(f"[-] Une erreur est survenue lors du test Zlib : {e}")


    # --- Test Gzip ---
    print("\n--- Test Gzip ---")
    try:
        compressed_gzip = compressor.compress_gzip(original_data)
        print(f"[*] Données compressées Gzip (longueur) : {len(compressed_gzip)} bytes")
        print(f"[*] Ratio de compression Gzip : {len(original_data) / len(compressed_gzip):.2f}x")

        decompressed_gzip = compressor.decompress_gzip(compressed_gzip)
        print(f"[*] Données décompressées Gzip (longueur) : {len(decompressed_gzip)} bytes")

        if original_data == decompressed_gzip:
            print("[+] Test Gzip réussi : Les données originales et décompressées correspondent.")
        else:
            print("[-] Erreur Gzip : Les données ne correspondent pas après décompression.")

        # Test d'erreur Gzip
        print("\n[*] Test d'erreur Gzip (données corrompues)...")
        try:
            corrupted_gzip = bytearray(compressed_gzip)
            corrupted_gzip[len(corrupted_gzip) // 2] = 0x00 # Altérer un byte
            compressor.decompress_gzip(bytes(corrupted_gzip))
            print("[-] Erreur : Décompression Gzip de données corrompues réussie (ce qui est faux).")
        except OSError as e: # GzipFile lève OSError
            print(f"[+] Test d'erreur Gzip réussi : {e}")
        except Exception as e:
            print(f"[-] Erreur inattendue avec Gzip corrompu : {e}")

    except Exception as e:
        print(f"[-] Une erreur est survenue lors du test Gzip : {e}")

    print("\n[+] Fin des tests du module Compressor.")

