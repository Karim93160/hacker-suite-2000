import os
import json
import time
import sys # Ajout de sys pour StreamHandler
from datetime import datetime

# Assurez-vous que Cryptodome est correctement installé
# pip install pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import unpad, pad
import base64
import logging # Ajout du module logging

# IMPORTANT : Le premier import/assignation de AES256Cipher doit se faire ici.
# Si l'import échoue, AES256Cipher est défini à None.
try:
    from modules.aes256 import AES256Cipher
except ImportError:
    print("[CRITICAL] [Logger] Le module AES256Cipher n'a pas pu être importé. Les logs NE SERONT PAS CHIFFRÉS.")
    AES256Cipher = None
except ValueError as e:
    print(f"[CRITICAL] [Logger] Erreur lors de l'initialisation de AES256Cipher: {e}. Les logs NE SERONT PAS CHIFFRÉS.")
    AES256Cipher = None

class Logger:
    # Utilisation des niveaux de logging standard pour la compatibilité
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

    LEVEL_NAMES = {
        DEBUG: "DEBUG",
        INFO: "INFO",
        WARNING: "WARNING",
        ERROR: "ERROR",
        CRITICAL: "CRITICAL"
    }

    MAX_LOG_SIZE = 1 * 1024 * 1024 # 1 MB
    BACKUP_COUNT = 1
    MAX_IN_MEMORY_LOGS = 1000 # Conserver les 1000 dernières lignes en mémoire pour l'UI

    def __init__(self, log_file_path: str | None, cipher_key: str | None, debug_mode: bool = False, stdout_enabled: bool = True):
        self.log_file_path = log_file_path
        self.debug_mode = debug_mode
        self.stdout_enabled = stdout_enabled
        self.cipher = None
        self.log_buffer = [] # Buffer pour stocker les messages de log en mémoire (pour l'UI Dash)

        self._setup_logging_handlers() # Configure les handlers de Python logging

        if AES256Cipher and cipher_key:
            try:
                self.cipher = AES256Cipher(cipher_key)
                self._add_log_to_buffer(self.INFO, "Chiffrement des logs activé.")
            except Exception as e:
                self._add_log_to_buffer(self.CRITICAL, f"Erreur à l'initialisation du chiffreur ({e}). Les logs NE SERONT PAS CHIFFRÉS.")
                self.cipher = None
        elif not cipher_key: # Si aucune clé n'est fournie
            self._add_log_to_buffer(self.INFO, "Aucune clé de chiffrement fournie. Le chiffrement des logs est désactivé.")
        elif not AES256Cipher: # Si AES256Cipher n'a pas pu être importé (et donc est None)
            self._add_log_to_buffer(self.CRITICAL, "Le module AES256Cipher n'est pas disponible. Le chiffrement des logs est désactivé.")


        self._ensure_log_directory_exists()

    def _setup_logging_handlers(self):
        # Configure le logger standard de Python
        self.logger = logging.getLogger('agent_logger_instance') # Nom unique pour éviter les conflits
        self.logger.setLevel(self.DEBUG if self.debug_mode else self.INFO)
        self.logger.propagate = False # Empêche la propagation aux handlers racine

        # Supprime les handlers existants pour éviter les doublons (important si le logger est réinitialisé)
        if self.logger.handlers:
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)

        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        # Handler pour la sortie console
        if self.stdout_enabled:
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(formatter)
            self.logger.addHandler(stream_handler)

        # Handler pour écrire dans le fichier (sera géré par _write_log pour le chiffrement)
        # On n'ajoute pas de FileHandler direct ici pour gérer le chiffrement manuellement dans _write_log
        # et éviter que logging n'écrive en double ou en clair si chiffré.

    def _add_log_to_buffer(self, level: int, message: str):
        """Ajoute le message formaté au buffer de logs interne et gère la taille."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level_name = self.LEVEL_NAMES.get(level, "UNKNOWN")
        full_msg = f"[{timestamp}] [{level_name}] {message}"

        self.log_buffer.append(full_msg)

        if len(self.log_buffer) > self.MAX_IN_MEMORY_LOGS:
            self.log_buffer = self.log_buffer[-self.MAX_IN_MEMORY_LOGS:]

    def _ensure_log_directory_exists(self):
        if not self.log_file_path:
            return

        log_dir = os.path.dirname(self.log_file_path)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception as e:
                self.logger.critical(f"Impossible de créer le répertoire de logs '{log_dir}': {e}. Les logs ne seront pas enregistrés sur le disque.")
                self.log_file_path = None # Désactive l'écriture sur disque si le répertoire ne peut pas être créé

    def _format_message_for_file(self, level: int, message: str) -> dict:
        """Formate le message en dictionnaire pour l'écriture JSON dans le fichier."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level_name = self.LEVEL_NAMES.get(level, "UNKNOWN")
        log_entry = {
            "timestamp": timestamp,
            "level": level_name,
            "message": message
        }
        return log_entry

    def _write_log(self, level: int, message: str):
        # Toujours ajouter au buffer en mémoire et envoyer au logger standard de Python
        # pour la gestion des StreamHandler (stdout)
        self._add_log_to_buffer(level, message)
        self.logger.log(level, message) # Ceci gère l'impression sur stdout via StreamHandler

        # Ne pas écrire sur disque si log_file_path n'est pas défini (ex: pour les logs d'explorateur dans Dash)
        if not self.log_file_path:
            return

        if not self.debug_mode and level == self.DEBUG:
            return # Ne pas écrire les logs DEBUG sur disque si debug_mode est désactivé

        try:
            if os.path.exists(self.log_file_path) and os.path.getsize(self.log_file_path) >= self.MAX_LOG_SIZE:
                self._rotate_logs()
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification/rotation des logs: {e}", exc_info=False) # exc_info=False pour éviter le traceback complet dans le log


        log_entry_dict = self._format_message_for_file(level, message)
        data_to_write_bytes = json.dumps(log_entry_dict).encode('utf-8')

        if self.cipher:
            try:
                # Chiffrer le JSON encodé en bytes
                encrypted_data_b64 = self.cipher.encrypt(data_to_write_bytes).decode('utf-8')
                # On stocke le JSON qui contient le message chiffré en Base64
                final_output_line = json.dumps({
                    "timestamp": log_entry_dict["timestamp"],
                    "level": log_entry_dict["level"],
                    "encrypted_message": encrypted_data_b64
                }).encode('utf-8')
            except Exception as e:
                self.logger.error(f"Échec du chiffrement du log: {e}. Écriture en clair.", exc_info=False)
                final_output_line = data_to_write_bytes # Écrire en clair si chiffrement échoue
        else:
            final_output_line = data_to_write_bytes # Écrire en clair

        try:
            with open(self.log_file_path, 'ab') as f:
                f.write(final_output_line + b'\n')
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            self.logger.critical(f"Impossible d'écrire dans le fichier de logs '{self.log_file_path}': {e}", exc_info=False)

    def _rotate_logs(self):
        self.logger.info("Rotation du fichier de log...")

        if os.path.exists(f"{self.log_file_path}.{self.BACKUP_COUNT}"):
            try:
                os.remove(f"{self.log_file_path}.{self.BACKUP_COUNT}")
            except Exception as e:
                self.logger.error(f"Impossible de supprimer le fichier de log de backup: {e}", exc_info=False)

        for i in range(self.BACKUP_COUNT - 1, -1, -1):
            src = f"{self.log_file_path}" if i == 0 else f"{self.log_file_path}.{i}"
            dst = f"{self.log_file_path}.{i+1}"
            if os.path.exists(src):
                try:
                    os.rename(src, dst)
                except Exception as e:
                    self.logger.error(f"Impossible de renommer '{src}' en '{dst}': {e}", exc_info=False)

        self.logger.info("Rotation des logs terminée.")

    # Ces méthodes appellent _write_log qui gère l'ajout au buffer et l'écriture sur disque/stdout.
    def log_debug(self, message: str, component: str = ""):
        self._write_log(self.DEBUG, f"[{component}] {message}" if component else message)

    def log_info(self, message: str, component: str = ""):
        self._write_log(self.INFO, f"[{component}] {message}" if component else message)

    def log_warning(self, message: str, component: str = ""):
        self._write_log(self.WARNING, f"[{component}] {message}" if component else message)

    def log_error(self, message: str, component: str = ""):
        self._write_log(self.ERROR, f"[{component}] {message}" if component else message)

    def log_critical(self, message: str, component: str = ""):
        self._write_log(self.CRITICAL, f"[{component}] {message}" if component else message)

    def read_and_decrypt_logs(self) -> list:
        """Lit et déchiffre les logs du fichier de log sur le disque."""
        if not self.log_file_path:
            self.logger.error("Chemin du fichier de log non spécifié. Impossible de lire les logs du disque.")
            return []

        if not os.path.exists(self.log_file_path):
            return [] # Fichier principal non trouvé

        decrypted_entries = []
        log_files_to_read = [self.log_file_path]
        for i in range(1, self.BACKUP_COUNT + 1):
            backup_path = f"{self.log_file_path}.{i}"
            if os.path.exists(backup_path):
                log_files_to_read.append(backup_path)

        for f_path in log_files_to_read:
            if not os.path.exists(f_path):
                continue

            try:
                with open(f_path, 'rb') as f:
                    for line_bytes in f:
                        line_bytes = line_bytes.strip()
                        if not line_bytes:
                            continue

                        try:
                            # Tenter de parser d'abord comme un JSON (format chiffré ou non chiffré)
                            log_json_data = json.loads(line_bytes.decode('utf-8', errors='ignore'))
                            
                            if self.cipher and "encrypted_message" in log_json_data:
                                try:
                                    encrypted_msg_b64 = log_json_data["encrypted_message"].encode('utf-8')
                                    decrypted_data_bytes = self.cipher.decrypt(encrypted_msg_b64)
                                    original_log_entry = json.loads(decrypted_data_bytes.decode('utf-8'))
                                    decrypted_entries.append(original_log_entry)
                                except Exception as e:
                                    self.logger.error(f"Erreur de déchiffrement ou parsing interne d'une ligne dans '{f_path}': {e}. Ligne: {line_bytes[:100]}...")
                                    # Ajouter une entrée indiquant l'erreur de déchiffrement
                                    decrypted_entries.append({
                                        "timestamp": log_json_data.get("timestamp", "N/A"),
                                        "level": "ERROR",
                                        "message": f"[DECHFF. ÉCHOUÉ] {log_json_data.get('message', '')} (Erreur: {e})",
                                        "original_encrypted": log_json_data.get("encrypted_message", "")
                                    })
                            else: # Non chiffré ou chiffrement désactivé/échoué, mais c'est un JSON valide
                                decrypted_entries.append(log_json_data)
                        except json.JSONDecodeError:
                            # Si ce n'est pas un JSON, c'est peut-être une ligne de log brute non-JSON ou corrompue
                            self.logger.warning(f"Ligne de log non-JSON ou corrompue dans '{f_path}': {line_bytes.decode('utf-8', errors='ignore')[:100]}...")
                            decrypted_entries.append({
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "level": "UNKNOWN",
                                "message": f"[RAW/CORROMPU] {line_bytes.decode('utf-8', errors='ignore')}"
                            })

            except Exception as e:
                self.logger.error(f"Erreur inattendue lors de la lecture de '{f_path}': {e}", exc_info=False)

        return decrypted_entries

    def get_new_logs(self, last_log_index: int = 0) -> tuple[list[str], int]:
        """
        Retourne les nouveaux messages de log du buffer interne depuis le dernier index.
        Utilisé par l'interface Dash pour le rafraîchissement en temps réel.
        """
        new_logs = self.log_buffer[last_log_index:]
        return new_logs, len(self.log_buffer)

    def reset_logs(self):
        """
        Réinitialise le buffer de logs interne et envoie un message au logger standard.
        """
        self.log_buffer = []
        # Utiliser self.logger pour un message de debug qui peut apparaître si debug_mode est activé
        self.logger.debug("Buffer de logs en mémoire réinitialisé.", extra={'component': 'Logger'})


if __name__ == "__main__":
    import shutil

    print("[+] Test du module Logger...")

    # --- CORRECTION APPLIQUÉE ICI : `global AES256Cipher` est supprimé car non nécessaire. ---
    # `AES256Cipher` est déjà défini au niveau global du module par le try-except en haut du fichier.
    # Toute réaffectation ici sera une réaffectation de la variable globale.
    # --- FIN DE LA CORRECTION ---

    # Mock la classe AES256Cipher pour les tests autonomes du logger
    # Cette classe doit simuler le comportement attendu de modules.aes256.AES256Cipher
    class MockAES256Cipher:
        def __init__(self, key):
            self.key = key.encode('utf-8')
            if len(self.key) != 32: # PBKDF2 pour s'assurer que la clé est de 32 bytes
                salt = b'salt_for_kdf'
                self.key = PBKDF2(self.key, salt, dkLen=32, count=100000, prf=SHA256)

        def encrypt(self, plaintext: bytes) -> bytes:
            cipher = AES.new(self.key, AES.MODE_GCM)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            encrypted_data_package = {
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8')
            }
            return base64.b64encode(json.dumps(encrypted_data_package).encode('utf-8'))

        def decrypt(self, encrypted_b64_data: bytes) -> bytes:
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
                raise ValueError(f"Erreur lors du déchiffrement dans Mock: {e}")
            except Exception as e:
                raise Exception(f"Erreur inattendue lors du déchiffrement dans Mock: {e}")

    # Cette affectation est maintenant correcte car il n'y a pas de "global" en amont
    AES256Cipher = MockAES256Cipher


    test_log_dir = "./test_logs"
    if os.path.exists(test_log_dir):
        shutil.rmtree(test_log_dir) # Nettoyer avant chaque exécution de test
    os.makedirs(test_log_dir, exist_ok=True)

    test_log_file = os.path.join(test_log_dir, "test_agent_logs.enc")
    test_cipher_key = "test_key_for_log_aes_256bits_long"

    # Nettoyage des anciens backups si présents (important pour les tests de rotation)
    for i in range(1, Logger.BACKUP_COUNT + 2):
        if os.path.exists(f"{test_log_file}.{i}"):
            os.remove(f"{test_log_file}.{i}")
    if os.path.exists(test_log_file):
        os.remove(test_log_file)


    print("\n--- Test 1: Logger en mode DEBUG (stdout activé pour le test principal) ---")
    logger_debug = Logger(test_log_file, test_cipher_key, debug_mode=True, stdout_enabled=True)
    logger_debug.log_debug("Ceci est un message de debug.", component="TEST")
    logger_debug.log_info("Ceci est un message d'info.", component="TEST")
    logger_debug.log_warning("Ceci est un message d'avertissement.", component="TEST")
    logger_debug.log_error("Ceci est un message d'erreur critique.", component="TEST")
    logger_debug.log_critical("Ceci est un message critique.", component="TEST")

    time.sleep(0.1) # Laisser le temps aux handlers d'écrire

    read_logs_debug = logger_debug.read_and_decrypt_logs()
    print(f"\n[*] Logs lus du disque (mode debug, {len(read_logs_debug)} entrées):")
    for entry in read_logs_debug:
        print(entry)
    assert len(read_logs_debug) == 5, "Le nombre de logs lus en mode debug est incorrect."
    assert any(e['level'] == 'DEBUG' for e in read_logs_debug), "Le log DEBUG n'a pas été enregistré sur disque en mode debug."

    print("\n[*] Contenu du buffer de logs interne (debug_mode):")
    buffer_logs, _ = logger_debug.get_new_logs(0)
    for log in buffer_logs:
        print(log)
    assert len(buffer_logs) == 5, "Le buffer interne n'a pas tous les logs."


    print("\n--- Test 2: Logger en mode normal (pas de DEBUG, stdout activé) ---")
    if os.path.exists(test_log_file): os.remove(test_log_file) # Nettoyer le fichier principal
    logger_normal = Logger(test_log_file, test_cipher_key, debug_mode=False, stdout_enabled=True)
    logger_normal.log_debug("Ceci est un message de debug qui ne devrait PAS apparaître sur disque mais SI dans le buffer.", component="TEST")
    logger_normal.log_info("Ceci est un message d'info en mode normal.", component="TEST")
    
    time.sleep(0.1)
    read_logs_normal = logger_normal.read_and_decrypt_logs()
    print(f"\n[*] Logs lus du disque (mode normal, {len(read_logs_normal)} entrées):")
    for entry in read_logs_normal:
        print(entry)
    # Le log initial généré par l'init + le log_info. Le debug log ne devrait pas être sur disque.
    assert len(read_logs_normal) == 1, "Le nombre de logs lus en mode normal est incorrect (devrait exclure DEBUG du disque)."
    assert not any(e['level'] == 'DEBUG' for e in read_logs_normal), "Le log DEBUG a été enregistré sur disque en mode normal."
                           
    print("\n[*] Contenu du buffer de logs interne (mode normal):")
    buffer_logs_normal, _ = logger_normal.get_new_logs(0)
    for log in buffer_logs_normal:
        print(log)
    # Le buffer doit contenir le log initial (INFO) et le log_debug (même si debug_mode=False pour le disque)
    assert len(buffer_logs_normal) == 2, "Le buffer interne n'a pas tous les logs en mode normal (inclut DEBUG)."
    assert any("[DEBUG]" in e for e in buffer_logs_normal), "Le log DEBUG n'est pas dans le buffer interne en mode normal."
                                                                                                                                             
    print("\n--- Test 3: Logger avec stdout DÉSACTIVÉ (simule l'utilisation par Dash) ---")
    if os.path.exists(test_log_file): os.remove(test_log_file)
    logger_no_stdout = Logger(test_log_file, test_cipher_key, debug_mode=True, stdout_enabled=False)
    logger_no_stdout.log_info("Ceci est un message qui ne doit apparaître QUE dans le buffer et sur disque.", component="TEST")
    logger_no_stdout.log_debug("Ceci est un debug qui ne doit apparaître QUE dans le buffer et sur disque.", component="TEST")
    # Tu NE devrais PAS voir ces messages imprimés dans la console Termux.   
    time.sleep(0.1)
    
    buffer_logs_no_stdout, _ = logger_no_stdout.get_new_logs(0)
    print(f"\n[*] Contenu du buffer interne (stdout désactivé) ({len(buffer_logs_no_stdout)} entrées):")
    for log_entry in buffer_logs_no_stdout:
        print(f"  Buffer: {log_entry}") # Pour vérifier qu'ils sont bien là
    assert len(buffer_logs_no_stdout) == 2, "Le buffer interne n'a pas les logs quand stdout est désactivé."
                                                                                                                               
    read_logs_no_stdout = logger_no_stdout.read_and_decrypt_logs()
    print(f"[*] Logs lus du disque (stdout désactivé) ({len(read_logs_no_stdout)} entrées):")
    for entry in read_logs_no_stdout:
        print(f"  Disque: {entry}") # Pour vérifier qu'ils sont bien là
    assert len(read_logs_no_stdout) == 2, "Les logs ne sont pas sur le disque quand stdout est désactivé."
                                                                                 
    print("\n--- Test 4: Rotation des logs ---")
    if os.path.exists(test_log_file): os.remove(test_log_file)
    # Nettoyage des backups existants avant le test de rotation
    for i in range(1, Logger.BACKUP_COUNT + 2):
        if os.path.exists(f"{test_log_file}.{i}"):
            os.remove(f"{test_log_file}.{i}")
            
    logger_rotate = Logger(test_log_file, test_cipher_key, debug_mode=True, stdout_enabled=False)
    # Calcule un nombre d'entrées suffisant pour forcer la rotation
    # Estime la taille d'une ligne de log chiffrée après encodage Base64
    sample_log_content = json.dumps({"timestamp": "2025-01-01 12:00:00", "level": "INFO", "message": "a test message"}).encode('utf-8')
    if logger_rotate.cipher:
        # Estimer la taille du message chiffré + base64 + JSON wrapper
        dummy_encrypted = logger_rotate.cipher.encrypt(sample_log_content).decode('utf-8')
        sample_log_size = len(json.dumps({
            "timestamp": "2025-01-01 12:00:00", "level": "INFO", "encrypted_message": dummy_encrypted
        }).encode('utf-8')) + 1 # +1 pour le '\n'
    else:
        sample_log_size = len(sample_log_content) + 1 # +1 pour le '\n'

    num_entries_to_fill = int(Logger.MAX_LOG_SIZE / sample_log_size) + 1 # +1 pour s'assurer de dépasser
    print(f"[*] Écriture de ~{num_entries_to_fill} messages pour forcer la rotation (taille max: {Logger.MAX_LOG_SIZE / 1024 / 1024:.2f} MB, taille par log: {sample_log_size} bytes)...")
    for i in range(num_entries_to_fill):
        logger_rotate.log_info(f"Message de test pour la rotation {i}", component="TEST_ROTATE")
                                                                                 
    time.sleep(0.5) # Laisser le temps à la rotation de s'effectuer si elle est asynchrone ou différée
    
    print(f"[*] Vérification des fichiers de log après rotation:")
    assert not os.path.exists(f"{test_log_file}.{Logger.BACKUP_COUNT + 1}"), "Too many backup files."
    assert os.path.exists(f"{test_log_file}.1"), "Le fichier de log n'a pas été renommé en .1"
    
    logger_rotate.log_critical("Ceci est un log après la rotation.", component="TEST_ROTATE")
    time.sleep(0.1)
    
    read_logs_rotated = logger_rotate.read_and_decrypt_logs()
    print(f"[*] Nombre total de logs lus après rotation: {len(read_logs_rotated)}")
    assert any("Ceci est un log après la rotation." in e['message'] for e in read_logs_rotated), "Le log après rotation n'est pas présent."
                                                                                 
    print("\n--- Test 5: Chiffrement des logs désactivé ---")
    if os.path.exists(test_log_file): os.remove(test_log_file)
    logger_no_cipher = Logger(test_log_file, None, debug_mode=True, stdout_enabled=False) # Pass None for cipher_key
    logger_no_cipher.log_info("Ceci est un log en clair (pas de chiffrement).", component="TEST_NOCIPHER")
    
    time.sleep(0.1)
    
    read_logs_no_cipher = logger_no_cipher.read_and_decrypt_logs()
    print(f"[*] Logs lus du disque (en clair): \n{read_logs_no_cipher[0]['message'][:100]}...")
    assert "Ceci est un log en clair (pas de chiffrement)." in read_logs_no_cipher[0]['message'], "Le log en clair n'est pas présent."
    assert "encrypted_message" not in read_logs_no_cipher[0], "Le log semble chiffré alors qu'il ne devrait pas l'être."
                                                                                 
    if os.path.exists(test_log_dir):
        shutil.rmtree(test_log_dir)
        print(f"\n[+] Répertoire de test '{test_log_dir}' supprimé.")
    print("\n[+] Fin des tests du module Logger.")

