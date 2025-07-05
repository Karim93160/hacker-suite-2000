import os
import re
import json
import base64
import datetime # Importe datetime pour les timestamps des logs

# --- DEBUT MODIFICATION : Initialisation passive de _LOGGER pour être patché ---
# _LOGGER est initialisé à None par défaut.
# control_panel.py (ou un module parent) le patchera avec l'instance réelle du logger.
# Si ce module est exécuté directement (__main__), il instanciera un FallbackMockLogger.
_LOGGER = None

# MockLogger simple pour le cas où modules.logger.Logger n'est pas disponible OU n'est pas patché
class FallbackMockLogger:
    def log_debug(self, msg): print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback DEBUG] {msg}")
    def log_info(self, msg): print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback INFO] {msg}")
    def log_warning(self, msg): print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback WARNING] {msg}")
    def log_error(self, msg): print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback ERROR] {msg}")
    def log_critical(self, msg): print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback CRITICAL] {msg}")
    def get_new_logs(self, last_log_index: int = 0) -> tuple[list[str], int]: return [], 0
    def reset_logs(self): pass

# --- FIN MODIFICATION ---


class FileExplorer:
    TARGET_TYPE_FILE = "file"
    TARGET_TYPE_DIRECTORY = "directory"

    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        self.found_targets = []
        self.sensitive_regex_patterns = [
            r'\.sql(?:\.zip|\.gz|\.bz2|\.rar|\.7z)?$',
            r'backup(?:s)?\.(?:zip|tar\.gz|tgz|rar|7z|sql)$',
            r'(?:wp|wordpress|site|db)_dump_?\d{8}(?:_\d{6})?\.sql(?:(?:\.zip|\.gz|\.bz2)?)$',
            r'(?:private|confidential|secret|internal|users|clients|passwords|creds|credentials|key)s?\.(?:pdf|doc|docx|xls|xlsx|csv|txt|ini|json|log)$',
            r'(?:debug|error|access|application|php)\.log(?:\.\d+)?$',
            r'\.env(?:\.sample)?$',
            r'wp-config-backup(?:s)?\.php$',
            r'(?:config|settings|ftp|ssh)\.(?:json|ini|txt|yml|yaml)$',
            r'(?:backups|private|secrets|exports|temp|tmp)(?:\/|\\|_)'
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.sensitive_regex_patterns]
        self.exclude_dirs = [
            'node_modules', '.git', '.svn', '__pycache__', 'vendor',
            'wp-admin', 'wp-includes'
        ]
        self.base_path = "" # Initialisé ici pour éviter une erreur si _get_readable_path est appelé avant explore_path

        # --- DEBUT MODIFICATION : Assurer l'utilisation du logger patché ---
        # Si _LOGGER a été patché par control_panel.py, cette instance l'utilisera.
        # Sinon (par exemple, si exécuté seul et que _LOGGER a été défini ci-dessous dans __main__),
        # il utilisera le FallbackMockLogger.
        global _LOGGER
        self._LOGGER = _LOGGER
        self._LOGGER.log_info(f"[FileExplorer] Initialisé (Debug Mode: {debug_mode}).")
        # --- FIN MODIFICATION ---

    def _log_debug(self, message: str):
        if self.debug_mode:
            self._LOGGER.log_debug(f"[FileExplorer] {message}") # Utilise self._LOGGER

    def _is_sensitive(self, name: str) -> str | None:
        for pattern_obj in self.compiled_patterns:
            if pattern_obj.search(name):
                return pattern_obj.pattern
        return None

    def _get_readable_path(self, path: str) -> str:
        if hasattr(self, 'base_path') and path.startswith(self.base_path):
            return os.path.relpath(path, self.base_path)
        return path

    def explore_path(self, base_path: str, max_depth: int = 3):
        self.base_path = base_path
        self.found_targets = []
        self._LOGGER.log_info(f"[FileExplorer] Début de l'exploration locale de '{base_path}' jusqu'à une profondeur de {max_depth}.")

        if not os.path.exists(base_path):
            self._LOGGER.log_error(f"[FileExplorer] Le chemin de base '{base_path}' n'existe pas.")
            return []
        if not os.path.isdir(base_path):
            self._LOGGER.log_error(f"[FileExplorer] Le chemin de base '{base_path}' n'est pas un répertoire.")
            return []


        for root, dirs, files in os.walk(base_path):
            current_depth = root.count(os.sep) - base_path.count(os.sep)
            if current_depth > max_depth:
                dirs[:] = []
                continue

            dirs_to_keep = []
            for d in dirs:
                if d in self.exclude_dirs:
                    self._log_debug(f"Exclusion du répertoire : {os.path.join(root, d)}")
                else:
                    dirs_to_keep.append(d)
            dirs[:] = dirs_to_keep


            sensitive_match = self._is_sensitive(os.path.basename(root))
            if sensitive_match:
                self.found_targets.append({
                    'path': self._get_readable_path(root),
                    'full_path': root,
                    'type': self.TARGET_TYPE_DIRECTORY,
                    'sensitive_match': sensitive_match
                })
                self._LOGGER.log_warning(f"[FileExplorer] Dossier sensible trouvé: {self._get_readable_path(root)} (Match: {sensitive_match})")


            for file_name in files:
                sensitive_match = self._is_sensitive(file_name)
                if sensitive_match:
                    full_file_path = os.path.join(root, file_name)
                    self.found_targets.append({
                        'path': self._get_readable_path(full_file_path),
                        'full_path': full_file_path,
                        'type': self.TARGET_TYPE_FILE,
                        'sensitive_match': sensitive_match
                    })
                    self._LOGGER.log_warning(f"[FileExplorer] Fichier sensible trouvé: {self._get_readable_path(full_file_path)} (Match: {sensitive_match})")
                else:
                    self._log_debug(f"Fichier non sensible: {self._get_readable_path(os.path.join(root, file_name))}")


        self._LOGGER.log_info(f"[FileExplorer] Exploration locale terminée. {len(self.found_targets)} cibles trouvées.")
        return self.found_targets

    def read_file_content(self, target_full_path: str, max_bytes: int = 10240) -> str:
        self._LOGGER.log_debug(f"[FileExplorer] Lecture du contenu de: {target_full_path}")
        if not os.path.exists(target_full_path) or not os.path.isfile(target_full_path):
            self._LOGGER.log_error(f"[FileExplorer] Chemin de fichier invalide ou inexistant: {target_full_path}")
            return "[ERREUR] Le chemin spécifié n'existe pas ou n'est pas un fichier."

        try:
            with open(target_full_path, 'rb') as f:
                content_bytes = f.read(max_bytes)
                decoded_content = content_bytes.decode('utf-8', errors='replace')

                if f.read(1):
                    decoded_content += "\n[... Contenu tronqué, lire le fichier complet pour voir la suite ...]"

                return decoded_content
        except PermissionError:
            self._LOGGER.log_error(f"[FileExplorer] Permission refusée pour lire: {target_full_path}")
            return "[ERREUR] Permission refusée pour lire ce fichier."
        except Exception as e:
            self._LOGGER.log_error(f"[FileExplorer] Erreur inattendue lors de la lecture de {target_full_path}: {e}")
            return f"[ERREUR] Impossible de lire le fichier: {e}"

    def download_file_base64(self, target_full_path: str) -> str:
        self._LOGGER.log_debug(f"[FileExplorer] Téléchargement de (Base64): {target_full_path}")
        if not os.path.exists(target_full_path) or not os.path.isfile(target_full_path):
            self._LOGGER.log_error(f"[FileExplorer] Chemin de fichier invalide ou inexistant pour téléchargement: {target_full_path}")
            return "[ERREUR] Le chemin spécifié n'existe pas ou n'est pas un fichier."

        try:
            with open(target_full_path, 'rb') as f:
                file_content = f.read()
            return base64.b64encode(file_content).decode('utf-8')
        except PermissionError:
            self._LOGGER.log_error(f"[FileExplorer] Permission refusée pour télécharger: {target_full_path}")
            return "[ERREUR] Permission refusée pour télécharger ce fichier."
        except Exception as e:
            self._LOGGER.log_error(f"[FileExplorer] Erreur inattendue lors du téléchargement de {target_full_path}: {e}")
            return f"[ERREUR] Impossible de lire le fichier pour le téléchargement: {e}"

    def get_found_targets(self) -> list:
        return self.found_targets

    def reset_state(self):
        self.found_targets = []
        self._LOGGER.log_info("[FileExplorer] État réinitialisé.")

# --- Bloc de test (pour exécution autonome du module) ---
if __name__ == "__main__":
    # Ce bloc ne s'exécute que si file_explorer.py est lancé directement
    # Il assure qu'un logger est disponible pour les tests unitaires.
    print("[+] Test du module FileExplorer (mode autonome)...")
    # Initialisation du _LOGGER global pour le test autonome
    try:
        from modules.logger import Logger as AgentLoggerTest
        _LOGGER = AgentLoggerTest(None, None, debug_mode=True, stdout_enabled=True)
        print("[INFO] AgentLogger utilisé pour les tests autonomes de FileExplorer.")
    except ImportError:
        _LOGGER = FallbackMockLogger() # Défini au début du fichier
        print("[WARNING] AgentLogger non disponible. FallbackMockLogger utilisé pour les tests autonomes de FileExplorer.")

    file_explorer = FileExplorer(debug_mode=True)

    # Créer un répertoire temporaire pour le test
    test_dir = "temp_test_dir_for_file_explorer"
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "sensitive.log"), "w") as f:
        f.write("Ceci est un log sensible.")
    with open(os.path.join(test_dir, "normal.txt"), "w") as f:
        f.write("Ceci est un fichier normal.")
    os.makedirs(os.path.join(test_dir, "wp-content", "backups"), exist_ok=True)

    print("\n--- Exécution de l'exploration pour générer des logs ---")
    file_explorer.explore_path(test_dir)

    print("\n--- Récupération des logs (via le logger global du module) ---")
    all_current_logs, total_logs_count = _LOGGER.get_new_logs()
    for log in all_current_logs:
        print(f"LOG: {log}")
    print(f"Total de logs collectés: {total_logs_count}")

    print("\n--- Récupération des nouveaux logs (après un certain temps/action) ---")
    _LOGGER.log_info("[FileExplorer] Un nouveau message de log après l'exploration.")
    _LOGGER.log_warning("[FileExplorer] Attention: un autre événement s'est produit.")

    new_logs, new_total_count = _LOGGER.get_new_logs(total_logs_count)
    print(f"Nouveaux logs depuis l'index {total_logs_count}:")
    for log in new_logs:
        print(f"NOUVEAU LOG: {log}")
    print(f"Nouveau total de logs: {new_total_count}")


    # Nettoyage
    os.remove(os.path.join(test_dir, "sensitive.log"))
    os.remove(os.path.join(test_dir, "normal.txt"))
    os.rmdir(os.path.join(test_dir, "wp-content", "backups"))
    os.rmdir(os.path.join(test_dir, "wp-content"))
    os.rmdir(test_dir)
    print("\n[+] Test de FileExplorer terminé.")


