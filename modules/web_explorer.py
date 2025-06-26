import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse, unquote
import json
import os
import time
from datetime import datetime # Pour inférer les années et mois dans les URLs
import base64 # Ajouté pour la fonction download_file_base64_from_url

# Simuler l'import du Logger de l'agent.
# --- DEBUT MODIFICATION ---
_LOGGER = None # Initialisé à None, car il sera patché par control_panel.py
try:
    from modules.logger import Logger as AgentLogger
    _LOGGER = AgentLogger(None, None, debug_mode=True) # Fallback pour les tests autonomes
except ImportError:
    pass

# MockLogger simple pour le cas où modules.logger.Logger n'est pas disponible ET n'est pas patché
class FallbackMockLogger:
    def log_debug(self, msg): print(f"[Fallback DEBUG] {msg}")
    def log_info(self, msg): print(f"[Fallback INFO] {msg}")
    def log_warning(self, msg): print(f"[Fallback WARNING] {msg}")
    def log_error(self, msg): print(f"[Fallback ERROR] {msg}")
    def log_critical(self, msg): print(f"[Fallback CRITICAL] {msg}")
    def get_new_logs(self, last_log_index: int = 0) -> tuple[list[str], int]: return [], 0
    def reset_logs(self): pass

if _LOGGER is None:
    _LOGGER = FallbackMockLogger()
    print("[WARNING] modules.logger.Logger non trouvé ou non initialisé. Utilisation de FallbackMockLogger dans WebExplorer.")
# --- FIN MODIFICATION ---


class WebExplorer:
    TARGET_TYPE_FILE = "file"
    TARGET_TYPE_DIRECTORY = "directory"

    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        self.found_targets = []
        self.visited_urls = set()
        self.initial_domain = None

        self.sensitive_regex_patterns = [
            r'\.sql(?:\.zip|\.gz|\.bz2|\.rar|\.7z)?$',
            r'backup(?:s)?\.(?:zip|tar\.gz|tgz|rar|7z|sql)$',
            r'(?:wp|wordpress|site|db)_dump_?\d{8}(?:_\d{6})?\.sql(?:(?:\.zip|\.gz|\.bz2)?)$',
            r'(?:private|confidential|secret|internal|users|clients|passwords|creds|credentials|key)s?\.(?:pdf|doc|docx|xls|xlsx|csv|txt|ini|json|log)$',
            r'(?:debug|error|access|application|php)\.log(?:\.\d+)?$',
            r'\.env(?:\.sample)?$',
            r'wp-config-backup(?:s)?\.php$',
            r'(?:config|settings|ftp|ssh)\.(?:json|ini|txt|yml|yaml)$',
            r'(?:backups|private|secrets|exports|temp|tmp)(?:\/|\\|_)',
            r'wp-content\/uploads\/\d{4}\/\d{2}\/.*' # Pour les chemins annuels/mensuels dans uploads
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.sensitive_regex_patterns]

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.session = requests.Session()

        # --- DEBUT MODIFICATION ---
        # S'assurer que le logger de l'instance est bien le logger global défini dans control_panel.py
        # Normalement, control_panel.py patchera déjà WebExplorer._LOGGER
        # Mais pour la sécurité, on utilise aussi l'instance globale si ce module est lancé seul.
        global _LOGGER # Déclare qu'on utilise le _LOGGER global de ce module
        self._LOGGER = _LOGGER
        self._LOGGER.log_info(f"[WebExplorer] Initialisé (Debug Mode: {debug_mode}).")
        # --- FIN MODIFICATION ---

    def _log_debug(self, message: str):
        if self.debug_mode:
            self._LOGGER.log_debug(f"[WebExplorer] {message}")

    def _is_sensitive(self, name_or_path: str) -> str | None:
        for pattern_obj in self.compiled_patterns:
            if pattern_obj.search(name_or_path):
                return pattern_obj.pattern
        return None

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def explore_url(self, target_url: str, max_depth: int = 2, current_depth: int = 0):
        if current_depth > max_depth:
            self._log_debug(f"Profondeur maximale atteinte pour '{target_url}'.")
            return []

        # S'assurer que l'URL est bien formée
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = "http://" + target_url

        # Initialiser le domaine cible si c'est le premier appel
        if self.initial_domain is None:
            self.initial_domain = urlparse(target_url).netloc
            self._LOGGER.log_info(f"[WebExplorer] Début de l'exploration web de '{target_url}' (Domaine cible: {self.initial_domain}, Profondeur max: {max_depth}).")

        if target_url in self.visited_urls:
            self._log_debug(f"URL déjà visitée : '{target_url}'.")
            return []

        self.visited_urls.add(target_url)
        self._LOGGER.log_info(f"[WebExplorer] Exploration de l'URL : '{target_url}' (Profondeur: {current_depth})")

        found_in_this_run = []
        try:
            response = self.session.get(target_url, headers=self.headers, timeout=15, allow_redirects=True)
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '').lower()

            # Vérifier si l'URL elle-même (le nom du fichier/dossier dans l'URL) est sensible
            # On vérifie à la fois le segment final du chemin et le chemin complet de l'URL
            path_url_parsed = urlparse(target_url)
            path_segment = unquote(path_url_parsed.path.split('/')[-1])
            full_url_path = unquote(path_url_parsed.path)

            sensitive_match_segment = self._is_sensitive(path_segment)
            sensitive_match_full_path = self._is_sensitive(full_url_path)

            if sensitive_match_segment or sensitive_match_full_path:
                match_reason = sensitive_match_segment if sensitive_match_segment else sensitive_match_full_path
                self.found_targets.append({
                    'path': path_url_parsed.path,
                    'full_path': target_url,
                    'type': self.TARGET_TYPE_FILE if '.' in path_segment else self.TARGET_TYPE_DIRECTORY,
                    'sensitive_match': match_reason
                })
                self._LOGGER.log_warning(f"[WebExplorer] Cible URL sensible trouvée: {target_url} (Match: {match_reason})")
                found_in_this_run.append(target_url)


            # Si c'est du HTML, parser les liens pour explorer plus profondément
            if 'text/html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Cible plus agressivement les liens qui pourraient pointer vers des fichiers
                link_tags = soup.find_all(['a', 'link', 'script', 'img'])
                # Ajout de liens dans les commentaires (parfois des infos cachées)
                comments_with_links = re.findall(r'(?:http[s]?://\S+)', response.text)

                links_to_explore = set()

                for tag in link_tags:
                    href = tag.get('href') or tag.get('src')
                    if href:
                        links_to_explore.add(href)

                # Ajouter des URLs inférées basées sur la structure WordPress
                if current_depth == 0: # Pour une "tête chercheuse", on ajoute des chemins connus dès le départ
                    self._LOGGER.log_debug("[WebExplorer] Ajout de chemins WordPress par défaut pour la découverte.")
                    # Années récentes et futures possibles (ex: pour des uploads datés)
                    for year in range(datetime.now().year - 2, datetime.now().year + 2):
                        # Mois classiques
                        for month in range(1, 13):
                            links_to_explore.add(f"/wp-content/uploads/{year}/{month:02}/")

                    # Fichiers et dossiers sensibles connus à la racine ou chemins typiques
                    links_to_explore.add("/wp-config.php")
                    links_to_explore.add("/wp-config.php.bak")
                    links_to_explore.add("/.env")
                    links_to_explore.add("/.env.example")
                    links_to_explore.add("/backup.zip")
                    links_to_explore.add("/database.sql")
                    links_to_explore.add("/wp-content/backups/") # Dossier de backup
                    links_to_explore.add("/wp-content/cache/") # Dossier de cache
                    links_to_explore.add("/wp-content/plugins/revslider/temp/") # Exemple de chemins connus pour des vulnérabilités / fichiers temporaires

                for comment_link in comments_with_links:
                    links_to_explore.add(comment_link)


                for href in links_to_explore:
                    absolute_url = urljoin(target_url, href)

                    parsed_abs_url = urlparse(absolute_url)
                    if parsed_abs_url.netloc != self.initial_domain:
                        self._log_debug(f"Lien externe ignoré : {absolute_url}")
                        continue

                    absolute_url_cleaned = absolute_url.split('#')[0]

                    link_file_name = unquote(parsed_abs_url.path.split('/')[-1])

                    sensitive_match_link_name = self._is_sensitive(link_file_name)
                    sensitive_match_link_path = self._is_sensitive(parsed_abs_url.path)

                    if sensitive_match_link_name or sensitive_match_link_path:
                        match_reason = sensitive_match_link_name if sensitive_match_link_name else sensitive_match_link_path
                        self.found_targets.append({
                            'path': parsed_abs_url.path,
                            'full_path': absolute_url_cleaned,
                            'type': self.TARGET_TYPE_FILE if '.' in link_file_name else self.TARGET_TYPE_DIRECTORY,
                            'sensitive_match': match_reason
                        })
                        self._LOGGER.log_warning(f"[WebExplorer] Lien sensible trouvé: {absolute_url_cleaned} (Match: {match_reason})")

                    # Continuer l'exploration récursive pour les liens HTML standards (pas pour les fichiers binaires/images/css/js)
                    # On évite de crawler des extensions connues pour être des assets non-HTML, mais on peut les détecter comme cibles sensibles.
                    if not any(absolute_url_cleaned.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.webp', '.pdf', '.zip', '.sql', '.xlsx', '.docx', '.json']):
                         found_in_this_run.extend(self.explore_url(absolute_url_cleaned, max_depth, current_depth + 1))

                    time.sleep(0.1)


            else:
                self._log_debug(f"Type de contenu non HTML pour '{target_url}': {content_type}. Pas de parsing de liens.")

        except requests.exceptions.RequestException as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP/réseau pour '{target_url}': {e}")
        except Exception as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors de l'exploration de '{target_url}': {e}")

        return found_in_this_run

    def read_file_content_from_url(self, target_url: str, max_bytes: int = 10240) -> str:
        self._LOGGER.log_debug(f"[WebExplorer] Lecture du contenu de l'URL : {target_url}")
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = "http://" + target_url

        try:
            response = self.session.get(target_url, headers=self.headers, stream=True, timeout=10)
            response.raise_for_status()

            content_bytes = b''
            for chunk in response.iter_content(chunk_size=1024):
                content_bytes += chunk
                if len(content_bytes) >= max_bytes:
                    content_bytes = content_bytes[:max_bytes]
                    break

            decoded_content = content_bytes.decode('utf-8', errors='replace')

            if len(content_bytes) == max_bytes and 'Content-Length' in response.headers and int(response.headers['Content-Length']) > max_bytes:
                decoded_content += "\n[... Content truncated, download full file to view more ...]"

            return decoded_content
        except requests.exceptions.RequestException as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP/réseau lors de la lecture du contenu de {target_url}: {e}")
            return f"[ERROR] Network/HTTP error reading URL content: {e}"
        except Exception as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors de la lecture du contenu de {target_url}: {e}")
            return f"[ERROR] Unexpected error reading URL content: {e}"

    def download_file_base64_from_url(self, target_url: str) -> str:
        self._LOGGER.log_debug(f"[WebExplorer] Téléchargement de (Base64) : {target_url}")
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = "http://" + target_url

        try:
            response = self.session.get(target_url, headers=self.headers, timeout=30)
            response.raise_for_status()

            file_content = response.content
            return base64.b64encode(file_content).decode('utf-8')
        except requests.exceptions.RequestException as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP/réseau lors du téléchargement de {target_url}: {e}")
            return f"[ERROR] Network/HTTP error downloading URL: {e}"
        except Exception as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors du téléchargement de {target_url}: {e}")
            return f"[ERROR] Unexpected error downloading URL: {e}"

    def get_found_targets(self) -> list:
        return self.found_targets

    def reset_state(self):
        self.found_targets = []
        self.visited_urls = set()
        self.initial_domain = None
        self._LOGGER.log_info("[WebExplorer] État réinitialisé.") # Utilise self._LOGGER


# --- Bloc de test (inchangé) ---
if __name__ == "__main__":
    print("[+] Test du module WebExplorer...")
    explorer = WebExplorer(debug_mode=True)

    # Test 1: Exploration d'une URL simple
    print("\n--- Test 1: Exploration d'une URL simple ---")
    # Utiliser un site de test qui ne bloque pas les crawlers et contient des liens
    test_site_url = "http://testphp.vulnweb.com/"
    print(f"Exploration de : {test_site_url}")
    explorer.explore_url(test_site_url, max_depth=1)
    targets = explorer.get_found_targets()
    print(f"Cibles sensibles trouvées : {json.dumps(targets, indent=2)}")
    explorer.reset_state()
    print("-" * 40)

    # Test 2: Lecture de contenu depuis une URL (simulée avec un fichier local pour le test)
    # Pour un vrai test, il faudrait une URL de fichier texte accessible.
    print("\n--- Test 2: Lecture de contenu depuis une URL ---")
    # Pour simuler, nous allons essayer de lire une page HTML connue
    # Note: Cette fonction est pour lire des fichiers, pas des pages entières de manière optimale.
    content = explorer.read_file_content_from_url("http://testphp.vulnweb.com/disclaimer.php", max_bytes=500)
    print("Contenu de la page (premiers 500 octets):")
    print(content[:200] + "..." if len(content) > 200 else content)
    print("-" * 40)

    # Test 3: Téléchargement Base64 depuis une URL (simulée)
    print("\n--- Test 3: Téléchargement Base64 depuis une URL ---")
    # Ici, nous ne pouvons pas réellement télécharger un fichier binaire depuis un site de test
    # sans risquer de le surcharger. Ceci est un exemple théorique.
    # Pour un test réel, il faudrait pointer vers une petite image ou un fichier texte.
    # data_b64 = explorer.download_file_base64_from_url("http://testphp.vulnweb.com/images/logo.gif")
    # print(f"Contenu Base64 (début): {data_b64[:50]}..." if data_b64 else "Échec du téléchargement Base64.")
    print("Test de téléchargement Base64 omis pour éviter des requêtes excessives sur un site externe.")
    print("-" * 40)

    # Test 4: Vérification des chemins sensibles WordPress (illustratif, ne fera pas de requêtes réelles)
    print("\n--- Test 4: Vérification des chemins sensibles WordPress (illustratif) ---")
    print("Cette partie de la 'tête chercheuse' est déclenchée au démarrage de l'exploration.")
    print("Elle tente de construire des URLs basées sur des motifs courants.")
    # On peut simuler l'ajout de ces chemins au set visited_urls pour montrer l'effet
    explorer.reset_state()
    # Simuler le premier appel à explore_url
    explorer.explore_url("http://example.com/", max_depth=0) # max_depth=0 pour voir juste l'initialisation
    print("Les URLs de tête chercheuse sont ajoutées au set de liens à explorer au démarrage.")
    print(f"Exemples de liens potentiellement ajoutés (vérifier les logs DEBUG pour voir l'ajout):")
    print("  /wp-config.php, /.env, /wp-content/uploads/YYYY/MM/...")
    # Vérifier si la logique de détection des sensibles fonctionne sur une URL "construite"
    test_sensitive_url = "http://example.com/wp-content/uploads/2024/05/db_dump_20240515.sql.zip"
    explorer.explore_url(test_sensitive_url, max_depth=0) # Test direct sur une URL sensible
    targets = explorer.get_found_targets()
    print(f"Cibles sensibles détectées (y compris l'URL test sensitive si elle match): {json.dumps(targets, indent=2)}")
    explorer.reset_state()
    print("-" * 40)

    print("[+] Tous les tests de WebExplorer terminés.")

