import requests
from bs4 import BeautifulSoup, Comment
import re
from urllib.parse import urljoin, urlparse, unquote, parse_qs
import json
import os
import time
from datetime import datetime
import base64
import collections
import hashlib
import mimetypes
from typing import List, Tuple, Dict, Any, Optional

# --- CORRECTION ICI : Import de requests_cache en dehors du try/except pour le rendre toujours défini si l'import réussit ---
try:
    import requests_cache
    _CACHE_ENABLED = True
    # Assurez-vous que le cache est installé et vidé si nécessaire
    requests_cache.install_cache('web_explorer_cache', backend='sqlite', expire_after=3600) # Cache 1 heure
    if not os.environ.get('WERKZEUG_RUN_MAIN'):
        requests_cache.clear()
        print("[INFO] requests_cache activé et vidé pour WebExplorer au démarrage.")
    else:
        print("[INFO] requests_cache activé pour WebExplorer (conserve le cache en mode dev).")
except ImportError:
    requests_cache = None # S'il ne peut pas être importé, on le définit à None
    _CACHE_ENABLED = False
    print("[WARNING] requests_cache non trouvé. Les requêtes ne seront pas mises en cache.")

# --- Initialisation passive de _LOGGER pour être patché par control_panel.py ---
_LOGGER = None
class FallbackMockLogger:
    def log_debug(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback DEBUG] {msg}")
    def log_info(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback INFO] {msg}")
    def log_warning(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback WARNING] {msg}")
    def log_error(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback ERROR] {msg}")
    def log_critical(self, msg): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Fallback CRITICAL] {msg}")
    def get_new_logs(self, last_log_index: int = 0) -> tuple[List[str], int]: return [], 0
    def reset_logs(self): pass

class WebExplorer:
    # Types de cibles identifiées pour l'interface utilisateur
    TARGET_TYPE_FILE = "file"
    TARGET_TYPE_DIRECTORY = "directory"
    TARGET_TYPE_CONTENT = "content_match"
    TARGET_TYPE_API = "api_endpoint"
    TARGET_TYPE_VULN = "vulnerable_path"
    TARGET_TYPE_SITEMAP_ENTRY = "sitemap_entry"
    TARGET_TYPE_FORM = "form_data"
    
    # Extensions de fichiers courantes à considérer comme des fichiers téléchargeables
    DOWNLOADABLE_FILE_EXTENSIONS = {
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', # Archives
        '.sql', '.db', '.sqlite', # Bases de données
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', # Documents
        '.txt', '.log', '.json', '.xml', '.ini', '.yml', '.yaml', '.conf', '.env', '.md', # Configuration/Logs/Texte
        '.pem', '.key', '.crt', # Clés/Certificats
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', # Images
        '.js', '.css', # Scripts/Stylesheets (parfois sensibles)
        '.mp3', '.mp4', '.avi', '.mov', # Médias
    }

    # Statistiques d'exploration
    _stats = {
        'urls_visited': 0,
        'urls_queued': 0,
        'urls_skipped_external': 0,
        'urls_skipped_visited': 0,
        'urls_skipped_robots': 0,
        'files_identified': 0,
        'dirs_identified': 0,
        'content_matches': 0,
        'api_endpoints_identified': 0,
        'vuln_paths_identified': 0,
        'sitemap_entries_identified': 0,
        'forms_identified': 0,
        'requests_successful': 0,
        'requests_failed': 0,
        'total_requests_made': 0,
        'bytes_downloaded_html': 0,
        'bytes_downloaded_files': 0,
        'last_status': 'Idle',
        'current_url': 'N/A',
        'start_time': None,
        'end_time': None,
        'duration_seconds': 0
    }
    
    def __init__(self, debug_mode: bool = False,
                 follow_robots_txt: bool = True,
                 max_redirects: int = 5,
                 request_timeout: int = 30,
                 delay_between_requests: float = 0.5,
                 allowed_content_types_for_recursion: Optional[List[str]] = None,
                 auth_headers: Optional[Dict[str, str]] = None
                ):
        self.debug_mode = debug_mode
        self.found_targets = []
        self.urls_to_visit = collections.deque()
        self.visited_urls_hash = set()
        self.initial_domain = None
        
        self.follow_robots_txt = follow_robots_txt
        self.max_redirects = max_redirects
        self.request_timeout = request_timeout
        self.delay_between_requests = delay_between_requests
        self.robots_disallow_paths: Dict[str, List[re.Pattern]] = {}
        
        if allowed_content_types_for_recursion is None:
            self.allowed_content_types_for_recursion = ['text/html', 'application/xhtml+xml']
        else:
            self.allowed_content_types_for_recursion = allowed_content_types_for_recursion
                                                  
        # --- DÉBUT CORRECTION DE L'ORDRE DES ATTRIBUTS ---
        # Définition de tous les attributs sensibles_patterns et compilation en premier
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
            r'wp-content\/uploads\/\d{4}\/\d{2}\/.*',
            r'phpinfo(?:-config)?\.php$',
            r'test(?:site)?\.php$',
            r'\.git(?:attributes|config|description|HEAD|index|info|logs|objects|refs|packed-refs|FETCH_HEAD|ORIG_HEAD|COMMIT_EDITMSG)$',
            r'\.svn(?:wc\.db|entries|tmp|text-base|props)$',
            r'\.bash_history$',
            r'\.ssh\/id_rsa$', r'\.ssh\/id_dsa$',
            r'\.npmrc$', r'\.gitignore$',
            r'web-config\.xml$',
            r'credentials\.json$', r'serviceAccount\.json$',
            r'log(?:s)?\/(?:error|access|debug|application)\.(?:log|txt)$'
        ]
        self.sensitive_content_patterns = [
            r'api_key\s*=\s*[\'"]([a-z0-9]{20,})[\'"]',
            r'(?:password|pass|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'secret_key\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'(?:oauth|token)\s*[:=]\s*[\'"]([a-z0-9\/+=]{32,})[\'"]',
            r'Authorization:\s*Bearer\s*([a-zA-Z0-9._-]+)',
            r'stripe_s?k_test_[a-zA-Z0-9]{24}', r'pk_test_[a-zA-Z0-9]{24}',
            r'sk_live_[a-zA-Z0-9]{24}', r'pk_live_[a-zA-Z0-9]{24}',
            r'(?:aws_access_key_id|aws_secret_access_key)[=:\s][\'"]([a-zA-Z0-9\/+=]{20,})[\'"]',
            r'db_password\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'ftp_pass\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'(?:BEGIN RSA PRIVATE KEY|BEGIN DSA PRIVATE KEY|BEGIN EC PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK)',
            r'(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)',
            r'(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})',
            r'(?:client_id|client_secret)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'ssh-(rsa|dss|ed25519)\s+A{3}A[0-9A-Za-z+\/=]+\s*(?:.*@)?(?:.*)\s*',
            r'jdbc:mysql:\/\/[\w.-]+:\d+\/[\w.-]+\?user=[\w.-]+&password=([^\s&]+)',
            r'(\b\d{16}\b|\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b)',
            r'(?:ssn|social security number)[^a-z0-9]*(\d{3}[- ]?\d{2}[- ]?\d{4})',
        ]
        self.api_endpoint_patterns = [
            r'\/api\/v[0-9]+', r'\/rest\/v[0-9]+', r'\/graphql', r'\/jsonapi',
            r'\/wp-json\/wp\/v2', r'\/xmlrpc\.php', r'\/admin-ajax\.php'
        ]
        self.vulnerable_paths = [
            r'\/phpmyadmin\/', r'\/adminer\.php', r'\/test\.php',
            r'\/backup\.zip', r'\/db_dump\.sql', r'\/wp-config\.php',
            r'\/vendor\/phpunit\/phpunit\/src\/Util\/PHP\/eval-stdin\.php',
            r'\/drupal\/sites\/default\/files\/private\/',
            r'\/joomla\/administrator\/',
            r'\/cpanel\/', r'\/webmail\/',
            r'\/.git\/config', r'\/.env', r'\/.dockerignore', r'\/Dockerfile',
            r'\/wp-content\/debug\.log', r'\/wp-content\/plugins\/revslider\/temp\/',
            r'\/console\/', r'\/debugbar\/',
            r'\/_wpeprivate\/config\.json',
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.sensitive_regex_patterns]
        self.compiled_content_patterns = [re.compile(p, re.IGNORECASE) for p in self.sensitive_content_patterns]
        self.compiled_api_patterns = [re.compile(p, re.IGNORECASE) for p in self.api_endpoint_patterns]
        self.compiled_vulnerable_paths = [re.compile(p, re.IGNORECASE) for p in self.vulnerable_paths]
        
        # Définition des User-Agents pour la rotation (plus furtif)
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
        ]
        self._current_user_agent_index = 0
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        if auth_headers:
            self.headers.update(auth_headers)
                                                  
        self.session = requests.Session()
        # --- FIN CORRECTION DE L'ORDRE DES ATTRIBUTS ---
        
        global _LOGGER
        # Si _LOGGER n'a pas encore été patché par control_panel.py, on utilise le FallbackMockLogger
        if _LOGGER is None:
            _LOGGER = FallbackMockLogger()
            print("[WARNING] modules.logger.Logger non trouvé ou non initialisé. Utilisation de FallbackMockLogger dans WebExplorer (autonome).")

        self._LOGGER = _LOGGER
        self._LOGGER.log_info(f"[WebExplorer] Initialisé (Debug Mode: {debug_mode}).")
                                                      
    def _log_debug(self, message: str):
        if self.debug_mode:
            self._LOGGER.log_debug(f"[WebExplorer] {message}")
                                                                                  
    def _hash_url(self, url: str) -> str:
        """Retourne un hachage SHA256 de l'URL pour un stockage compact dans visited_urls_hash."""
        return hashlib.sha256(url.encode('utf-8')).hexdigest()        
    def _get_next_user_agent(self) -> str:
        """Fait pivoter les User-Agents."""
        ua = self.user_agents[self._current_user_agent_index]
        self._current_user_agent_index = (self._current_user_agent_index + 1) % len(self.user_agents)
        return ua                                                     
    def _is_sensitive_path_or_name(self, name_or_path: str) -> str | None:
        """Vérifie si un nom de chemin ou de fichier correspond à un motif sensible."""
        for pattern_obj in self.compiled_patterns:
            if pattern_obj.search(name_or_path):
                return pattern_obj.pattern
        return None                                                   
    def _is_sensitive_content(self, text_content: str) -> List[Tuple[str, str]]:
        """Recherche des motifs sensibles dans le contenu textuel et retourne les correspondances."""
        found_matches = []                                                    
        for pattern_obj in self.compiled_content_patterns:
            for match in pattern_obj.finditer(text_content):                          
                matched_string = match.group(0)
                if len(match.groups()) > 0 and match.group(1) is not None:
                    found_matches.append((pattern_obj.pattern, match.group(1)))
                else:                                                                     
                    found_matches.append((pattern_obj.pattern, matched_string))                                                                     
        return found_matches
                                                                          
    def _is_api_endpoint(self, url_path: str) -> str | None:
        """Vérifie si un chemin d'URL est un endpoint API connu."""
        for pattern_obj in self.compiled_api_patterns:                            
            if pattern_obj.search(url_path):
                return pattern_obj.pattern                                    
        return None
                                                                          
    def _is_vulnerable_path(self, url_path: str) -> str | None:
        """Vérifie si un chemin d'URL est un chemin connu de vulnérabilité/exposition."""
        for pattern_obj in self.compiled_vulnerable_paths:                        
            if pattern_obj.search(url_path):
                return pattern_obj.pattern
        return None                                                   
    def _get_base_url_from_full_url(self, url: str) -> str:
        """Extrait l'URL de base (schéma + domaine) d'une URL complète."""
        parsed = urlparse(url)                                                
        return f"{parsed.scheme}://{parsed.netloc}"
                                                                          
    def _fetch_robots_txt(self, base_url: str):
        """Récupère et parse le fichier robots.txt pour un domaine."""
        robots_url = urljoin(base_url, '/robots.txt')                         
        try:
            response = self.session.get(robots_url, headers={'User-Agent': self._get_next_user_agent()}, timeout=self.request_timeout)                  
            if response.status_code == 200:
                disallow_paths = []                                                   
                for line in response.text.splitlines():
                    if line.strip().lower().startswith('disallow:'):
                        path = line.strip()[len('disallow:'):].strip()                        
                        if path and path != '/':
                            regex_path = re.escape(path).replace(r'\*', '.*')                                                                                           
                            disallow_paths.append(re.compile(f"^{regex_path}"))                                                                             
                self.robots_disallow_paths[self._get_base_url_from_full_url(base_url)] = disallow_paths                                                     
                self._LOGGER.log_info(f"[WebExplorer] robots.txt trouvé pour {base_url}. {len(disallow_paths)} règles Disallow détectées.")             
            else:
                self._log_debug(f"Pas de robots.txt pour {base_url} (status: {response.status_code}).")
        except requests.exceptions.RequestException as e:
            self._log_debug(f"Erreur lors de la récupération de robots.txt pour {base_url}: {e}")
        except Exception as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors du parsing de robots.txt pour {base_url}: {e}", exc_info=self.debug_mode)


    def _is_allowed_by_robots(self, url: str) -> bool:
        """Vérifie si une URL est autorisée par les règles robots.txt."""                                                                           
        base_url = self._get_base_url_from_full_url(url)
        if base_url not in self.robots_disallow_paths:                            
            self._fetch_robots_txt(base_url)
                                                                              
        disallow_rules = self.robots_disallow_paths.get(base_url, [])
        path_to_check = urlparse(url).path                                    
        for pattern in disallow_rules:
            if pattern.search(path_to_check):                                         
                self._log_debug(f"URL '{url}' bloquée par robots.txt: {pattern.pattern}")                                                                   
                return False
        return True
                                                                          
    def _extract_urls_from_sitemap(self, sitemap_url: str):
        """Extrait les URLs d'un fichier sitemap.xml."""                      
        try:
            response = self.session.get(sitemap_url, headers={'User-Agent': self._get_next_user_agent()}, timeout=self.request_timeout)                  
            response.raise_for_status()                                           
            soup = BeautifulSoup(response.text, 'xml')                
            
            urls = soup.find_all('loc')                                           
            for url_tag in urls:
                loc_url = url_tag.get_text()                                          
                parsed_loc_url = urlparse(loc_url)
                if parsed_loc_url.netloc == self.initial_domain:                          
                    # Ajout des URLs de sitemap pour exploration ou comme fichier si l'extension est reconnue
                    url_path_sitemap = parsed_loc_url.path
                    file_extension_sitemap = os.path.splitext(url_path_sitemap)[1].lower()

                    if file_extension_sitemap in self.DOWNLOADABLE_FILE_EXTENSIONS:
                        self.found_targets.append({
                            'path': url_path_sitemap,
                            'full_path': loc_url,
                            'type': self.TARGET_TYPE_FILE,
                            'sensitive_match': f"Sitemap File: {file_extension_sitemap}",
                            'source': 'Sitemap Entry',
                            'content_type': mimetypes.guess_type(loc_url)[0] or 'application/octet-stream'
                        })
                        self._stats['files_identified'] += 1
                        self._LOGGER.log_info(f"[WebExplorer] Fichier de sitemap identifié: {loc_url}")
                    else:
                        self._queue_url_for_exploration(loc_url, current_depth=0) # current_depth 0 pour éviter de dépasser la profondeur max
                        self._stats['sitemap_entries_identified'] += 1
                        self._LOGGER.log_debug(f"URL de sitemap ajoutée: {loc_url}")
                else:
                    self._log_debug(f"URL de sitemap externe ignorée: {loc_url}")
            self._LOGGER.log_info(f"[WebExplorer] Sitemap '{sitemap_url}' traité. {len(urls)} URLs découvertes.")
        except requests.exceptions.RequestException as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur lors du traitement du sitemap '{sitemap_url}': {e}")                                      
        except Exception as e:
            self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors du parsing du sitemap '{sitemap_url}': {e}", exc_info=self.debug_mode)                                                                  
    
    def _queue_url_for_exploration(self, url: str, current_depth: int):
        """Ajoute une URL à la queue d'exploration si elle est valide et nouvelle."""
        # Normalise l'URL pour la comparaison et le stockage                  
        absolute_url_cleaned = urljoin(self._get_base_url_from_full_url(self._stats['current_url']), url).split('#')[0].rstrip('/')
        url_hash = self._hash_url(absolute_url_cleaned)               
        parsed_abs_url = urlparse(absolute_url_cleaned)               
        
        # Ignorer les liens externes au domaine initial de l'exploration
        if parsed_abs_url.netloc != self.initial_domain:                          
            self._stats['urls_skipped_external'] += 1                             
            self._log_debug(f"Lien externe ignoré pour la queue : {absolute_url_cleaned}")                                                              
            return
                                                                              
        # Ignorer si déjà visitée
        if url_hash in self.visited_urls_hash:                                    
            self._stats['urls_skipped_visited'] += 1
            self._log_debug(f"URL déjà visitée, ignorée pour la queue : {absolute_url_cleaned}")
            return                                                                                                                                  
        # Vérifier robots.txt
        if self.follow_robots_txt and not self._is_allowed_by_robots(absolute_url_cleaned):
            self._stats['urls_skipped_robots'] += 1                               
            self._LOGGER.log_info(f"[WebExplorer] URL '{absolute_url_cleaned}' ignorée (robots.txt).")                                                  
            return
                                                                              
        # Éviter d'ajouter à la queue si la profondeur max est atteinte pour les futures explorations                                               
        if current_depth + 1 > self.max_depth_limit:
             self._log_debug(f"URL '{absolute_url_cleaned}' ignorée (profondeur max pour queue).")
             return                                                   
        
        self.urls_to_visit.append((absolute_url_cleaned, current_depth + 1))
        self._stats['urls_queued'] += 1                                       
        self._log_debug(f"URL mise en queue : {absolute_url_cleaned} (Profondeur: {current_depth + 1})")
                                                                          
    def explore_url(self, target_url: str, max_depth: int = 2):
        """Point d'entrée principal pour l'exploration récursive."""          
        self.reset_state() # Toujours réinitialiser l'état au début d'une nouvelle exploration                                                      
        self._stats['start_time'] = datetime.now()
        self.max_depth_limit = max_depth # Stocke la profondeur max pour la queue
                                                                              
        # Initialiser la queue avec l'URL cible
        # Normalisation initiale de l'URL cible pour s'assurer qu'elle a un schéma                                                                  
        if not target_url.startswith('http://') and not target_url.startswith('https://'):                                                              
            self._LOGGER.log_warning(f"[WebExplorer] Schéma manquant pour l'URL cible, ajout de 'http://' à {target_url}")
            target_url = "http://" + target_url                                                                                                     
        # Nettoyage initial pour l'URL d'entrée
        target_url_cleaned_initial = target_url.split('#')[0].rstrip('/')                                                                   
        self.urls_to_visit.append((target_url_cleaned_initial, 0)) # (url, current_depth)                                                           
        self._stats['urls_queued'] += 1
                                                                              
        self._LOGGER.log_info(f"[WebExplorer] Démarrage de l'exploration récursive depuis '{target_url_cleaned_initial}' (Profondeur max: {max_depth}).")            
        
        while self.urls_to_visit and (datetime.now() - self._stats['start_time']).total_seconds() < 300: # Limite de temps (5 minutes)
            current_url, current_depth = self.urls_to_visit.popleft() # Prend la prochaine URL de la queue
                                                                                  
            # Gestion du délai entre les requêtes
            time.sleep(self.delay_between_requests)                                                                                                     
            # Re-normalisation pour la cohérence
            current_url_cleaned = current_url.split('#')[0].rstrip('/')                                                                     
            url_hash = self._hash_url(current_url_cleaned)                                                                                              
            
            if current_depth > max_depth:
                self._log_debug(f"Profondeur maximale ({max_depth}) atteinte pour '{current_url_cleaned}'.")
                continue # Passe à la prochaine URL dans la queue                                                                                       
            if url_hash in self.visited_urls_hash:
                self._stats['urls_skipped_visited'] += 1                              
                self._log_debug(f"URL déjà visitée : '{current_url_cleaned}'.")
                continue                                              
            
            # Initialiser le domaine cible si c'est le premier appel (après popleft)
            if self.initial_domain is None:                                           
                parsed_initial_url = urlparse(current_url_cleaned)
                self.initial_domain = parsed_initial_url.netloc                       
                self._LOGGER.log_info(f"[WebExplorer] Domaine d'exploration défini: {self.initial_domain}")
                if self.follow_robots_txt:                                                
                    self._fetch_robots_txt(self._get_base_url_from_full_url(current_url_cleaned))
                                                                                  
            # Vérifier robots.txt avant de visiter (si activé et non déjà vérifié pour cette URL)
            if self.follow_robots_txt and not self._is_allowed_by_robots(current_url_cleaned):
                self._LOGGER.log_info(f"[WebExplorer] URL '{current_url_cleaned}' ignorée par robots.txt.")
                self._stats['urls_skipped_robots'] += 1                               
                continue # Passe à l'URL suivante dans la queue       
            
            self.visited_urls_hash.add(url_hash)                                  
            self._stats['urls_visited'] += 1                                      
            self._stats['current_url'] = current_url_cleaned
            self._stats['last_status'] = f"Exploring: {current_url_cleaned}. Queue size: {len(self.urls_to_visit)}"                                                   
            self._LOGGER.log_info(f"[WebExplorer] Exploration de l'URL : '{current_url_cleaned}' (Profondeur: {current_depth})")            
            
            try:                                                                      
                self._stats['total_requests_made'] += 1                               
                headers_with_ua = self.headers.copy()                                 
                headers_with_ua['User-Agent'] = self._get_next_user_agent()                                                                 
                response = self.session.get(current_url_cleaned, headers=headers_with_ua, timeout=self.request_timeout, allow_redirects=True)
                response.raise_for_status()                           
                
                self._stats['requests_successful'] += 1                               
                content_type = response.headers.get('Content-Type', '').lower()
                self._stats['bytes_downloaded_html'] += len(response.content)                                                               
                
                # --- DÉTECTION DE CIBLES SENSIBLES PAR CHEMIN/NOM DE FICHIER DANS L'URL ---                                                                
                parsed_url_path = urlparse(current_url_cleaned)
                path_segment = unquote(parsed_url_path.path.split('/')[-1])                                                                                 
                full_url_path_normalized = unquote(parsed_url_path.path).rstrip('/') # Normalise pour la détection de chemins                               
                if not full_url_path_normalized.startswith('/'): full_url_path_normalized = '/' + full_url_path_normalized                  
                                                                                      
                sensitive_match_segment = self._is_sensitive_path_or_name(path_segment)
                sensitive_match_full_path = self._is_sensitive_path_or_name(full_url_path_normalized)                                                       
                api_match = self._is_api_endpoint(full_url_path_normalized)                                                                                 
                vuln_match = self._is_vulnerable_path(full_url_path_normalized)                                                             
                
                if sensitive_match_segment or sensitive_match_full_path or api_match or vuln_match:                                                             
                    match_reason = sensitive_match_segment or sensitive_match_full_path or api_match or vuln_match                                              
                    target_type = self.TARGET_TYPE_FILE if '.' in path_segment else self.TARGET_TYPE_DIRECTORY
                    if api_match: target_type = self.TARGET_TYPE_API                      
                    if vuln_match: target_type = self.TARGET_TYPE_VULN
                    
                    self.found_targets.append({                                               
                        'path': parsed_url_path.path,                                         
                        'full_path': current_url_cleaned,
                        'type': target_type,                                                  
                        'sensitive_match': match_reason,                                      
                        'source': 'URL Path/Name',
                        'content_type': content_type.split(';')[0].strip()                                                                                      
                    })
                    if target_type == self.TARGET_TYPE_FILE: self._stats['files_identified'] += 1                                                               
                    elif target_type == self.TARGET_TYPE_DIRECTORY: self._stats['dirs_identified'] += 1                                                         
                    elif target_type == self.TARGET_TYPE_API: self._stats['api_endpoints_identified'] += 1
                    elif target_type == self.TARGET_TYPE_VULN: self._stats['vuln_paths_identified'] += 1                                                        
                    self._LOGGER.log_warning(f"[WebExplorer] Cible sensible (URL/Chemin) trouvée: {current_url_cleaned} (Match: {match_reason})")
                                                                      
                # --- DÉTECTION DE CIBLES SENSIBLES DANS LE CONTENU HTML/JSON/XML/JS ---                                                                
                if any(ct_allowed in content_type for ct_allowed in ['text/html', 'application/json', 'application/xml', 'text/plain', 'application/javascript']):                                                                    
                    content_text = response.text
                    sensitive_content_matches = self._is_sensitive_content(content_text)                                                                        
                    if sensitive_content_matches:
                        for pattern, matched_value in sensitive_content_matches:                                                                                        
                            display_value = matched_value if len(matched_value) < 100 else f"{matched_value[:97]}..."                                                   
                            self.found_targets.append({                                               
                                'path': parsed_url_path.path, # Chemin de la page où le script est trouvé                                                                   
                                'full_path': current_url_cleaned,                                     
                                'type': self.TARGET_TYPE_CONTENT,                                     
                                'sensitive_match': f"Content-Regex: {pattern} (Value: {display_value})",                                                                    
                                'source': 'Page Content',                                             
                                'content_type': content_type.split(';')[0].strip()                                                                                      
                            })
                            self._stats['content_matches'] += 1                                   
                            self._LOGGER.log_warning(f"[WebExplorer] Contenu sensible trouvé dans '{current_url_cleaned}': (Match: {pattern}, Valeur: {display_value})")
                                                                                                                                                            
                # --- PARSING ET QUEUE DES LIENS POUR EXPLORATION RÉCURSIVE ET DÉTECTION DE FICHIERS TÉLÉCHARGEABLES ---                                                                             
                if any(ct_allowed in content_type for ct_allowed in self.allowed_content_types_for_recursion) or 'text/plain' in content_type: # Ajout text/plain pour les sitemaps et autres
                    # Si le Content-Type est text/plain, il peut s'agir d'un robots.txt ou sitemap.xml non-XML validé par le serveur
                    if 'text/plain' in content_type and (parsed_url_path.path.endswith('/robots.txt') or parsed_url_path.path.endswith('/sitemap.xml')):
                        self._LOGGER.log_info(f"[WebExplorer] Traitement d'un fichier text/plain potentiellement de sitemap/robots: {current_url_cleaned}")
                        if 'sitemap.xml' in parsed_url_path.path:
                            self._extract_urls_from_sitemap(current_url_cleaned) # Tente de traiter comme sitemap

                    soup = BeautifulSoup(content_text, 'html.parser') 
                    all_links_found = set()                                               
                    # Liens dans les balises HTML classiques
                    for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe', 'source', 'video', 'audio']):                                         
                        href = tag.get('href') or tag.get('src') or tag.get('action')
                        if href:                                                                  
                            all_links_found.add(href)                 
                    # Liens et informations dans les commentaires HTML
                    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                        # Regex plus ouverte pour capturer URLs, emails, etc. dans les commentaires                                                                 
                        found_data_in_comment = re.findall(r'(?:http[s]?://|www\.)[^\s<>"]+|[^\s<>"]+@(?:[^\s<>"]+)\.(?:[a-zA-Z]{2,6})\b|[^\s<>"\'`]+\.(?:php|html|js|css|zip|sql|txt|log|env|bak|conf|yml|yaml)\b', str(comment))
                        for item_data in found_data_in_comment:                                   
                            all_links_found.add(item_data)                                        
                            # On pourrait aussi analyser ce contenu pour des sensitive_content_matches ici.                                                                                                                           
                    # Extraction statique d'URLs et de patterns dans les scripts JavaScript intégrés
                    for script_tag in soup.find_all('script'):                                
                        if script_tag.string:
                            js_content = script_tag.string                                        
                            # Cherche des URLs complètes ou chemins absolus/relatifs pertinents dans JS
                            # Assure-toi que cette regex est aussi dans sensitive_regex_patterns si tu veux des 'files'                                                 
                            found_urls_in_js = re.findall(r'(?:http[s]?://|www\.|/)(?:[a-zA-Z0-9.\/_@-]+)(?:\.js|\.php|\.html|\.json|\.xml|\.txt|\.log|\.sql|\.zip|\.env|\bapi\b|\badmin\b|\btest\b)', js_content)                            
                            for u in found_urls_in_js:
                                all_links_found.add(u)                                            
                            # Cherche des patterns sensibles dans le JS lui-même
                            sensitive_js_content_matches = self._is_sensitive_content(js_content)                                                                       
                            if sensitive_js_content_matches:
                                for pattern, matched_value in sensitive_js_content_matches:                                                                                     
                                    display_value = matched_value if len(matched_value) < 100 else f"{matched_value[:97]}..."                                                   
                                    self.found_targets.append({                                               
                                        'path': parsed_url_path.path, # Chemin de la page où le script est trouvé                                                                   
                                        'full_path': current_url_cleaned,
                                        'type': self.TARGET_TYPE_CONTENT,                                                                                                           
                                        'sensitive_match': f"JS-Content-Regex: {pattern} (Value: {display_value})",
                                        'source': 'JavaScript Content',
                                        'content_type': 'application/javascript'
                                    })                                                                    
                                    self._stats['content_matches'] += 1
                                    self._LOGGER.log_warning(f"[WebExplorer] Contenu JS sensible trouvé dans '{current_url_cleaned}': (Match: {pattern}, Valeur: {display_value})")
                                                                                          
                    # Détection et extraction des données de formulaire                                                                                         
                    for form_tag in soup.find_all('form'):                                    
                        form_action = form_tag.get('action')                                  
                        form_method = form_tag.get('method', 'get').lower()                                                                                         
                        form_inputs = {}                                                      
                        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                            input_name = input_tag.get('name')                                    
                            input_value = input_tag.get('value', '')
                            input_type = input_tag.get('type', 'text')                            
                            if input_name:
                                form_inputs[input_name] = input_value 
                        form_full_url = urljoin(current_url_cleaned, form_action)
                        if form_full_url not in self.visited_urls_hash: # Éviter de lister les mêmes formulaires plusieurs fois
                            self.found_targets.append({                                               
                                'path': urlparse(form_full_url).path,
                                'full_path': form_full_url,                                           
                                'type': self.TARGET_TYPE_FORM,
                                'sensitive_match': f"Form: {form_method.upper()} to {urlparse(form_full_url).path}",
                                'source': 'Discovered Form',                                          
                                'content_type': 'application/x-www-form-urlencoded',
                                'method': form_method,                                                
                                'inputs': form_inputs # Peut être utile pour l'analyse                                                                                  
                            })
                            self._stats['forms_identified'] += 1                                  
                            self._LOGGER.log_info(f"[WebExplorer] Formulaire découvert: {form_method.upper()} {form_full_url} (Inputs: {list(form_inputs.keys())})")                                                                          
                        # Si le formulaire est GET, on peut l'ajouter à la queue d'exploration.                                                                     
                        if form_method == 'get':
                            self._queue_url_for_exploration(form_full_url + '?' + '&'.join(f"{k}={v}" for k,v in form_inputs.items()), current_depth)
                        else: # Pour POST, on ne peut pas l'explorer récursivement de manière passive                                                                   
                            self._log_debug(f"Formulaire POST/autre méthode ignoré pour l'exploration récursive: {form_full_url}")      

                    # Ajout de chemins communs pour la "tête chercheuse" (WordPress, CMS, etc.)                                                                 
                    # Cette section est surtout pertinente pour la profondeur 0 et devrait être gérée intelligemment                                            
                    if current_depth == 0:                                                    
                        self._LOGGER.log_debug("[WebExplorer] Ajout de chemins WordPress/CMS par défaut pour la découverte initiale.")                              
                        current_year = datetime.now().year                                    
                        for year_offset in range(-2, 3):
                            year = current_year + year_offset                                     
                            for month in range(1, 13):                                                
                                all_links_found.add(f"/wp-content/uploads/{year}/{month:02}/")                                                                      
                        all_links_found.update([                                                  
                            "/wp-config.php", "/wp-config.php.bak", "/.env", "/.env.example",                                                                           
                            "/backup.zip", "/database.sql", "/db_backup/", "/wp-admin/admin-ajax.php",
                            "/wp-content/backups/", "/wp-content/cache/", "/wp-content/debug.log",
                            "/admin/", "/phpmyadmin/", "/.git/config", "/.svn/entries",                                                                                 
                            "/config.php", "/settings.php", "/configuration.php",                                                                                       
                            "/includes/config.php", "/etc/passwd",                                
                            "/vendor/composer/installed.json",
                            "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",                                                                                        
                            "/server-status",
                            "/info.php", "/test.php",                                             
                            "/README.md", "/LICENSE",
                            "/wp-content/plugins/", "/wp-content/themes/",
                            "/wp-login.php", "/admin/login.php", "/login.php",                                                                                          
                            "/api/", "/graphql/", "/rest/",
                            "/vendor/",                                                           
                            "/favicon.ico", "/crossdomain.xml", # Fichiers de politique
                            "/admin/config.php", # Chemin de config admin                                                                                               
                            "/includes/db.php", # Chemins de base de données                                                                                            
                            "/application/config/database.php", # Laravel/CodeIgniter DB config
                        ])                                                                                                                                          
                        # Vérifier le sitemap si existe et explorer ses URLs.
                        for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.php"]:                                                                     
                            sitemap_full_url = urljoin(self._get_base_url_from_full_url(current_url_cleaned), sitemap_path)
                            if self._get_base_url_from_full_url(sitemap_full_url) == self.initial_domain:
                                self._LOGGER.log_info(f"[WebExplorer] Tente de traiter le sitemap : {sitemap_full_url}")                                                    
                                self._extract_urls_from_sitemap(sitemap_full_url)                                                                                                                                                                                                                           
                    for href in all_links_found:                                              
                        # Assure que le lien est bien une URL complète et propre
                        absolute_url = urljoin(current_url_cleaned, href).split('#')[0].rstrip('/')                                                                                                                                       
                        # Détecter si c'est un fichier téléchargeable par son extension
                        parsed_href_path = urlparse(absolute_url).path
                        file_extension = os.path.splitext(parsed_href_path)[1].lower()

                        if file_extension in self.DOWNLOADABLE_FILE_EXTENSIONS:
                            # Ne pas le mettre en queue pour récursion, mais l'ajouter comme cible de fichier
                            if self._hash_url(absolute_url) not in self.visited_urls_hash: # Éviter les doublons
                                self.found_targets.append({
                                    'path': parsed_href_path,
                                    'full_path': absolute_url,
                                    'type': self.TARGET_TYPE_FILE,
                                    'sensitive_match': f"File Extension: {file_extension}",
                                    'source': 'Discovered Link',
                                    'content_type': mimetypes.guess_type(absolute_url)[0] or 'application/octet-stream'
                                })
                                self._stats['files_identified'] += 1
                                self._LOGGER.log_info(f"[WebExplorer] Fichier identifiable trouvé: {absolute_url}")
                                self.visited_urls_hash.add(self._hash_url(absolute_url)) # Marquer comme visité pour ne pas le retraiter inutilement

                        # Ajouter à la queue d'exploration seulement si ce n'est pas un fichier (pour ne pas explorer les fichiers comme des pages)
                        # et si la profondeur le permet.
                        if file_extension not in self.DOWNLOADABLE_FILE_EXTENSIONS: # Correction ici: on ne met en queue que les URLs qui NE SONT PAS des fichiers téléchargeables.
                            self._queue_url_for_exploration(absolute_url, current_depth)
                        else: # Si c'est un fichier (potentiellement téléchargeable), on le loggue juste comme debug s'il est ignoré pour récursion.
                            self._log_debug(f"Lien ignoré pour la récursion (fichier téléchargeable) : {absolute_url}")
                                                                                              
                        # Pause entre les requêtes pour ne pas surcharger le serveur
                        time.sleep(self.delay_between_requests)                                                                                             
                else: # Si le contenu n'est pas HTML, mais a été parsé pour du contenu sensible                                                                 
                    self._log_debug(f"Type de contenu non HTML/JS pour '{current_url_cleaned}': {content_type}. Pas de parsing de liens pour récursion.")
                                                                                  
            except requests.exceptions.RequestException as e:                         
                self._stats['requests_failed'] += 1
                if isinstance(e, requests.exceptions.Timeout):                            
                    self._LOGGER.log_error(f"[WebExplorer] Timeout lors de l'exploration de '{current_url_cleaned}': {e}")                                  
                elif isinstance(e, requests.exceptions.HTTPError):                        
                    self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP pour '{current_url_cleaned}': {e} (Statut: {e.response.status_code})")                                                                                     
                elif "Connection refused" in str(e) :                                     
                    self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP/réseau pour '{current_url_cleaned}': Connexion refusée. Vérifiez que la cible est accessible et qu'un service est en écoute sur le port.")                 
                else:                                                                     
                    self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP/réseau pour '{current_url_cleaned}': {e}")                                       
            except Exception as e:                                                    
                self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors de l'exploration de '{current_url_cleaned}': {e}", exc_info=self.debug_mode)                                                                                                                                          
            # Mise à jour du statut en cours (pour l'UI Dash)                     
            self._stats['last_status'] = f"Explored: {current_url_cleaned}. Queue size: {len(self.urls_to_visit)}"                                                                                                        
        
        self._stats['end_time'] = datetime.now()                              
        self._stats['duration_seconds'] = (self._stats['end_time'] - (self._stats['start_time'] or datetime.now())).total_seconds()                 
        self._stats['last_status'] = f"Exploration terminée. Cibles trouvées: {len(self.found_targets)}. Requêtes: {self._stats['total_requests_made']}."                                                                 
        self._LOGGER.log_info(f"[WebExplorer] Exploration web terminée. {len(self.found_targets)} cibles sensibles trouvées sur {self._stats['urls_visited']} URLs visitées en {self._stats['duration_seconds']:.2f} secondes.")                                                                                                                                                                                                        
    def read_file_content_from_url(self, target_url: str, max_bytes: int = 10240) -> str:                                                           
        self._LOGGER.log_debug(f"[WebExplorer] Lecture du contenu de l'URL : {target_url}")                                                         
        if not target_url.startswith('http://') and not target_url.startswith('https://'):                                                              
            self._LOGGER.log_warning(f"[WebExplorer] Schéma manquant lors de la lecture, ajout de 'http://' à {target_url}")                            
            target_url = "http://" + target_url
                                                                              
        try:                                                                      
            self._stats['total_requests_made'] += 1                               
            headers_with_ua = self.headers.copy()                                 
            headers_with_ua['User-Agent'] = self._get_next_user_agent()                                                                                                                                                       
            response = self.session.get(target_url, headers=headers_with_ua, stream=True, timeout=self.request_timeout)                                 
            response.raise_for_status()                                           
            self._stats['requests_successful'] += 1                                                                                                     
            content_bytes = b''                                                   
            for chunk in response.iter_content(chunk_size=1024):                      
                content_bytes += chunk                                                
                if len(content_bytes) >= max_bytes:                                       
                    content_bytes = content_bytes[:max_bytes]                             
                    break                                                         
            self._stats['bytes_downloaded_files'] += len(content_bytes)                                                                                                                                                       
            try:                                                                      
                decoded_content = content_bytes.decode('utf-8')                   
            except UnicodeDecodeError:                                                
                self._log_debug(f"Échec décodage UTF-8 pour {target_url}, tentative avec latin-1.")                                                         
                decoded_content = content_bytes.decode('latin-1', errors='replace')                                                                                                                                                                                                                 
            if len(content_bytes) == max_bytes and 'Content-Length' in response.headers and int(response.headers['Content-Length']) > max_bytes:                                                                                  
                decoded_content += "\n[... Contenu tronqué, télécharger le fichier complet pour voir la suite ...]"                                                                                                           
            return decoded_content                                            
        except requests.exceptions.RequestException as e:                         
            self._stats['requests_failed'] += 1                                   
            self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP/réseau lors de la lecture du contenu de {target_url}: {e}")                              
            return f"[ERROR] Network/HTTP error reading URL content: {e}"                                                                           
        except Exception as e:                                                    
            self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors de la lecture du contenu de {target_url}: {e}", exc_info=self.debug_mode)
            return f"[ERROR] Unexpected error reading URL content: {e}"                                                                                                                                               
    def download_file_base64_from_url(self, target_url: str) -> str:          
        self._LOGGER.log_debug(f"[WebExplorer] Téléchargement de (Base64) : {target_url}")                                                          
        if not target_url.startswith('http://') and not target_url.startswith('https://'):                                                              
            self._LOGGER.log_warning(f"[WebExplorer] Schéma manquant lors du téléchargement, ajout de 'http://' à {target_url}")                        
            target_url = "http://" + target_url                                                                                                     
        try:                                                                      
            self._stats['total_requests_made'] += 1                               
            headers_with_ua = self.headers.copy()                                 
            headers_with_ua['User-Agent'] = self._get_next_user_agent()                                                                                                                                                       
            response = self.session.get(target_url, headers=headers_with_ua, timeout=60) # Augmenté le timeout pour le téléchargement                   
            response.raise_for_status()                                           
            self._stats['requests_successful'] += 1                               
            self._stats['bytes_downloaded_files'] += len(response.content)                                                                                                                                                    
            file_content = response.content                                       
            return base64.b64encode(file_content).decode('utf-8')             
        except requests.exceptions.RequestException as e:                         
            self._stats['requests_failed'] += 1                                   
            self._LOGGER.log_error(f"[WebExplorer] Erreur HTTP/réseau lors du téléchargement de {target_url}: {e}")                                     
            return f"[ERROR] Network/HTTP error downloading URL: {e}"         
        except Exception as e:                                                    
            self._LOGGER.log_error(f"[WebExplorer] Erreur inattendue lors du téléchargement de {target_url}: {e}", exc_info=self.debug_mode)
            return f"[ERROR] Unexpected error downloading URL: {e}"                                                                             
    def get_found_targets(self) -> List[Dict[str, Any]]:                      
        return self.found_targets                                                                                                               
    def get_exploration_stats(self) -> Dict[str, Any]:                        
        """Retourne les statistiques actuelles de l'exploration."""           
        return self._stats                                                                                                                      
    def reset_state(self):                                                    
        self.found_targets = []                                               
        self.visited_urls_hash = set()                                        
        self.initial_domain = None                                            
        self.urls_to_visit = collections.deque()                              
        self.robots_disallow_paths = {}                                       
        # Réinitialise les stats                                              
        self._stats = {                                                           
            'urls_visited': 0, 'urls_queued': 0, 'urls_skipped_external': 0, 'urls_skipped_visited': 0, 'urls_skipped_robots': 0,                       
            'files_identified': 0, 'dirs_identified': 0, 'content_matches': 0,                                                                          
            'api_endpoints_identified': 0, 'vuln_paths_identified': 0, 'sitemap_entries_identified': 0,                                                 
            'forms_identified': 0, 'requests_successful': 0, 'requests_failed': 0, 'total_requests_made': 0,                                            
            'bytes_downloaded_html': 0, 'bytes_downloaded_files': 0,              
            'last_status': 'Idle', 'current_url': 'N/A',                          
            'start_time': None, 'end_time': None, 'duration_seconds': 0                                                                             
        }                                                                     
        self._LOGGER.log_info("[WebExplorer] État réinitialisé.")                                                                                                                                                 
# --- Bloc de test (mise à jour pour tester les nouvelles fonctionnalités) ---                                                              
if __name__ == "__main__":                                                
    print("[+] Test du module WebExplorer (mode autonome)...")            
    try:                                                                      
        from modules.logger import Logger as AgentLoggerTest
        _LOGGER = AgentLoggerTest(None, None, debug_mode=True, stdout_enabled=True)                                                                 
        print("[INFO] AgentLogger utilisé pour les tests autonomes de WebExplorer.")                                                            
    except ImportError:                                                       
        _LOGGER = FallbackMockLogger()
        print("[WARNING] AgentLogger non disponible. FallbackMockLogger utilisé pour les tests autonomes de WebExplorer.")                  
    
    explorer = WebExplorer(debug_mode=True)                                                                                                     
    # Test 1: Exploration d'une URL simple et analyse des résultats (ex: example.com)                                                           
    print("\n--- Test 1: Exploration d'une URL simple (https://example.com) ---")
    test_site_url = "https://example.com"                                 
    print(f"Exploration de : {test_site_url}")                            
    explorer.explore_url(test_site_url, max_depth=1) # Utilisation de explore_url directement ici pour le test unitaire                         
    targets = explorer.get_found_targets()                                
    stats = explorer.get_exploration_stats()
    print(f"Cibles sensibles trouvées : {json.dumps(targets, indent=2)}")                                                                       
    print(f"Statistiques d'exploration: {json.dumps(stats, indent=2)}")                                                                         
    explorer.reset_state()                                                
    print("-" * 40)                                                                                                                             
    # Test 2: Exploration d'une URL qui devrait trouver des contenus sensibles (simulée)                                                        
    print("\n--- Test 2: Exploration d'une URL avec contenu / chemins sensibles (simulé) ---")                                                  
    class MockResponse:
        def __init__(self, content_data, status_code=200, headers=None, url="https://mock.example.com/"):                                               
            self._data = content_data                                             
            self.status_code = status_code                                        
            self.headers = headers or {'Content-Type': 'text/html'}               
            self.url = url
            # Pour simuler Content-Length si nécessaire pour la lecture tronquée
            if 'Content-Length' not in self.headers and isinstance(content_data, (str, bytes)):
                self.headers['Content-Length'] = str(len(content_data) if isinstance(content_data, bytes) else len(content_data.encode('utf-8')))

        @property                                                             
        def text(self): 
            if isinstance(self._data, bytes): return self._data.decode('utf-8', errors='ignore')
            return self._data                                     
        @property
        def content(self): 
            if isinstance(self._data, bytes): return self._data
            return self._data.encode('utf-8')                  
        
        def iter_content(self, chunk_size):
            # Simule le streaming d'un fichier binaire ou texte
            data = self.content
            for i in range(0, len(data), chunk_size):
                yield data[i:i + chunk_size]

        def raise_for_status(self):                                               
            if self.status_code >= 400: raise requests.exceptions.HTTPError(f"HTTP Error: {self.status_code}")                                                                                                        
    original_session_get = requests.Session.get
    def mock_session_get_complex_test(self, url, *args, **kwargs):            
        clean_url = url.split('#')[0].rstrip('/')
        if "mock.example.com/test_content" in clean_url:                          
            mock_html = """                                                       
            <html><body><h1>Welcome</h1>                                          
            <p>Database password: my_super_secret_db_pass</p>
            <a href="/private/users/credentials.json">User Credentials</a>                                                                              
            <script>var secretToken = "mySuperSecretJSKey_xyz123";</script>                                                                             
            <form action="/login" method="post"><input type="text" name="username"><input type="password" name="password"></form>                       
            <a href="/api/v1/users">API Users</a>                                 
            <a href="/wp-admin/">WordPress Admin Panel</a>                        
            <a href="/downloads/report.pdf">Download Report PDF</a>
            <a href="/uploads/image.png">Image File</a>
            <a href="/archive/important.zip">Important Archive</a>
            </body></html>                                                        
            """                                                                   
            return MockResponse(mock_html, url="https://mock.example.com/test_content.html")                                                        
        elif "private/users/credentials.json" in clean_url:
            return MockResponse('{"user":"admin","password":"dev_password"}', headers={'Content-Type': 'application/json'}, url=url)
        elif "robots.txt" in clean_url:                                           
            return MockResponse("User-agent: *\nDisallow: /admin/\nDisallow: /private/", url=url, headers={'Content-Type': 'text/plain'})
        elif "sitemap.xml" in clean_url:                                          
            return MockResponse("<urlset><url><loc>https://mock.example.com/sitemap_page1.html</loc></url><url><loc>https://mock.example.com/downloads/doc.zip</loc></url><url><loc>https://mock.example.com/private/excluded.html</loc></url></urlset>", headers={'Content-Type': 'application/xml'}, url=url)                                                 
        elif "sitemap_page1.html" in clean_url:
            return MockResponse("<html><body>Sitemap Page Content</body></html>", url=url)                                                          
        elif "/login" in clean_url and "method=post" not in clean_url.lower():                                                                           
            return MockResponse("Login page", url=url)
        elif "/downloads/report.pdf" in clean_url: # Simulate a downloadable file
            return MockResponse(b"FAKE_PDF_CONTENT_BINARY_FOR_DOWNLOAD", url=url, headers={'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="report.pdf"'})
        elif "/uploads/image.png" in clean_url: # Simulate a downloadable file
            return MockResponse(b"FAKE_PNG_CONTENT_BINARY_FOR_DOWNLOAD", url=url, headers={'Content-Type': 'image/png'})
        elif "/archive/important.zip" in clean_url: # Simulate a downloadable file
            return MockResponse(b"FAKE_ZIP_CONTENT_BINARY_FOR_DOWNLOAD", url=url, headers={'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="important.zip"'})
        elif "/downloads/doc.zip" in clean_url: # Simulate a downloadable file from sitemap
            return MockResponse(b"FAKE_SITEMAP_ZIP_CONTENT_BINARY_FOR_DOWNLOAD", url=url, headers={'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="doc.zip"'})


        return original_session_get(self, url, *args, **kwargs)                                                                                 
    requests.Session.get = mock_session_get_complex_test                                                                                        
    test_sensitive_content_url = "https://mock.example.com/test_content.html"
    print(f"Exploration de : {test_sensitive_content_url}")
    explorer.explore_url(test_sensitive_content_url, max_depth=2) # Utilisation de explore_url ici
    targets = explorer.get_found_targets()                                
    stats = explorer.get_exploration_stats()                              
    print(f"\nCibles sensibles trouvées (devrait inclure contenu, API, vuln et liens) : {json.dumps(targets, indent=2)}")                       
    print(f"Statistiques d'exploration: {json.dumps(stats, indent=2)}")                                                                         
    explorer.reset_state()
                                                                          
    requests.Session.get = original_session_get
    print("-" * 40)                                                                                                                             
    # Test 3: Lecture de contenu depuis une URL (ex: example.com)         
    print("\n--- Test 3: Lecture de contenu depuis une URL (https://example.com) ---")                                                          
    content = explorer.read_file_content_from_url("https://example.com", max_bytes=500)                                                         
    print("Contenu de la page (premiers 200 octets):")                    
    print(content[:200] + "..." if len(content) > 200 else content)
    print("-" * 40)                                                                                                                             
    # Test 4: Téléchargement Base64 depuis une URL                        
    print("\n--- Test 4: Téléchargement Base64 depuis une URL (https://example.com) ---")                                                       
    try:                                                                      
        mock_file_content_binary = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x00IEND\xaeB`\x82" # Petit PNG                                      
        original_get_tmp = requests.Session.get                               
        requests.Session.get = lambda self, url, *args, **kwargs: MockResponse(mock_file_content_binary, url=url, headers={'Content-Type': 'image/png'})                                                                                                                      
        data_b64 = explorer.download_file_base64_from_url("https://mock.example.com/test_download.png")                                             
        print(f"Contenu Base64 (début): {data_b64[:50]}..." if data_b64 else "Échec du téléchargement Base64.")                                     
        requests.Session.get = original_get_tmp # Revert patch        
    except Exception as e:                                                    
        print(f"Erreur lors du test de téléchargement Base64: {e}")       
    print("-" * 40)
                                                                          
    print("[+] Tous les tests de WebExplorer terminés.")

