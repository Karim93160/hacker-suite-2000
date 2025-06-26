import os
import sys
import time
import platform
import subprocess # Nouveau: pour exécuter des commandes système
import json
import re

class EvasionDetector:
    """
    Détecte la présence de débogueurs, de machines virtuelles, de conteneurs,
    et d'autres environnements d'analyse pour entraver l'exécution de l'agent.
    Implémentation sans psutil.
    """

    def __init__(self, logger=None):
        self.logger = logger
        self.evasion_detections = []

        if self.logger:
            self.logger.log_debug("[EvasionDetector] Initialisé (sans psutil).")

    def _log(self, level, message):
        if self.logger:
            getattr(self.logger, f"log_{level}")(f"[EvasionDetector] {message}")
        else:
            print(f"[{level.upper()}] [EvasionDetector] {message}")

    def _run_command(self, command: list, timeout: int = 3) -> str:
        """Exécute une commande shell et retourne sa sortie standard."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            self._log("debug", f"Commande '{' '.join(command)}' a retourné une erreur: {e.stderr.strip()}")
            return ""
        except subprocess.TimeoutExpired:
            self._log("debug", f"Commande '{' '.join(command)}' a dépassé le délai.")
            return ""
        except FileNotFoundError:
            self._log("debug", f"Commande '{command[0]}' non trouvée.")
            return ""
        except Exception as e:
            self._log("error", f"Erreur inattendue lors de l'exécution de commande '{' '.join(command)}': {e}")
            return ""

    def _add_detection(self, technique: str, description: str, severity: str = "medium"):
        detection = {
            "technique": technique,
            "description": description,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }
        self.evasion_detections.append(detection)
        self._log("warning", f"Détection d'évasion: {technique} - {description}")

    # --- Techniques de détection génériques/multiplateformes ---

    def _check_process_parent(self):
        """
        Vérifie si le processus parent est suspect.
        Sans psutil, cela devient plus difficile de manière portable.
        On peut se baser sur l'analyse de /proc/<pid>/status sur Linux.
        """
        if platform.system() != "Linux" and platform.system() != "Android":
            self._log("debug", "Vérification du processus parent non implémentée pour ce système sans psutil.")
            return
        
        try:
            # Lire le PID du processus parent depuis /proc/self/status
            pid = os.getpid()
            parent_pid = 0
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        parent_pid = int(line.split(":")[1].strip())
                        break
            
            if parent_pid == 0:
                self._log("debug", "Impossible de déterminer le PID parent.")
                return

            # Maintenant, essayez de déterminer le nom/cmdline du parent via /proc/<ppid>/cmdline
            parent_cmdline = self._run_command(["cat", f"/proc/{parent_pid}/cmdline"])
            parent_name = parent_cmdline.split('\x00')[0] if '\x00' in parent_cmdline else parent_cmdline

            if parent_name:
                parent_name = parent_name.lower()
                parent_cmdline_lower = parent_cmdline.lower()

                suspicious_parents = ["gdb", "strace", "ltrace", "valgrind", "wireshark", "ida", "x64dbg", "python"]
                # Inclure "python" peut causer des faux positifs si l'agent est juste lancé via python.
                # Mais dans un contexte de sandbox, un python qui lance un autre python pourrait être un indicateur.
                
                if any(sp in parent_name for sp in suspicious_parents) or                    any(sp in parent_cmdline_lower for sp in suspicious_parents):
                    self._add_detection("Parent Process", f"Processus parent suspect détecté: {parent_name} ({parent_cmdline})", "high")
                else:
                    self._log("debug", f"Processus parent non suspect: {parent_name} ({parent_cmdline})")
            else:
                self._log("debug", f"Nom de processus parent non déterminé pour PID {parent_pid}.")

        except FileNotFoundError:
            self._log("warning", "Impossible de lire /proc/<pid>/status ou /proc/<pid>/cmdline pour la vérification du parent.")
        except Exception as e:
            self._log("error", f"Erreur lors de la vérification du processus parent: {e}")

    def _check_running_processes(self):
        """
        Vérifie la présence de processus d'analyse/monitoring courants en parsant la sortie de 'ps'.
        """
        suspicious_processes = [
            "wireshark", "procmon", "x64dbg", "idaq", "ollydbg", "gdb", "strace",
            "tcpdump", "netstat", "autoruns", "sandboxie", "vboxservice", "vmtoolsd",
            "qemu-ga", "fiddler", "burpsuite", "charles", "monitor", "analyzer"
        ]
        
        ps_output = self._run_command(["ps", "-e", "-o", "comm,args"]) # Obtenir nom et args
        if not ps_output:
            self._log("warning", "Impossible d'obtenir la liste des processus en cours via 'ps'.")
            return

        found = False
        for line in ps_output.splitlines():
            line_lower = line.lower()
            if any(s_proc in line_lower for s_proc in suspicious_processes):
                self._add_detection("Running Processes", f"Processus suspect détecté: {line}", "medium")
                found = True
        if not found:
            self._log("debug", "Aucun processus d'analyse suspect détecté.")

    def _check_system_uptime(self):
        """
        Vérifie le temps de fonctionnement du système en lisant /proc/uptime.
        """
        if platform.system() != "Linux" and platform.system() != "Android":
            self._log("debug", "Vérification de l'uptime non implémentée pour ce système sans psutil.")
            return

        try:
            uptime_content = self._run_command(["cat", "/proc/uptime"])
            if uptime_content:
                uptime_seconds = float(uptime_content.split()[0])
                uptime_minutes = uptime_seconds / 60
                if uptime_minutes < 5: # Moins de 5 minutes
                    self._add_detection("System Uptime", f"Temps de fonctionnement du système très court: {uptime_minutes:.1f} minutes.", "medium")
                else:
                    self._log("debug", f"Temps de fonctionnement du système: {uptime_minutes:.1f} minutes.")
        except FileNotFoundError:
            self._log("warning", "/proc/uptime non trouvé. Impossible de vérifier l'uptime.")
        except Exception as e:
            self._log("error", f"Erreur lors de la vérification de l'uptime: {e}")

    def _check_disk_space_ratio(self):
        """
        Vérifie le ratio d'espace disque libre en utilisant 'df -P'.
        """
        try:
            df_output = self._run_command(["df", "-P", "/"]) # Vérifier la partition racine
            lines = df_output.splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 5:
                    total_kb = int(parts[1])
                    percent_used = int(parts[4].replace('%', ''))
                    
                    total_gb = round(total_kb / (1024**2), 2)
                    free_percent = 100 - percent_used

                    if total_gb < 20 and free_percent > 80: # Moins de 20GB total et plus de 80% libre
                        self._add_detection("Disk Space", f"Faible espace disque total ({total_gb} GB) "
                                            f"avec un pourcentage libre élevé ({free_percent:.1f}%).", "low")
                    else:
                        self._log("debug", f"Espace disque: Total={total_gb} GB, Libre={free_percent:.1f}%.")
                else:
                    self._log("warning", f"Format de sortie 'df -P' inattendu: {lines[1]}")
            else:
                self._log("warning", "Impossible d'obtenir les informations d'espace disque via 'df -P'.")
        except Exception as e:
            self._log("error", f"Erreur lors de la vérification de l'espace disque: {e}")

    def _check_environment_variables(self):
        """
        Vérifie la présence de variables d'environnement spécifiques aux sandboxes ou outils d'analyse.
        """
        suspicious_env_vars = [
            "VBOX_RUNNING_FROM_VM", 
            "PYCHARM_RUNNING", 
            "DEBUGPY_PROCESS",
            "PYTHONDEBUG",
            "TERMUX_API_VERSION" # Peut être un indicateur si l'agent ne devrait pas être sur Termux
                                 # Mais pour nous, c'est une cible valide, donc non suspect.
        ]
        
        found = False
        for var in suspicious_env_vars:
            if os.getenv(var):
                self._add_detection("Environment Variables", f"Variable d'environnement suspecte détectée: {var}={os.getenv(var)}", "low")
                found = True
        if not found:
            self._log("debug", "Aucune variable d'environnement suspecte détectée.")

    # --- Techniques de détection spécifiques à Linux (et donc Termux) ---

    def _check_ptrace(self):
        """
        Vérifie si le processus est en cours de débogage via ptrace (Linux/Unix)
        en lisant /proc/self/status.
        """
        if platform.system() != "Linux" and platform.system() != "Android":
            return

        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split(":")[1].strip())
                        if tracer_pid != 0:
                            self._add_detection("Ptrace Detection", f"Débogueur ptrace détecté (TracerPID: {tracer_pid}).", "high")
                            return
            self._log("debug", "Aucun TracerPID détecté.")
        except FileNotFoundError:
            self._log("warning", "/proc/self/status non trouvé. Impossible de vérifier ptrace.")
        except Exception as e:
            self._log("error", f"Erreur lors de la vérification ptrace: {e}")

    def _check_vm_files(self):
        """
        Vérifie la présence de fichiers spécifiques aux outils de VM/Conteneurs.
        """
        if platform.system() != "Linux" and platform.system() != "Android":
            return

        vm_artifacts = [
            "/usr/bin/VBoxControl", "/usr/bin/VBoxService",  # VirtualBox
            "/usr/bin/vmware-toolbox-cmd", "/usr/sbin/vmtoolsd", # VMware
            "/etc/vmware-tools/locations",
            "/dev/vboxuser", "/dev/vmware/vmmon", # Périphériques
            "/var/lib/docker", # Docker
            "/run/systemd/container", # systemd pour les conteneurs
        ]
        found = False
        for path in vm_artifacts:
            if os.path.exists(path):
                self._add_detection("VM/Container Artifacts", f"Fichier/répertoire suspect de VM/Conteneur trouvé: {path}", "medium")
                found = True
        if not found:
            self._log("debug", "Aucun artefact VM/Conteneur commun détecté.")
        
        # Vérification cgroup pour les conteneurs (plus robuste)
        try:
            cgroup_content = self._run_command(["cat", "/proc/self/cgroup"])
            if cgroup_content:
                if "docker" in cgroup_content or "lxc" in cgroup_content or re.search(r"/(docker|lxc|kubepods)/", cgroup_content):
                    self._add_detection("Cgroup Check", "Le processus semble s'exécuter dans un conteneur (cgroup).", "medium")
        except FileNotFoundError:
            self._log("warning", "/proc/self/cgroup non trouvé. Impossible de vérifier les conteneurs par cgroup.")
        except Exception as e:
            self._log("error", f"Erreur lors de la vérification cgroup: {e}")


    def _check_cpu_flags_vm(self):
        """
        Vérifie les flags CPU spécifiques aux VM dans /proc/cpuinfo.
        """
        if platform.system() != "Linux" and platform.system() != "Android":
            return

        try:
            cpuinfo_content = self._run_command(["cat", "/proc/cpuinfo"])
            if cpuinfo_content:
                # 'hypervisor' flag est souvent présent dans les VM.
                # L'absence de vmx/svm (flags de virtualisation matérielle) sur une machine moderne
                # peut indiquer une virtualisation (car l'OS hôte ne verrait pas ces flags directement).
                # C'est une heuristique, pas une preuve irréfutable.
                if "hypervisor" in cpuinfo_content or ("vmx" not in cpuinfo_content and "svm" not in cpuinfo_content):
                    self._add_detection("CPU Flags", "Flags CPU suspects (hypervisor ou absence de vmx/svm).", "medium")
                else:
                    self._log("debug", "Flags CPU non suspects pour VM.")
            else:
                self._log("warning", "Impossible de lire /proc/cpuinfo.")
        except Exception as e:
            self._log("error", f"Erreur lors de la vérification des flags CPU: {e}")

    def run_all_checks(self) -> list:
        """
        Exécute toutes les vérifications anti-évasion et retourne les détections.
        """
        self.evasion_detections = [] # Réinitialiser les détections
        self._log("info", "Lancement des vérifications anti-évasion (sans psutil)...")

        self._check_process_parent()
        self._check_running_processes()
        self._check_system_uptime()
        self._check_disk_space_ratio()
        self._check_environment_variables()
        
        if platform.system() in ["Linux", "Android"]: # Les vérifications spécifiques à Linux/Android
            self._check_ptrace()
            self._check_vm_files()
            self._check_cpu_flags_vm()
        
        if not self.evasion_detections:
            self._log("info", "Aucune détection d'évasion majeure. Environnement semble normal.")
        else:
            self._log("warning", f"{len(self.evasion_detections)} détection(s) d'évasion trouvée(s).")
        
        return self.evasion_detections

# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("[+] Test du module EvasionDetector (sans psutil)...")

    class MockLogger:
        def log_info(self, msg): print(f"[INFO] {msg}")
        def log_warning(self, msg): print(f"[WARN] {msg}")
        def log_error(self, msg): print(f"[ERROR] {msg}")
        def log_debug(self, msg): print(f"[DEBUG] {msg}")

    logger = MockLogger()
    detector = EvasionDetector(logger=logger)

    # Exécuter toutes les vérifications
    detections = detector.run_all_checks()

    print("\n--- Résultat des détections d'évasion ---")
    if detections:
        print(json.dumps(detections, indent=4))
        print(f"\n[!] {len(detections)} détection(s) d'évasion trouvée(s).")
    else:
        print("[+] Aucune détection d'évasion. L'environnement semble propre (ou les techniques sont insuffisantes).")

    print("\n--- Simulation de détections pour démonstration ---")
    # Pour simuler une détection ptrace sur Linux sans la lancer avec gdb:
    # Simuler le contenu de /proc/self/status pour le test
    if platform.system() in ["Linux", "Android"]:
        # Créez un fichier temporaire pour simuler /proc/self/status
        temp_status_file = "/tmp/simulated_status_file_for_ptrace_test"
        with open(temp_status_file, "w") as f:
            f.write("Name:\tpython\n")
            f.write("State:\tR (running)\n")
            f.write("TracerPid:\t1234\n") # Simule un débogueur
            f.write("Pid:\t5678\n")
        
        # Remplacez temporairement la fonction open pour rediriger vers notre fichier simulé
        original_open = open
        def mock_open(file, *args, **kwargs):
            if file == "/proc/self/status":
                return original_open(temp_status_file, *args, **kwargs)
            return original_open(file, *args, **kwargs)
        
        # Monkey patch
        import builtins
        builtins.open = mock_open

        # Ré-exécutez la vérification ptrace
        print("\n[*] Simulating ptrace detection...")
        detector = EvasionDetector(logger=logger) # Nouvelle instance pour réinitialiser les détections
        detector._check_ptrace()
        print(json.dumps(detector.evasion_detections, indent=4))

        # Restaurez la fonction open originale
        builtins.open = original_open
        os.remove(temp_status_file)
        print("[+] Simulation ptrace terminée et nettoyage.")

    # Exemple de détection manuelle (sans forcément être vraie)
    print("\n[*] Ajout manuel d'une détection pour l'exemple...")
    detector._add_detection("Manual Test", "Ceci est une détection ajoutée manuellement pour les tests.", "low")
    print(json.dumps(detector.evasion_detections, indent=4))

    print("\n[+] Tests du module EvasionDetector terminés.")
    print("[!] N'oubliez pas que les techniques anti-évasion sont une course à l'armement et ne sont jamais infaillibles.")

