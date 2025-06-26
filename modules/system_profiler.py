import platform
import os
import socket
import json
import time
import subprocess
import re
from datetime import datetime

class SystemProfiler:
    """
    Collecte des informations détaillées sur le système d'exploitation, le réseau,
    le matériel et les processus, en utilisant des modules Python standards
    et des commandes système.
    """

    def __init__(self, logger=None):
        self.logger = logger
        if self.logger:
            self.logger.log_debug("[SystemProfiler] Initialisé.")

    def _log(self, level, message):
        """Méthode interne pour loguer les messages."""
        if self.logger:
            getattr(self.logger, f"log_{level}")(f"[SystemProfiler] {message}")
        else:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level.upper()}] [SystemProfiler] {message}")

    def _run_command(self, command: list, timeout: int = 7) -> str:
        """
        Exécute une commande shell et retourne sa sortie standard.
        Gère les erreurs et les timeouts.
        """
        try:
            self._log("debug", f"Executing command: {' '.join(command)}")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
                encoding='utf-8', # S'assurer d'utiliser UTF-8 pour la sortie
                errors='ignore' # Ignorer les caractères non-décodables
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            self._log("warning", f"Command '{' '.join(command)}' returned error (Exit Code: {e.returncode}): {e.stderr.strip()}")
            return ""
        except subprocess.TimeoutExpired:
            self._log("warning", f"Command '{' '.join(command)}' timed out after {timeout} seconds.")
            return ""
        except FileNotFoundError:
            self._log("warning", f"Command '{command[0]}' not found. Is it installed and in PATH?")
            return ""
        except Exception as e:
            self._log("error", f"Unexpected error while executing command '{' '.join(command)}': {e}")
            return ""

    def _get_hostname(self) -> str:
        """Récupère le nom d'hôte du système."""
        try:
            hostname = socket.gethostname()
            self._log("debug", f"Hostname: {hostname}")
            return hostname
        except Exception as e:
            self._log("error", f"Error getting hostname: {e}")
            return "N/A"

    def _get_os_info(self) -> dict:
        """Collecte les informations du système d'exploitation."""
        os_info = {
            "system": platform.system(),
            "node_name": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "platform_string": platform.platform(), # Renommé pour éviter conflit avec le module platform
            "architecture": platform.architecture()[0],
            "os_name_full": "N/A" # Pour un nom plus "user-friendly"
        }

        # Tentative de récupérer le nom complet de l'OS sur Linux (ex: Ubuntu 22.04 LTS)
        if os_info["system"] == "Linux":
            os_release_content = self._run_command(["cat", "/etc/os-release"])
            if os_release_content:
                for line in os_release_content.splitlines():
                    if line.startswith("PRETTY_NAME="):
                        os_info["os_name_full"] = line.split('=')[1].strip('"')
                        break
            if os_info["os_name_full"] == "N/A":
                # Fallback pour d'autres distributions ou si /etc/os-release est absent
                lsb_release_output = self._run_command(["lsb_release", "-d", "-s"])
                if lsb_release_output:
                    os_info["os_name_full"] = lsb_release_output.strip()

        self._log("debug", f"OS Info: {os_info}")
        return os_info

    def _get_cpu_info(self) -> dict:
        """Collecte les informations du CPU."""
        cpu_info = {
            "model_name": "N/A",
            "logical_cores": "N/A",
            "physical_cores": "N/A",
            "cpu_usage_percent": "N/A" # Nécessite un échantillonnage sur le temps
        }
        try:
            cpuinfo_content = self._run_command(["cat", "/proc/cpuinfo"])
            if cpuinfo_content:
                logical_cores = 0
                physical_ids = set()
                core_ids = set()
                for line in cpuinfo_content.splitlines():
                    if "processor" in line:
                        logical_cores += 1
                    elif "model name" in line and cpu_info["model_name"] == "N/A":
                        cpu_info["model_name"] = line.split(":", 1)[1].strip()
                    elif "physical id" in line:
                        physical_ids.add(line.split(":", 1)[1].strip())
                    elif "core id" in line:
                        core_ids.add(line.split(":", 1)[1].strip())
                
                cpu_info["logical_cores"] = logical_cores
                cpu_info["physical_cores"] = len(physical_ids) if physical_ids else len(core_ids) if core_ids else logical_cores # Meilleure estimation
            
            # Note: Le CPU usage en pourcentage nécessite de mesurer sur une période (e.g., 1 seconde),
            # ce qui est difficile avec une simple commande instantanée comme `cat /proc/stat`.
            # Des outils comme `top` ou `mpstat` sont mieux adaptés mais complexes à parser pour une valeur unique.
            # Pour l'instant, on laisse à N/A ou on pourrait implémenter un mini-échantillonnage si absolument nécessaire.

        except Exception as e:
            self._log("error", f"Error getting CPU info: {e}")
        self._log("debug", f"CPU Info: {cpu_info}")
        return cpu_info

    def _get_memory_info(self) -> dict:
        """Collecte les informations de la mémoire vive."""
        mem_info = {
            "total_gb": "N/A",
            "free_gb": "N/A",
            "available_gb": "N/A",
            "used_percent": "N/A"
        }
        try:
            meminfo_content = self._run_command(["cat", "/proc/meminfo"])
            if meminfo_content:
                total_kb = 0
                free_kb = 0
                available_kb = 0
                for line in meminfo_content.splitlines():
                    if "MemTotal:" in line:
                        total_kb = int(re.search(r'\d+', line).group())
                    elif "MemFree:" in line:
                        free_kb = int(re.search(r'\d+', line).group())
                    elif "MemAvailable:" in line:
                        available_kb = int(re.search(r'\d+', line).group())
                
                if total_kb > 0:
                    mem_info["total_gb"] = round(total_kb / (1024**2), 2)
                    mem_info["free_gb"] = round(free_kb / (1024**2), 2)
                    mem_info["available_gb"] = round(available_kb / (1024**2), 2)
                    used_kb = total_kb - available_kb # Utiliser MemAvailable pour un usage réel
                    mem_info["used_percent"] = round((used_kb / total_kb) * 100, 2)
                else:
                    self._log("warning", "Could not parse total memory from /proc/meminfo.")

        except Exception as e:
            self._log("error", f"Error getting memory info: {e}")
        self._log("debug", f"Memory Info: {mem_info}")
        return mem_info

    def _get_disk_info(self) -> list:
        """Collecte les informations sur les partitions de disque."""
        partitions_info = []
        try:
            df_output = self._run_command(["df", "-hT"]) # -h pour human readable, -T pour type de système de fichiers
            lines = df_output.splitlines()
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 7: # Filesystem    Type   Size  Used Avail Use% Mounted on
                        try:
                            filesystem = parts[0]
                            fs_type = parts[1]
                            size = parts[2]
                            used = parts[3]
                            avail = parts[4]
                            use_percent = parts[5].replace('%', '')
                            mountpoint = parts[6]

                            # Convertir en bytes/GB pour des calculs plus précis si nécessaire
                            # Pour l'instant, on garde le format lisible de df -h
                            partitions_info.append({
                                "filesystem": filesystem,
                                "type": fs_type,
                                "size": size,
                                "used": used,
                                "available": avail,
                                "percent_used": float(use_percent),
                                "mountpoint": mountpoint,
                            })
                        except ValueError as ve:
                            self._log("warning", f"Failed to parse df line (ValueError): {line} - {ve}")
                        except IndexError as ie:
                            self._log("warning", f"Unexpected df line format (IndexError): {line} - {ie}")
                    else:
                        self._log("warning", f"Skipping malformed df line: {line}")
        except Exception as e:
            self._log("error", f"Error getting disk info: {e}")
        self._log("debug", f"Disk Info: {partitions_info}")
        return partitions_info

    def _get_network_info(self) -> dict:
        """Collecte les informations sur les interfaces réseau."""
        net_info = {
            "interfaces": {},
            "default_gateway": "N/A",
            "dns_servers": []
        }
        try:
            # Récupération des interfaces, adresses IP et MAC
            ip_output = self._run_command(["ip", "-o", "addr"]) # Output plus facile à parser
            for line in ip_output.splitlines():
                # Exemple de ligne: 1: lo    inet 127.0.0.1/8 scope host    valid_lft forever preferred_lft forever
                # Ou: 2: eth0    link/ether 00:0c:29:ab:cd:ef brd ff:ff:ff:ff:ff:ff
                
                parts = line.split()
                if not parts: continue

                interface_name = parts[1].rstrip(':')
                
                if interface_name not in net_info["interfaces"]:
                    net_info["interfaces"][interface_name] = {
                        "ipv4_addresses": [],
                        "ipv6_addresses": [],
                        "mac_address": "N/A",
                        "status": "N/A"
                    }
                
                if 'link/ether' in line: # MAC address line
                    mac_match = re.search(r'link/ether ([0-9a-fA-F:]{17})', line)
                    if mac_match:
                        net_info["interfaces"][interface_name]["mac_address"] = mac_match.group(1)
                
                if 'inet ' in line: # IPv4 address line
                    ipv4_match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
                    if ipv4_match:
                        net_info["interfaces"][interface_name]["ipv4_addresses"].append(ipv4_match.group(1))
                
                if 'inet6 ' in line: # IPv6 address line
                    ipv6_match = re.search(r'inet6 ([0-9a-fA-F:]+/\d{1,3})', line)
                    if ipv6_match:
                        net_info["interfaces"][interface_name]["ipv6_addresses"].append(ipv6_match.group(1))
                
                # Status UP/DOWN (simplifié, peut nécessiter 'ip link show')
                if 'UP' in line:
                    net_info["interfaces"][interface_name]["status"] = "UP"
                elif 'DOWN' in line:
                    net_info["interfaces"][interface_name]["status"] = "DOWN"

            # Récupération de la passerelle par défaut
            route_output = self._run_command(["ip", "route", "show", "default"])
            gateway_match = re.search(r'default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', route_output)
            if gateway_match:
                net_info["default_gateway"] = gateway_match.group(1)

            # Récupération des serveurs DNS (souvent dans /etc/resolv.conf)
            resolv_conf = self._run_command(["cat", "/etc/resolv.conf"])
            for line in resolv_conf.splitlines():
                if line.startswith("nameserver"):
                    dns_ip = line.split()[1]
                    if dns_ip not in net_info["dns_servers"]:
                        net_info["dns_servers"].append(dns_ip)

        except Exception as e:
            self._log("error", f"Error getting network info: {e}")
        self._log("debug", f"Network Info: {net_info}")
        return net_info

    def _get_users_info(self) -> list:
        """Collecte les informations sur les utilisateurs connectés."""
        users_info = []
        try:
            who_output = self._run_command(["who"])
            for line in who_output.splitlines():
                parts = line.split(maxsplit=4) # Split au maximum 4 fois
                if len(parts) >= 4: # user, line, time, host (optional)
                    name = parts[0]
                    terminal = parts[1]
                    
                    # Regex pour capturer la date et l'heure, et l'hôte si présent entre parenthèses
                    # Exemple: "user     tty7         2024-06-25 09:30 (:0)"
                    # Ou: "user     pts/0        2024-06-25 09:30 (192.168.1.10)"
                    date_time_host_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2})(?: \((.*)\))?', parts[2] + " " + parts[3])
                    
                    started_time = date_time_host_match.group(1) if date_time_host_match else f"{parts[2]} {parts[3]}"
                    host = date_time_host_match.group(2) if date_time_host_match and date_time_host_match.group(2) else "local"
                    
                    # Si 'w' est disponible, il peut donner l'inactivité et JCPU/PCPU
                    users_info.append({
                        "name": name,
                        "terminal": terminal,
                        "host": host,
                        "started": started_time
                    })
        except Exception as e:
            self._log("error", f"Error getting user info: {e}")
        self._log("debug", f"Users Info: {users_info}")
        return users_info
    
    def _get_running_processes(self) -> list:
        """Collecte les informations sur les processus en cours d'exécution."""
        processes_list = []
        try:
            # Utiliser 'ps -e -o pid,ppid,user,etime,pcpu,pmem,args' pour plus de détails
            # et faciliter le parsing
            # etime = elapsed time since process started
            # pcpu = CPU utilization
            # pmem = memory utilization
            ps_output = self._run_command(["ps", "-e", "-o", "pid,ppid,user,etime,pcpu,pmem,args"])
            lines = ps_output.splitlines()
            if len(lines) > 1: # Skip header
                for line in lines[1:]:
                    try:
                        # Regex pour parser les colonnes. Les espaces peuvent varier.
                        match = re.match(r'^\s*(\d+)\s+(\d+)\s+([^ ]+)\s+([^ ]+)\s+([0-9.]+)\s+([0-9.]+)\s+(.*)', line)
                        if match:
                            pid = int(match.group(1))
                            ppid = int(match.group(2))
                            user = match.group(3)
                            elapsed_time = match.group(4)
                            cpu_percent = float(match.group(5))
                            mem_percent = float(match.group(6))
                            cmdline = match.group(7).strip()
                            
                            processes_list.append({
                                "pid": pid,
                                "ppid": ppid,
                                "user": user,
                                "elapsed_time": elapsed_time, # Format H:M:S ou D-H:M:S
                                "cpu_percent": cpu_percent,
                                "memory_percent": mem_percent,
                                "cmdline": cmdline
                            })
                        else:
                            self._log("warning", f"Failed to parse process line with regex: {line}")
                    except ValueError as ve:
                        self._log("warning", f"Data conversion error in process parsing: {line} - {ve}")
                    except Exception as e:
                        self._log("warning", f"Unexpected error during process line parsing: {line} - {e}")
        except Exception as e:
            self._log("error", f"Error getting running processes: {e}")
        self._log("debug", f"Collected {len(processes_list)} running processes.")
        return processes_list


    def collect_system_info(self) -> dict:
        """
        Collecte toutes les informations système et les retourne dans un dictionnaire.
        """
        self._log("info", "Starting system information collection (using system commands)...")
        system_info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": self._get_hostname(),
            "os_info": self._get_os_info(),
            "cpu_info": self._get_cpu_info(),
            "memory_info": self._get_memory_info(),
            "disk_info": self._get_disk_info(),
            "network_info": self._get_network_info(),
            "users_info": self._get_users_info(),
            "running_processes": self._get_running_processes()
        }
        self._log("info", "System information collection completed.")
        return system_info

# --- Partie de test (à exécuter si le fichier est lancé directement) ---
if __name__ == "__main__":
    print("\n--- Testing SystemProfiler Module ---")

    class MockLogger:
        def log_info(self, msg): print(f"[INFO] {msg}")
        def log_warning(self, msg): print(f"[WARN] {msg}")
        def log_error(self, msg): print(f"[ERROR] {msg}")
        def log_debug(self, msg): print(f"[DEBUG] {msg}")

    logger = MockLogger()
    profiler = SystemProfiler(logger=logger)

    system_data = profiler.collect_system_info()

    print("\n--- Collected System Information (JSON Format) ---")
    print(json.dumps(system_data, indent=4))

    # Basic assertions for data presence
    print("\n--- Verifying Collected Data ---")
    assert system_data["hostname"] != "N/A", "Hostname was not collected."
    print("Hostname collected: OK")
    assert "system" in system_data["os_info"] and system_data["os_info"]["system"] != "N/A", "OS information is missing or N/A."
    print("OS Info collected: OK")
    assert "model_name" in system_data["cpu_info"] and system_data["cpu_info"]["model_name"] != "N/A", "CPU model name is missing or N/A."
    print("CPU Info collected: OK")
    assert "total_gb" in system_data["memory_info"] and system_data["memory_info"]["total_gb"] != "N/A", "Memory info is missing or N/A."
    print("Memory Info collected: OK")
    assert isinstance(system_data["disk_info"], list) and len(system_data["disk_info"]) > 0, "Disk information is missing or not a list."
    print("Disk Info collected: OK")
    assert isinstance(system_data["network_info"]["interfaces"], dict), "Network interfaces are missing or malformed."
    print("Network Info collected: OK")
    assert isinstance(system_data["users_info"], list), "User information is missing."
    print("User Info collected: OK")
    assert isinstance(system_data["running_processes"], list), "Process information is missing."
    print("Processes collected: OK")

    print("\n--- SystemProfiler Module Tests Completed Successfully ---")
    print("[!] Note: The level of detail for collected information may vary significantly "
          "based on the operating system, installed tools, and user permissions.")


