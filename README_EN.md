[🇫🇷 Français](https://github.com/karim93160/hacker-suite-2000/blob/main/README.md) |
[🇬🇧 English](https://github.com/karim93160/hacker-suite-2000/blob/main/README_EN.md) |
[🇪🇸 Español](https://github.com/karim93160/hacker-suite-2000/blob/main/README_ES.md)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Dash-0062FF?style=for-the-badge&logo=plotly&logoColor=white" alt="Dash Plotly">
  <img src="https://img.shields.io/badge/Cybersecurity-00CED1?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/Termux-20C20E?style=for-the-badge&logo=android&logoColor=white" alt="Termux">
  <img src="https://img.shields.io/github/stars/karim93160/hacker-suite-2000?style=for-the-badge" alt="Stars">
  <img src="https://img.shields.io/github/forks/karim93160/hacker-suite-2000?style=for-the-badge" alt="Forks">
</p>

### 🚀HACKER-SUITE+2000🚀

---

<p align="center">
  <img src="https://github.com/Karim93160/Dark-Web/raw/56bcada59bf637cfddc36b7c3e04c6df5277b041/hacker_output.gif" alt="Hacker-Suite+2000 Demonstration" width="700"/>
</p>

---
<p align="center">
<img src="https://img.shields.io/badge/Python-3.8+-informational?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+ Required">
<img src="https://img.shields.io/badge/Interface-Web%20Dash-blueviolet?style=for-the-badge" alt="Web Dash Interface">
<img src="https://img.shields.io/badge/Exfiltration-HTTPS%2FDNS-green?style=for-the-badge" alt="HTTPS/DNS Exfiltration">
</p>
---

## 📦 Installation
Follow these steps to set up and launch HACKER-SUITE+2000.
Termux Preparation (Android)
If you're using Termux on Android, you can run the included setup script to facilitate installation of necessary tools:
 * Open Termux.
 * Clone the repository (if not already done):

```
git clone https://github.com/karim93160/hacker-suite-2000.git
cd hacker-suite-2000

```

 * Run the script:

```
setup_termux.sh:
chmod +x setup_termux.sh
./setup_termux.sh

```

This script will install python, pip, and other system tools if needed.

---

## 🚀 Launching the Application

To start the HACKER-SUITE+2000 control interface, navigate to the project's main directory and run:

```
python3 control_panel.py

```

We recommend running it in the background so you can close your terminal without stopping the application (Make sure you're in the project root directory):

```
cd exfiltration_agent/
nohup python3 -u control_panel.py > control_panel.log 2>&1 &

```

 * nohup: Prevents the process from stopping if the terminal is closed.
 * python3 -u: Runs Python in unbuffered mode, useful for real-time logging.
 * > control_panel.log 2>&1: Redirects standard output and error to control_panel.log for later debugging.

 * &: Runs the process in the background.
Once launched, you'll see messages in your terminal indicating the application is ready.
Access the interface via your web browser at:

```
http://127.0.0.1:8050
```

Welcome to HACKER-SUITE+2000, an advanced toolkit for cyber operations, designed for data exfiltration, system profiling, and payload management, all through an intuitive web interface. This tool is developed with Python and Dash, offering a smooth user experience for controlling local or remote agents.

---

*🤝 Contributions*

**Contributions are welcome! If you'd like to improve hacker-suite+2000, fix bugs, or add new features, please check out our Contribution Guide.**

[![Sponsor me on GitHub](https://img.shields.io/badge/Sponsor-GitHub-brightgreen.svg)](https://github.com/sponsors/karim93160)
[![Buy me a coffee](https://img.shields.io/badge/Donate-Buy%20Me%20A%20Coffee-FFDD00.svg)](https://www.buymeacoffee.com/karim93160)
[![Support me on Ko-fi](https://img.shields.io/badge/Donate-Ko--fi-F16061.svg)](https://ko-fi.com/karim93160)
[![Support me on Patreon](https://img.shields.io/badge/Patreon-Support%20me-FF424D.svg)](https://www.patreon.com/karim93160)
[![Donate on Liberapay](https://img.shields.io/badge/Donate-Liberapay-F6C915.svg)](https://liberapay.com/karim93160/donate)

_________

## License 📜

hacker-suite+2000 is distributed under the [MIT License](https://github.com/Karim93160/hacker-suite-2000/blob/cae8101acb7c14a65792abfcf21b332d1dc8afd0/LICENSE)
_________
## Contact 📧

For any questions or suggestions, feel free to open a [GitHub issue](https://github.com/Karim93160/hacker-suite-2000/issues) or contact us by email:

[![Contact by Email](https://img.shields.io/badge/Contact-by%20Email-blue.svg)](mailto:karim9316077185@gmail.com)
_________
<div align="center">
  <h2>🌿 hacker-suite+2000 - Code of Conduct 🌿</h2>
  <p>
    We are committed to creating a welcoming and respectful environment for all contributors.
    Please take a moment to read our <a href="CODE_OF_CONDUCT.md">Code of Conduct</a>.
    By participating in this project, you agree to abide by its terms.
  </p>
  <p>
    <a href="CODE_OF_CONDUCT.md">
      <img src="https://img.shields.io/badge/Code%20of%20Conduct-Please%20Read-blueviolet?style=for-the-badge&logo=github" alt="Code of Conduct">
    </a>
  </p>
</div>
<div align="center">
  <h2>🐞 Report a Bug in hacker-suite+2000 🐞</h2>
  <p>
    Encountering an issue with hacker-suite+2000? Help us improve the project by reporting bugs!
    Click the button below to directly open a new pre-filled bug report.
  </p>
  <p>
    <a href="https://github.com/karim93160/hacker-suite-2000/issues/new?assignees=&labels=bug&projects=&template=bug_report.md&title=">
      <img src="https://img.shields.io/badge/Report%20a%20Bug-Open%20an%20Issue-red?style=for-the-badge&logo=bugsnag" alt="Report a Bug">
    </a>
  </p>
</div>

---

## 🎯 Table of Contents
 * Overview
 * Features
 * Project Structure
 * Prerequisites
 * Installation
   * Termux Preparation (Android)
   * Python Dependencies Installation
 * Launching the Application
 * Using the Interface
   * "DYNAMIC DISPLAY" Tab
   * "DASHBOARD" Tab
   * "AGENT CONTROL" Tab
   * "FILE EXPLORER" Tab
   * "SYSTEM PROFILER" Tab
   * "PAYLOADS & PERSISTENCE" Tab
   * "STEALTH & EVASION" Tab
   * "LOGS & STATUS" Tab
 * Configuration
 * Contributing
 * License
 * Code of Conduct
 
 ---
 
# ✨Overview
HACKER-SUITE+2000 is a centralized cyber-operations environment that lets you deploy, configure, and monitor an exfiltration agent. Whether you need to collect specific files, obtain detailed information about a target system, manage malicious payloads, or maintain operational stealth, this suite gives you the necessary control through a web browser-based graphical interface.
Designed for flexibility, it supports exfiltration via HTTPS and DNS, and includes advanced filtering mechanisms to precisely target data. The interface offers a real-time dashboard, an interactive file explorer, system profiling capabilities, and controls for stealth and evasion.

---

## 🛠️ Features
 * Interactive Web Interface: Control the agent through a Dash user interface accessible from any web browser.
 * Versatile Exfiltration Agent:
   * Exfiltration Methods: Supports HTTPS (recommended) and DNS (for stealthy scenarios).
   * Advanced Filtering: File scanning by type (inclusion/exclusion), min/max size, keywords, and regular expressions.
   * AES256 Encryption: Encrypts exfiltrated data and logs to ensure confidentiality.
 * Target File Explorer: Navigate through local or remote (web) file systems of the target system, view file contents, and download files.
 * Detailed System Profiling: Collects comprehensive information about the target system (OS, CPU, memory, disks, network, users, running processes).
 * Payload Management: Deploy, execute, and remove custom payloads on the target system.
 * Stealth & Evasion: Options for process hiding, anti-debugging, and sandbox detection bypass.
 * Built-in Logging: Displays agent logs in real-time and allows reading/downloading encrypted logs.
 * Status Dashboard: Monitors key agent metrics (scanned files, exfiltrated files, etc.) in real-time.
 * Configuration Persistence: Settings are saved in shared_config.json for easy reloading.

---

## 📂 Project Structure

Here's an overview of the project's file and directory organization:

```
├── CODE_OF_CONDUCT.md
├── LICENSE
├── README.md
├── README_EN.md
├── README_ES.md
├── control_panel.py
├── display
│   ├── index.html
│   ├── script.js
│   └── style.css
├── exf_agent.py
├── modules
│   ├── __pycache__
│   │   ├── aes256.cpython-312.pyc
│   │   ├── file_explorer.cpython-312.pyc
│   │   ├── log_streamer.cpython-312.pyc
│   │   ├── logger.cpython-312.pyc
│   │   ├── system_profiler.cpython-312.pyc
│   │   └── web_explorer.cpython-312.pyc
│   ├── aes256.py
│   ├── anti_evasion.py
│   ├── compression.py
│   ├── config.py
│   ├── exfiltration_dns.py
│   ├── exfiltration_http.py
│   ├── file_explorer.py
│   ├── file_scanner.py
│   ├── log_streamer.py
│   ├── logger.py
│   ├── payload_dropper.py
│   ├── retry_manager.py
│   ├── stealth_mode.py
│   ├── system_profiler.py
│   └── web_explorer.py
├── requirements.txt
├── setup_termux.sh
└── shared_config.json

4 directories, 34 files
```

---

## ⚙️ Prerequisites
Make sure you have the following installed on your system (recommended: Linux or Termux for Android):
 * Python 3.x (3.8 or newer recommended)
 * pip (Python package manager)

---

## 🖥️Using the Interface
The interface is organized into several tabs, each dedicated to a specific aspect of agent management.
"DYNAMIC DISPLAY" Tab
This tab serves as a visual and dynamic dashboard, potentially for displaying aggregated information or real-time visualizations of agent activity. It loads content from display/index.html.
"DASHBOARD" Tab
Monitor the agent's status in real-time.
 * Key Statistics: Displays number of files scanned, matches found, amount of data exfiltrated, exfiltration success/failure, agent status, and timestamps.
 * Live System Activity: A real-time log stream from the agent, giving you instant insight into its operations.
"AGENT CONTROL" Tab
Configure agent settings and start/stop its operations.
 * Deployment & Configuration:
   * Target URL (HTTPS/DNS): The URL or IP address where exfiltrated data will be sent.
   * Scan Path: The local directory on the target system to scan.
   * AES Key (32 bytes): Encryption key used for exfiltration and logs. Required.
   * Exfiltration Method: Choose between HTTPS (recommended) or DNS. If DNS is selected, you'll need to specify a DNS server and domain.
 * Filtering Settings: Define criteria for file scanning: file types to include/exclude, minimum/maximum size, keywords and regular expressions to search in file contents.
 * Operational Settings:
   * Payload URL (Optional): URL to download a payload.
   * Payload Path (Optional): Path where the payload will be saved on the target system.
   * Processing Threads: Number of threads to use for scanning and uploading.
 * Debugging & Evasion Options: Enable debug mode (verbose logging, no cleanup), disable trace cleanup, or disable anti-evasion checks.
 * Actions:
   * <kbd>[ SAVE ALL CONFIG ]</kbd>: Saves current configuration to shared_config.json.
   * <kbd>[ LAUNCH AGENT ]</kbd>: Starts the agent with the applied configuration.
   * <kbd>[ STOP AGENT ]</kbd>: Stops the running agent.
"FILE EXPLORER" Tab
Explore the target's file system.
 * Target Host: The URL or IP address of the target for exploration.
 * Base Path: The path on the target system from which to start exploration (leave empty for full web exploration).
 * Maximum Depth: Limits the recursion depth of exploration.
 * Actions:
   * <kbd>[ LAUNCH EXPLORATION ]</kbd>: Starts exploration based on parameters.
   * <kbd>[ STOP EXPLORATION ]</kbd>: Stops ongoing exploration.
 * Exploration Results: Displays found files and directories in a table. You can "READ" (view content) or "DOWNLOAD" files identified.
 * Explorer Live Logs: Displays explorer operations in real-time.
"SYSTEM PROFILER" Tab
Get detailed information about the target system.
 * <kbd>[ REQUEST SYSTEM INFO ]</kbd>: Triggers system information collection from the agent.
 * Information Display: Data is presented in collapsible sections:
   * Operating system information
   * CPU information
   * Memory usage
   * Disk partitions
   * Network interfaces
   * Connected users
   * Running processes
"PAYLOADS & PERSISTENCE" Tab
Manage payload deployment and execution.
 * Payload Source (URL): URL from which the payload will be downloaded.
 * Target Path on Agent: Location on the target system where the payload will be stored.
 * Actions:
   * <kbd>[ DEPLOY PAYLOAD ]</kbd>: Deploys payload to target.
   * <kbd>[ EXECUTE PAYLOAD ]</kbd>: Executes deployed payload.
   * <kbd>[ REMOVE PAYLOAD ]</kbd>: Removes payload from target.
"STEALTH & EVASION" Tab
Configure agent stealth and anti-evasion features.
 * ACTIVATE PROCESS HIDING: Attempts to hide the agent process.
 * ENABLE ANTI-DEBUGGING: Enables mechanisms to detect and hinder debugging.
 * BYPASS SANDBOX DETECTION: Activates techniques to bypass sandbox detection.
 * <kbd>[ APPLY STEALTH SETTINGS ]</kbd>: Applies selected stealth settings to the agent.
"LOGS & STATUS" Tab
View and manage agent logs.
 * Agent Live Log Stream: A display of agent logs in real-time, similar to the dashboard.
 * Encrypted Log Archive:
   * <kbd>[ REFRESH ENCRYPTED LOGS ]</kbd>: Loads and decrypts agent logs stored locally (agent_logs.enc). Make sure the AES key in the "AGENT CONTROL" tab is correct for decryption.
   * <kbd>[ DOWNLOAD RAW LOGS ]</kbd>: Downloads the encrypted log file (agent_logs.enc).
⚙️ Configuration
The shared_config.json file is automatically generated (if absent) when first launching the application. It stores default settings and the AES key.
<p align="center">⚠️     WARNING     ⚠️</p>
During initial generation, the default_target_url field will contain

```https://webhook.site/YOUR_UNIQUE_URL_HERE```

It is imperative to replace this URL with your own data reception service URL (for example, a custom webhook.site) via the interface or by manually editing the shared_config.json file before launching the agent.
