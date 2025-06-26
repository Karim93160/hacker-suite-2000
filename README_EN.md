<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Dash-0062FF?style=for-the-badge&logo=plotly&logoColor=white" alt="Dash Plotly">
  <img src="https://img.shields.io/badge/Cybersecurity-00CED1?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/Termux-20C20E?style=for-the-badge&logo=android&logoColor=white" alt="Termux">
  <img src="https://img.shields.io/github/stars/karim93160/hacker-suite-2000?style=for-the-badge" alt="Stars">
  <img src="https://img.shields.io/github/forks/karim93160/hacker-suite-2000?style=for-the-badge" alt="Forks">
</p>

### 🚀 HACKER-SUITE+2000 🚀

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

Welcome to **HACKER-SUITE+2000**, an **advanced** cyber operations tool suite, designed for **data exfiltration**, **system profiling**, and **payload management**, all through an intuitive web interface. This tool is developed with **Python** and **Dash**, offering a **fluid** user experience for controlling remote or local agents.

---

## 🎯 Table of Contents

* [Overview](#-overview)
* [Features](#-features)
* [Project Structure](#-project-structure)
* [Prerequisites](#-prerequisites)
* [Installation](#-installation)
    * [Termux Preparation (Android)](#termux-preparation-android)
    * [Python Dependencies Installation](#python-dependencies-installation)
* [Application Startup](#-application-startup)
* [Interface Usage](#-interface-usage)
    * [ "DYNAMIC DISPLAY" Tab](#dynamic-display-tab)
    * [ "DASHBOARD" Tab](#dashboard-tab)
    * [ "AGENT CONTROL" Tab](#agent-control-tab)
    * [ "FILE EXPLORER" Tab](#file-explorer-tab)
    * [ "SYSTEM PROFILER" Tab](#system-profiler-tab)
    * [ "PAYLOADS & PERSISTENCE" Tab](#payloads--persistence-tab)
    * [ "STEALTH & EVASION" Tab](#stealth--evasion-tab)
    * [ "LOGS & STATUS" Tab](#logs--status-tab)
* [Configuration](#-configuration)
* [Contributing](#-contributing)
* [License](#-license)
* [Contact](#-contact)
* [Code of Conduct](#-code-of-conduct)
* [Report a Bug](#-report-a-bug)

---

## ✨ Overview

**HACKER-SUITE+2000** is a centralized cyber operations environment that allows you to **deploy**, **configure**, and **monitor** an exfiltration agent. Whether you need to collect specific files, obtain detailed system information from a target, manage malicious payloads, or maintain the discretion of your operations, this suite gives you the **necessary control** via a graphical interface based on a web browser.

Designed for **flexibility**, it supports exfiltration via **HTTPS** and **DNS**, and includes **advanced filtering mechanisms** to precisely target data. The interface offers a **real-time** dashboard, an **interactive file explorer**, **system profiling capabilities**, and controls for **stealth** and **evasion**.

---

## 🛠️ Features

* **Interactive Web Interface**: Control the agent via a **Dash** user interface accessible from any browser.
* **Versatile Exfiltration Agent**:
    * **Exfiltration Methods**: Supports **HTTPS** (recommended) and **DNS** (for covert scenarios).
    * **Advanced Filtering**: File scanning by type (**inclusion/exclusion**), min/max size, **keywords**, and **regular expressions**.
    * **AES256 Encryption**: Encrypts exfiltrated data and logs to ensure **confidentiality**.
* **Target File Explorer**: Navigate local or remote (web) file systems of the target, view file content, and download them.
* **Detailed System Profiling**: Collects comprehensive information about the target system (OS, CPU, memory, disks, network, users, running processes).
* **Payload Management**: Deploy, execute, and remove custom payloads on the target system.
* **Stealth & Evasion**: Options for **process hiding**, **anti-debugging**, and **sandbox detection bypass**.
* **Integrated Logging**: Displays agent logs in real-time and allows reading/downloading encrypted logs.
* **Status Dashboard**: Monitors key agent metrics (scanned files, exfiltrated files, etc.) live.
* **Configuration Persistence**: Settings are saved in `shared_config.json` for easy reloading.

---

## 📂 Project Structure

Here's an overview of the project's file and directory organization:

    .
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

---

## ⚙️ Prerequisites

Make sure you have the following installed on your system (recommended: **Linux** or **Termux** for Android):

* **Python 3.x** (3.8 or newer recommended)
* **pip** (Python package manager)

---

## 📦 Installation

Follow these steps to set up and launch **HACKER-SUITE+2000**.

### Termux Preparation (Android)

If you are using **Termux** on Android, you can run the included setup script to facilitate the installation of necessary tools:

* Open Termux.
* Clone the repository (if you haven't already):

```bash
git clone [https://github.com/karim93160/hacker-suite-2000.git](https://github.com/karim93160/hacker-suite-2000.git)
cd hacker-suite-2000

 * Execute the script:
<!-- end list -->
setup_termux.sh :
chmod +x setup_termux.sh
./setup_termux.sh

This script will install python, pip, and other system tools if needed.
Python Dependencies Installation
Whether you are on a standard Linux system or Termux, navigate to the project's root directory and install the Python dependencies:
pip install -r requirements.txt

🚀 Application Startup
To launch the HACKER-SUITE+2000 control interface, navigate to the project's main directory and run:
control_panel.py

We recommend running it in the background so you can close your terminal without stopping the application (Make sure you are in the project's root directory):
cd exfiltration_agent/
nohup python3 -u control_panel.py > control_panel.log 2>&1 &

 * nohup: Prevents the process from stopping if the terminal is closed.
 * python3 -u: Runs Python in unbuffered mode, useful for real-time logs.
 * > control_panel.log 2>&1: Redirects standard output and standard error to control_panel.log for later debugging.
 * &: Launches the process in the background.
Once launched, you will see messages in your terminal indicating that the application is ready.
Access the interface via your web browser at:
[http://127.0.0.1:8050](http://127.0.0.1:8050)

<p align="center">
<a href="[lien suspect supprimé]">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Access%2520Interface-8050-blue%3Fstyle%3Dfor-the-badge%26logo%3Dinternet-explorer%26logoColor%3Dwhite" alt="Access Interface Button">
</a>
</p>
🖥️ Interface Usage
The interface is organized into several tabs, each dedicated to a specific aspect of agent management.
"DYNAMIC DISPLAY" Tab
This tab serves as a visual and dynamic dashboard, potentially for displaying aggregated information or real-time visualizations of agent activity. It loads content from display/index.html.
"DASHBOARD" Tab
Monitor the agent's status in real-time.
 * Key Statistics: Displays the number of files scanned, matches found, amount of data exfiltrated, exfiltration success/failure, agent status, and timestamps.
 * Live System Activity: A real-time log stream from the agent, giving you an instant overview of its operations.
"AGENT CONTROL" Tab
Configure agent settings and launch/stop its operations.
 * Deployment & Configuration:
   * Target URL (HTTPS/DNS): The URL or IP address where exfiltrated data will be sent.
   * Scan Path: The local directory on the target system to scan.
   * AES Key (32 bytes): Encryption key used for exfiltration and logs. Mandatory.
   * Exfiltration Method: Choose between HTTPS (recommended) or DNS. If DNS is selected, you must specify a DNS server and domain.
 * Filtering Parameters: Define criteria for file scanning: file types to include/exclude, min/max size, keywords, and regular expressions to search within file content.
 * Operational Parameters:
   * Payload URL (Optional): URL to download a payload.
   * Payload Path (Optional): Path where the payload will be saved on the target system.
   * Processing Threads: Number of threads to use for scanning and uploading.
 * Debugging & Evasion Options: Enable debug mode (verbose logs, no cleanup), disable trace cleanup, or disable anti-evasion controls.
 * Actions:
   * <kbd>[ SAVE ALL CONFIG ]</kbd>: Saves the current configuration to shared_config.json.
   * <kbd>[ LAUNCH AGENT ]</kbd>: Starts the agent with the applied configuration.
   * <kbd>[ STOP AGENT ]</kbd>: Stops the running agent.
"FILE EXPLORER" Tab
Explore the target's file system.
 * Target Host: The URL or IP address of the target for exploration.
 * Base Path: The path on the target system from which to start exploration (leave blank for a full web crawl).
 * Max Depth: Limits the recursion depth of the exploration.
 * Actions:
   * <kbd>[ LAUNCH EXPLORATION ]</kbd>: Launches exploration based on parameters.
   * <kbd>[ STOP EXPLORATION ]</kbd>: Stops ongoing exploration.
 * Exploration Results: Displays found files and directories in a table. You can "READ" file content or "DOWNLOAD" identified files.
 * Live Explorer Logs: Displays real-time explorer operations.
"SYSTEM PROFILER" Tab
Get detailed information about the target system.
 * <kbd>[ REQUEST SYSTEM INFO ]</kbd>: Triggers the collection of system information from the agent.
 * Information Display: Data is presented in expandable sections:
   * Operating System Information
   * CPU Information
   * Memory Usage
   * Disk Partitions
   * Network Interfaces
   * Logged-in Users
   * Running Processes
"PAYLOADS & PERSISTENCE" Tab
Manage payload deployment and execution.
 * Payload Source (URL): URL from which the payload will be downloaded.
 * Target Path on Agent: The location on the target system where the payload will be stored.
 * Actions:
   * <kbd>[ DEPLOY PAYLOAD ]</kbd>: Deploys the payload to the target.
   * <kbd>[ EXECUTE PAYLOAD ]</kbd>: Executes the deployed payload.
   * <kbd>[ REMOVE PAYLOAD ]</kbd>: Removes the payload from the target.
"STEALTH & EVASION" Tab
Configure the agent's stealth capabilities and anti-evasion mechanisms.
 * ACTIVATE PROCESS HIDING: Attempts to hide the agent's process.
 * ENABLE ANTI-DEBUGGING: Activates mechanisms to detect and hinder debugging.
 * BYPASS SANDBOX DETECTION: Activates techniques to bypass sandbox detection.
 * <kbd>[ APPLY STEALTH SETTINGS ]</kbd>: Applies selected stealth settings to the agent.
"LOGS & STATUS" Tab
View and manage agent logs.
 * Agent Live Log Stream: A real-time display of agent logs, similar to the dashboard.
 * Encrypted Log Archive:
   * <kbd>[ REFRESH ENCRYPTED LOGS ]</kbd>: Loads and decrypts agent logs stored locally (agent_logs.enc). Ensure the AES key in the "AGENT CONTROL" tab is correct for decryption.
   * <kbd>[ DOWNLOAD RAW LOGS ]</kbd>: Downloads the encrypted log file (agent_logs.enc).
⚙️ Configuration
The shared_config.json file is automatically generated (if absent) on the application's first launch. It stores default settings and the AES key.
<p align="center">⚠️     WARNING     ⚠️</p>
Upon first generation, the default_target_url field will contain https://webhook.site/YOUR_UNIQUE_URL_HERE. It is imperative to replace this URL with your own data reception service URL (e.g., a custom webhook.site) via the interface or by manually modifying the shared_config.json file before launching the agent.
🤝 Contributions
Contributions are welcome! If you wish to improve HACKER-SUITE+2000, fix bugs, or add new features, please consult our Contribution Guide.





License 📜
hacker-suite+2000 is distributed under the MIT License
Contact 📧
For any questions or suggestions, feel free to open an issue on GitHub or contact us by email:
<div align="center">
<h2>🌿 hacker-suite+2000 - Code of Conduct 🌿</h2>
<p>
We are committed to creating a welcoming and respectful environment for all contributors.
Please take a moment to read our <a href="CODE_OF_CONDUCT.md">Code of Conduct</a>.
By participating in this project, you agree to abide by its terms.
</p>
<p>
<a href="CODE_OF_CONDUCT.md">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Code%2520of%2520Conduct-Please%2520Read-blueviolet%3Fstyle%3Dfor-the-badge%26logo%3Dgithub" alt="Code of Conduct">
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
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Report%2520a%2520Bug-Open%2520an%2520Issue-red%3Fstyle%3Dfor-the-badge%26logo%3Dbugsnag" alt="Report a Bug">
</a>
</p>
</div>
