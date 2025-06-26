<p align="center">
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Dash-0062FF?style=for-the-badge&logo=plotly&logoColor=white" alt="Dash Plotly">
<img src="https://img.shields.io/badge/Cybersecurity-00CED1?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Cybersecurity">
<img src="https://img.shields.io/badge/Termux-20C20E?style=for-the-badge&logo=android&logoColor=white" alt="Termux">
<img src="https://img.shields.io/github/stars/karim93160/hacker-suite-2000?style=for-the-badge" alt="Stars">
<img src="https://img.shields.io/github/forks/karim93160/hacker-suite-2000?style=for-the-badge" alt="Forks">
</p>

# 🚀HACKER-SUITE+2000🚀

---

Bienvenue dans HACKER-SUITE+2000, une suite d'outils avancée pour les opérations cyber, conçue pour l'exfiltration de données, le profilage système et la gestion de payloads, le tout via une interface web intuitive. Cet outil est développé avec Python et Dash, offrant une expérience utilisateur fluide pour le contrôle d'agents à distance ou locaux.
<p align="center">
<img src="https://img.shields.io/badge/Python-3.8+-informational?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+ Required">
<img src="https://img.shields.io/badge/Interface-Web%20Dash-blueviolet?style=for-the-badge" alt="Web Dash Interface">
<img src="https://img.shields.io/badge/Exfiltration-HTTPS%2FDNS-green?style=for-the-badge" alt="HTTPS/DNS Exfiltration">
</p>

---

## 🎯 Table des matières
 * Présentation
 * Fonctionnalités
 * Structure du projet
 * Prérequis
 * Installation
   * Préparation Termux (Android)
   * Installation des dépendances Python
 * Démarrage de l'application
 * Utilisation de l'interface
   * Onglet "DYNAMIC DISPLAY"
   * Onglet "DASHBOARD"
   * Onglet "AGENT CONTROL"
   * Onglet "FILE EXPLORER"
   * Onglet "SYSTEM PROFILER"
   * Onglet "PAYLOADS & PERSISTENCE"
   * Onglet "STEALTH & EVASION"
   * Onglet "LOGS & STATUS"
 * Configuration
 * Contribuer
 * Licence
 * Code de conduite
 
 ---
 
# ✨Présentation
HACKER-SUITE+2000 est un environnement de cyber-opérations centralisé qui te permet de déployer, configurer et surveiller un agent d'exfiltration. Que tu aies besoin de collecter des fichiers spécifiques, d'obtenir des informations détaillées sur un système cible, de gérer des charges utiles malveillantes ou de maintenir la discrétion de tes opérations, cette suite te donne le contrôle nécessaire via une interface graphique basée sur un navigateur web.
Conçu pour la flexibilité, il prend en charge l'exfiltration via HTTPS et DNS, et inclut des mécanismes de filtrage avancés pour cibler précisément les données. L'interface offre un tableau de bord en temps réel, un explorateur de fichiers interactif, des capacités de profilage système et des contrôles pour la furtivité et l'évasion.

---

## 🛠️ Fonctionnalités
 * Interface Web Interactive : Contrôle l'agent via une interface utilisateur Dash accessible depuis n'importe quel navigateur.
 * Agent d'Exfiltration Polyvalent :
   * Méthodes d'Exfiltration : Supporte HTTPS (recommandé) et DNS (pour les scénarios furtifs).
   * Filtrage Avancé : Scan de fichiers par type (inclusion/exclusion), taille min/max, mots-clés et expressions régulières.
   * Chiffrement AES256 : Chiffre les données exfiltrées et les logs pour garantir la confidentialité.
 * Explorateur de Fichiers Cible : Navigue dans les systèmes de fichiers locaux ou distants (web) du système cible, affiche le contenu des fichiers et les télécharge.
 * Profilage Système Détaillé : Collecte des informations complètes sur le système cible (OS, CPU, mémoire, disques, réseau, utilisateurs, processus en cours).
 * Gestion des Payloads : Déploie, exécute et supprime des charges utiles personnalisées sur le système cible.
 * Furtivité & Évasion : Options pour le masquage de processus, l'anti-débogage et le contournement des détections de sandbox.
 * Journalisation Intégrée : Affiche les logs de l'agent en temps réel et permet la lecture/téléchargement des logs chiffrés.
 * Tableau de Bord de Statut : Surveille les métriques clés de l'agent (fichiers scannés, exfiltrés, etc.) en direct.
 * Persistance de Configuration : Les paramètres sont sauvegardés dans shared_config.json pour un rechargement facile.

---

## 📂 Structure du projet
Voici un aperçu de l'organisation des fichiers et des répertoires du projet :

├── CODE_OF_CONDUCT.md
├── LICENSE
├── README.md           <- Ce fichier
├── README_EN.md        <- Version anglaise du README
├── README_ES.md        <- Version espagnole du README
├── control_panel.py    <- Script principal de l'interface web Dash
├── display             <- Contient les assets web (HTML, CSS, JS) pour l'interface
│   ├── index.html
│   ├── script.js
│   └── style.css
├── exf_agent.py        <- Le script de l'agent d'exfiltration lui-même
├── modules             <- Modules Python internes pour les fonctionnalités de l'agent
│   ├── __pycache__
│   ├── aes256.py           <- Module de chiffrement AES256
│   ├── anti_evasion.py     <- Logique anti-évasion
│   ├── compression.py      <- Gestion de la compression des données
│   ├── config.py           <- Configuration interne des modules
│   ├── exfiltration_dns.py <- Méthode d'exfiltration DNS
│   ├── exfiltration_http.py<- Méthode d'exfiltration HTTP
│   ├── file_explorer.py    <- Module d'exploration de fichiers locaux
│   ├── file_scanner.py     <- Logique de scan de fichiers
│   ├── log_streamer.py     <- Diffusion des logs en temps réel
│   ├── logger.py           <- Système de journalisation
│   ├── payload_dropper.py  <- Gestion du déploiement de payloads
│   ├── retry_manager.py    <- Gestion des tentatives pour les opérations réseau
│   ├── stealth_mode.py     <- Fonctionnalités de mode furtif
│   ├── system_profiler.py  <- Module de profilage système
│   └── web_explorer.py     <- Module d'exploration web
├── requirements.txt    <- Liste des dépendances Python
├── setup_termux.sh     <- Script d'aide pour la configuration sous Termux
└── shared_config.json  <- Fichier de configuration partagée

---

## ⚙️ Prérequis
Assure-toi d'avoir les éléments suivants installés sur ton système (recommandé : Linux ou Termux pour Android) :
 * Python 3.x (3.8 ou plus récent recommandé)
 * pip (gestionnaire de paquets Python)

---

## 📦 Installation
Suis ces étapes pour configurer et lancer HACKER-SUITE+2000.
Préparation Termux (Android)
Si tu utilises Termux sur Android, tu peux exécuter le script de configuration inclus pour faciliter l'installation des outils nécessaires :
 * Ouvre Termux.
 * Clone le dépôt (si ce n'est pas déjà fait) :

```
git clone https://github.com/ton_utilisateur/hacker-suite-2000.git
cd hacker-suite-2000
```

 * Exécute le script ```
setup_termux.sh :
chmod +x setup_termux.sh
./setup_termux.sh
```

Ce script installera python, pip, et d'autres outils système si nécessaire.

---

## 🚀 Démarrage de l'application

Pour lancer l'interface de contrôle HACKER-SUITE+2000, navigue dans le répertoire principal du projet et exécute :

```
control_panel.py
```

Nous te recommandons de le lancer en arrière-plan pour que tu puisses fermer ton terminal sans arrêter l'application (Assure-toi d'être dans le répertoire racine du projet) :

```
cd exfiltration_agent/
nohup python3 -u control_panel.py > control_panel.log 2>&1 &
```

 * nohup : Empêche le processus de s'arrêter si le terminal est fermé.
 * python3 -u : Exécute Python en mode non-tamponné, ce qui est utile pour les logs en temps réel.
 * > control_panel.log 2>&1 : Redirige la sortie standard et l'erreur standard vers control_panel.log pour un débogage ultérieur.

 * & : Lance le processus en arrière-plan.
Une fois lancé, tu verras des messages dans ton terminal indiquant que l'application est prête.
Accède à l'interface via ton navigateur web à l'adresse :

```http://127.0.0.1:8050```

---

## 🖥️Utilisation de l'interface
L'interface est organisée en plusieurs onglets, chacun dédié à un aspect spécifique de la gestion de l'agent.
Onglet "DYNAMIC DISPLAY"
Cet onglet sert de tableau de bord visuel et dynamique, potentiellement pour afficher des informations agrégées ou des visualisations en temps réel de l'activité de l'agent. Il charge le contenu de display/index.html.
Onglet "DASHBOARD"
Surveille l'état de l'agent en temps réel.
 * Statistiques Clés : Affiche le nombre de fichiers scannés, les correspondances trouvées, la quantité de données exfiltrées, le succès/échec de l'exfiltration, le statut de l'agent, et les horodatages.
 * Activité Système en Direct : Un flux de logs en temps réel provenant de l'agent, te donnant un aperçu instantané de ses opérations.
Onglet "AGENT CONTROL"
Configure les paramètres de l'agent et lance/arrête ses opérations.
 * Déploiement & Configuration :
   * URL Cible (HTTPS/DNS) : L'URL ou l'adresse IP où les données exfiltrées seront envoyées.
   * Chemin de Scan : Le répertoire local sur le système cible à scanner.
   * Clé AES (32 bytes) : Clé de chiffrement utilisée pour l'exfiltration et les logs. Obligatoire.
   * Méthode d'Exfiltration : Choisis entre HTTPS (recommandé) ou DNS. Si DNS est sélectionné, tu devras spécifier un serveur DNS et un domaine.
 * Paramètres de Filtrage : Définis les critères pour le scan de fichiers : types de fichiers à inclure/exclure, taille minimale/maximale, mots-clés et expressions régulières à rechercher dans le contenu des fichiers.
 * Paramètres Opérationnels :
   * URL de Payload (Optionnel) : URL pour télécharger une charge utile.
   * Chemin de Payload (Optionnel) : Chemin où la charge utile sera sauvegardée sur le système cible.
   * Threads de Traitement : Nombre de threads à utiliser pour le scan et l'upload.
 * Options de Débogage & Évasion : Active le mode débogage (logs verbeux, pas de nettoyage), désactive le nettoyage des traces, ou désactive les contrôles anti-évasion.
 * Actions :
   * <kbd>[ SAVE ALL CONFIG ]</kbd> : Sauvegarde la configuration actuelle dans shared_config.json.
   * <kbd>[ LAUNCH AGENT ]</kbd> : Démarre l'agent avec la configuration appliquée.
   * <kbd>[ STOP AGENT ]</kbd> : Arrête l'agent en cours d'exécution.
Onglet "FILE EXPLORER"
Explore le système de fichiers de la cible.
 * Hôte Cible : L'URL ou l'adresse IP de la cible pour l'exploration.
 * Chemin de Base : Le chemin sur le système cible à partir duquel commencer l'exploration (laisse vide pour une exploration complète sur le web).
 * Profondeur Maximale : Limite la profondeur de récursivité de l'exploration.
 * Actions :
   * <kbd>[ LAUNCH EXPLORATION ]</kbd> : Lance l'exploration en fonction des paramètres.
   * <kbd>[ STOP EXPLORATION ]</kbd> : Arrête l'exploration en cours.
 * Résultats de l'Exploration : Affiche les fichiers et répertoires trouvés dans un tableau. Tu peux "READ" (lire le contenu) ou "DOWNLOAD" (télécharger) les fichiers identifiés.
 * Logs en Direct de l'Explorateur : Affiche les opérations de l'explorateur en temps réel.
Onglet "SYSTEM PROFILER"
Obtiens des informations détaillées sur le système cible.
 * <kbd>[ REQUEST SYSTEM INFO ]</kbd> : Déclenche la collecte d'informations système depuis l'agent.
 * Affichage des Informations : Les données sont présentées dans des sections dépliables :
   * Informations sur le système d'exploitation
   * Informations CPU
   * Utilisation de la mémoire
   * Partitions de disque
   * Interfaces réseau
   * Utilisateurs connectés
   * Processus en cours
Onglet "PAYLOADS & PERSISTENCE"
Gère le déploiement et l'exécution de charges utiles.
 * Source de Payload (URL) : URL à partir de laquelle le payload sera téléchargé.
 * Chemin Cible sur l'Agent : L'emplacement sur le système cible où le payload sera stocké.
 * Actions :
   * <kbd>[ DEPLOY PAYLOAD ]</kbd> : Déploie le payload sur la cible.
   * <kbd>[ EXECUTE PAYLOAD ]</kbd> : Exécute le payload déployé.
   * <kbd>[ REMOVE PAYLOAD ]</kbd> : Supprime le payload de la cible.
Onglet "STEALTH & EVASION"
Configure les fonctionnalités de furtivité et d'anti-évasion de l'agent.
 * ACTIVATE PROCESS HIDING : Tente de masquer le processus de l'agent.
 * ENABLE ANTI-DEBUGGING : Active les mécanismes pour détecter et entraver le débogage.
 * BYPASS SANDBOX DETECTION : Active des techniques pour contourner les détections de sandbox.
 * <kbd>[ APPLY STEALTH SETTINGS ]</kbd> : Applique les paramètres de furtivité sélectionnés à l'agent.
Onglet "LOGS & STATUS"
Visualise et gère les logs de l'agent.
 * Flux de Logs en Direct de l'Agent : Un affichage des logs de l'agent en temps réel, similaire à celui du tableau de bord.
 * Archive de Logs Chiffrés :
   * <kbd>[ REFRESH ENCRYPTED LOGS ]</kbd> : Charge et déchiffre les logs de l'agent stockés localement (agent_logs.enc). Assure-toi que la clé AES dans l'onglet "AGENT CONTROL" est correcte pour le déchiffrement.
   * <kbd>[ DOWNLOAD RAW LOGS ]</kbd> : Télécharge le fichier de logs chiffré (agent_logs.enc).
⚙️ Configuration
Le fichier shared_config.json est automatiquement généré (si absent) lors du premier lancement de l'application. Il stocke les paramètres par défaut et la clé AES.
<p align="center">⚠️     ATTENTION     ⚠️</p>
Lors de la première génération, le champ default_target_url contiendra https://webhook.site/VOTRE_URL_UNIQUE_ICI. Il est impératif de remplacer cette URL par ta propre URL de service de réception de données (par exemple, un webhook.site personnalisé) via l'interface ou en modifiant manuellement le fichier shared_config.json avant de lancer l'agent.
---
## 👋 Contribuer
Les contributions sont les bienvenues ! Si tu souhaites améliorer HACKER-SUITE+2000, n'hésite pas à :
 * Fork le dépôt.
 * Créer une nouvelle branche (git checkout -b feature/AmazingFeature).
 * Effectuer tes modifications et les commiter (git commit -m 'Add some AmazingFeature').
 * Pousser vers la branche (git push origin feature/AmazingFeature).
 * Ouvrir une Pull Request.
Avant de contribuer, veuillez lire le CODE_OF_CONDUCT.md.
---
## 📝 Licence
Ce projet est sous licence LICENSE.
---
## 🤝 Code de conduite
Veuillez consulter le CODE_OF_CONDUCT.md pour les détails sur notre code de conduite.
