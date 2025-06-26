#!/bin/bash

# Ce script est le point d'entrée unique pour l'installation et le lancement sur Termux.
# Il est conçu pour être exécuté depuis la racine du dossier 'exfiltration_agent'.

echo "--- Préparation de l'environnement Termux pour l'agent d'exfiltration ---"
echo "Assurez-vous d'avoir une connexion internet active."

# Définir le répertoire du projet (répertoire courant)
PROJECT_ROOT_DIR=$(pwd)
AGENT_NAME="exfiltration_agent" # Nom du répertoire

# 1. Mise à jour et installation des outils de base Termux
echo "[+] Mise à jour des packages APT..."
pkg update -y
pkg upgrade -y

echo "[+] Installation des outils de compilation, Python et bibliothèques C spécifiques..."
pkg install -y build-essential python python-pip openssl libffi clang pkg-config iproute2 procps coreutils

# 2. Le script est déjà dans le répertoire du projet.
echo "[+] Le script s'exécute déjà dans le répertoire du projet: $PROJECT_ROOT_DIR"

# 3. Installation des dépendances Python via requirements.txt
echo "[+] Installation des dépendances Python via requirements.txt..."
if [ -f "requirements.txt" ]; then
    python -m pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        echo "[+] Toutes les dépendances Python ont été installées avec succès."
    else
        echo "[-] Erreur lors de l'installation des dépendances Python."
        echo "Veuillez vérifier les messages d'erreur ci-dessus pour des indices."
        exit 1
    fi
else
    echo "Erreur: Le fichier requirements.txt est introuvable dans $PWD. Impossible de continuer."
    exit 1
fi

# 4. Générer la configuration partagée si elle n'existe pas ou est corrompue
# Cette logique est maintenant gérée par control_panel.py au démarrage.

echo ""
echo "--- Installation Termux terminée. Lancement du panneau de contrôle ---"
echo "Vous pouvez fermer ce terminal si le panneau de contrôle se lance en arrière-plan."
echo "Si le panneau de contrôle ne se lance pas automatiquement, lancez-le manuellement avec:"
echo "cd $PROJECT_ROOT_DIR && python $PROJECT_ROOT_DIR/control_panel.py"
echo ""

# Lancer le panneau de contrôle en arrière-plan
nohup python -u "$PROJECT_ROOT_DIR/control_panel.py" > "$PROJECT_ROOT_DIR/control_panel.log" 2>&1 &
echo "[+] Panneau de contrôle lancé en arrière-plan. Vérifiez $PROJECT_ROOT_DIR/control_panel.log pour sa sortie."
echo "[+] Accédez à l'interface dans votre navigateur Android sur : http://127.0.0.1:8050"

