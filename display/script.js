document.addEventListener('DOMContentLoaded', () => {
    const dynamicMessageElement = document.getElementById('dynamic-message');
    const githubLinkElement = document.getElementById('github-link'); // Récupère le lien GitHub

    let messageIndex = 0;
    const messages = [
        "Le système de contrôle est opérationnel.",
        "Surveillez les activités de l'agent en temps réel.",
        "Explorez les fonctionnalités avancées de l'outil.",
        "Votre feedback est essentiel pour l'amélioration continue.",
        "Merci d'utiliser AGENT EXFILTRATION :: CYBER OPS HUB !"
    ];

    function updateMessage() {
        dynamicMessageElement.textContent = messages[messageIndex];
        messageIndex = (messageIndex + 1) % messages.length; // Passe au message suivant, boucle à la fin
    }

    // Met à jour le message toutes les 5 secondes (5000 millisecondes)
    // J'ai augmenté le délai pour rendre les messages plus lisibles.
    setInterval(updateMessage, 5000);

    // Tu peux ajouter d'autres fonctions ici pour récupérer des données depuis le serveur, etc.
});

