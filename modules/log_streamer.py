import sys
from datetime import datetime
import threading
import os

class LogStreamer:
    """
    Redirige sys.stdout et sys.stderr vers un buffer en mémoire,
    permettant de capturer toutes les sorties du programme, y compris les prints standards.
    """
    def __init__(self, max_buffer_lines: int = 1000):
        self._buffer = []
        self._lock = threading.Lock() # Pour la sécurité des threads
        self.max_buffer_lines = max_buffer_lines
        self.original_stdout = None
        self.original_stderr = None
        self._is_capturing = False # Pour éviter les démarrages multiples

    def write(self, message: str):
        """Méthode appelée quand quelque chose est écrit dans le flux."""
        # On s'assure de ne pas loguer les messages du LogStreamer lui-même
        # ou les traces de stack indésirables si elles viennent de sys.stdout/stderr redirection
        if message.strip() and not message.strip().startswith("[LogStreamer]"):
            formatted_message = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message.strip()}"
            with self._lock:
                self._buffer.append(formatted_message)
                if len(self._buffer) > self.max_buffer_lines:
                    self._buffer.pop(0) # Supprime la plus ancienne ligne

    def flush(self):
        """Méthode de flush (requise pour les flux sys.stdout/stderr)."""
        pass # Le buffer est en mémoire, pas besoin de flush disque

    def start_capturing(self):
        """Commence la redirection de sys.stdout et sys.stderr."""
        with self._lock:
            if not self._is_capturing:
                self.original_stdout = sys.stdout
                self.original_stderr = sys.stderr

                # Redirection effective
                sys.stdout = self
                sys.stderr = self
                self._is_capturing = True
                # Loguer via le logger global une fois que LogStreamer est activé
                # Ce message sera capturé par le LogStreamer lui-même
                if '_GLOBAL_MODULE_LOGGER' in globals() and globals()['_GLOBAL_MODULE_LOGGER'] is not None:
                     globals()['_GLOBAL_MODULE_LOGGER'].log_info("[LogStreamer] Capture des sorties standard activée.")
                else:
                    # Fallback si le logger n'est pas encore prêt ou est mock
                    # Attention: ce print sera capturé par le streamer lui-même
                    sys.__stdout__.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [LogStreamer] Capture des sorties standard activée (initialisation sans logger global).\n")


    def stop_capturing(self):
        """Arrête la redirection et restaure les flux originaux."""
        with self._lock:
            if self._is_capturing:
                # Restaurer d'abord les flux originaux avant de loguer l'arrêt
                if self.original_stdout is not None:
                    sys.stdout = self.original_stdout
                    self.original_stdout = None
                if self.original_stderr is not None:
                    sys.stderr = self.original_stderr
                    self.original_stderr = None
                self._is_capturing = False
                
                # Loguer l'arrêt via le logger global ou sys.__stdout__
                if '_GLOBAL_MODULE_LOGGER' in globals() and globals()['_GLOBAL_MODULE_LOGGER'] is not None:
                     globals()['_GLOBAL_MODULE_LOGGER'].log_info("[LogStreamer] Capture des sorties standard désactivée.")
                else:
                    sys.__stdout__.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [LogStreamer] Capture des sorties standard désactivée.\n")

    def get_logs(self, last_index: int = 0) -> tuple[list[str], int]:
        """Retourne les nouveaux logs et l'index total actuel."""
        with self._lock:
            if last_index < 0:
                last_index = 0
            elif last_index > len(self._buffer):
                last_index = len(self._buffer)

            new_logs = self._buffer[last_index:]
            return new_logs, len(self._buffer)

    def clear_logs(self):
        """Vide le buffer de logs."""
        with self._lock:
            self._buffer.clear()
        if '_GLOBAL_MODULE_LOGGER' in globals() and globals()['_GLOBAL_MODULE_LOGGER'] is not None:
            globals()['_GLOBAL_MODULE_LOGGER'].log_info("[LogStreamer] Buffer de logs vidé.")
        else:
            sys.__stdout__.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [LogStreamer] Buffer de logs vidé (sans logger global).\n")


# Pour les tests autonomes du module log_streamer
if __name__ == "__main__":
    print("\n--- Test autonome du module LogStreamer ---")

    # Créer une instance de LogStreamer
    test_streamer = LogStreamer(max_buffer_lines=5)

    # Simuler le démarrage de la capture
    test_streamer.start_capturing() # Ce print interne sera maintenant ignoré car la redirection se fait APRES

    print("Ceci est un message de test 1.")
    sys.stderr.write("Ceci est un message d'erreur sur stderr 2.\n")
    print("Test 3: Un autre message normal.")
    time.sleep(0.05) # Court délai pour la capture

    # Récupérer et afficher les logs
    current_logs, current_idx = test_streamer.get_logs(0)
    print("\nLogs initiaux capturés:")
    for log_line in current_logs:
        print(f"  > {log_line}")
    print(f"Total de lignes dans le buffer: {current_idx}")

    # Simuler plus de logs pour tester le buffer max_buffer_lines
    print("\nSimulation de logs supplémentaires (le buffer a une limite de 5 lignes):")
    print("Message 4")
    print("Message 5")
    print("Message 6 (devrait pousser le 'Test 1' hors du buffer)")
    time.sleep(0.05)

    updated_logs, updated_idx = test_streamer.get_logs(current_idx)
    print("\nNouveaux logs capturés (depuis le dernier index):")
    for log_line in updated_logs:
        print(f"  >> {log_line}")
    print(f"Nouveau total de lignes dans le buffer: {updated_idx}")

    # Vérifier le contenu total du buffer après dépassement
    all_final_logs, _ = test_streamer.get_logs(0)
    print("\nContenu final complet du buffer (devrait contenir les 5 dernières lignes):")
    for log_line in all_final_logs:
        print(f"  >>> {log_line}")
    assert len(all_final_logs) == 5, f"Erreur: Le buffer devrait contenir 5 lignes, mais en a {len(all_final_logs)}"
    # Vérifier que le premier log a bien été supprimé
    # Assurez-vous que le message est le bon après le préfixe de date
    assert "Ceci est un message de test 1." not in [log.split('] ')[1] for log in all_final_logs if '] ' in log], "Le plus ancien log n'a pas été supprimé."


    # Test du nettoyage du buffer
    print("\nTest du nettoyage du buffer...")
    test_streamer.clear_logs()
    cleared_logs, cleared_idx = test_streamer.get_logs(0)
    print(f"Buffer après nettoyage: {len(cleared_logs)} lignes, total {cleared_idx}")
    assert len(cleared_logs) == 0, "Erreur: Le buffer n'a pas été vidé correctement."

    # Arrêter la capture (ceci imprimera un message sur le stdout original)
    test_streamer.stop_capturing()
    print("Ceci est un message après l'arrêt de la capture, il ne devrait pas être dans le buffer.")

    # Vérification finale du buffer (devrait toujours être vide)
    final_check_logs, _ = test_streamer.get_logs(0)
    assert len(final_check_logs) == 0, "Erreur: Des logs ont été ajoutés après l'arrêt de la capture ou le nettoyage."

    print("\n--- Test LogStreamer terminé avec succès ! ---")

