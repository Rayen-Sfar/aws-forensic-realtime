# cpu_stress.py
# Ce script est conçu pour consommer 100% d'un cœur CPU à des fins de test.
# À n'utiliser que sur des instances de test dédiées.

import multiprocessing

def burn_cpu():
    """Fonction qui exécute une boucle infinie pour consommer du CPU."""
    print("Démarrage du stress test CPU... Appuyez sur Ctrl+C pour arrêter.")
    while True:
        pass

if __name__ == '__main__':
    # Démarre le processus sur un seul cœur.
    # Pour stresser plusieurs cœurs, augmentez le nombre de processus.
    process = multiprocessing.Process(target=burn_cpu)
    process.start()
    process.join() # Attend la fin du processus (qui n'arrivera jamais sans interruption)