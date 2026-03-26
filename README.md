# Analyse Forensique Réseau

## Description

Ce projet est un outil d'analyse forensique réseau conçu pour analyser des fichiers de capture PCAP (Packet Capture). Il détecte automatiquement des comportements suspects tels que l'exfiltration de données via UDP, les scans SYN et les scans agressifs de ports. L'outil fournit des statistiques détaillées, des rapports et une interface graphique conviviale.

## Fonctionnalités

- **Analyse de paquets** : Comptage des paquets IP, TCP et UDP.
- **Détection d'anomalies** :
  - Exfiltration UDP sur le port 9999 (configurable).
  - Scans SYN (type nmap -sS).
  - Scans agressifs (exploration de nombreux ports).
- **Statistiques réseau** : Top IP sources/destinations, ports cibles, protocoles observés.
- **Rapports** : Génération automatique de rapports texte avec exemples de données capturées.
- **Interface graphique** : Application Tkinter pour une analyse interactive avec onglets pour rapports, alertes, top IP et ports.
- **Scripts en ligne de commande** : Versions scriptées pour une analyse automatisée.

## Installation

### Prérequis

- Python 3.7 ou supérieur
- Bibliothèque Scapy : `pip install scapy`
- Tkinter (généralement inclus avec Python, sinon installer via votre gestionnaire de paquets système)

### Étapes

1. Clonez le dépôt :
   ```
   git clone https://github.com/votre-utilisateur/analyse_Forensique.git
   cd analyse_Forensique
   ```

2. Installez les dépendances :
   ```
   pip install scapy
   ```

3. (Optionnel) Créez un dossier `captures` pour stocker vos fichiers PCAP.

## Utilisation

### Interface Graphique (app.py)

Lancez l'application graphique :
```
python app.py
```

- Sélectionnez un fichier PCAP via le bouton "Choisir" ou chargez le dernier PCAP automatiquement.
- Cliquez sur "Analyser" pour traiter le fichier.
- Consultez les résultats dans les onglets : Rapport, Alertes, Top IP, Ports.

### Scripts en Ligne de Commande

#### analyse.py
Analyse le dernier fichier PCAP dans le dossier `captures` et génère un rapport dans `analysis_report.txt`.
```
python analyse.py
```

#### capture.py
Similaire à analyse.py, avec une logique légèrement différente pour la détection.
```
python capture.py
```

### Configuration

Modifiez les constantes en haut des fichiers pour ajuster :
- `TARGET_UDP_PORT` : Port UDP cible pour la détection d'exfiltration (défaut : 9999).
- Seuils de détection : `SYN_SCAN_MIN_SYN`, `SYN_SCAN_MIN_PORTS`, etc.

## Structure des Fichiers

- `app.py` : Application graphique principale.
- `analyse.py` : Script d'analyse en ligne de commande.
- `capture.py` : Script alternatif d'analyse.
- `analysis_report.txt` : Rapport généré automatiquement.
- `capture.pcap` : Exemple de fichier PCAP (à fournir).
- `events.txt` : Fichier d'événements (usage non spécifié).
- `README.md` : Ce fichier.

## Exemples

Après analyse d'un fichier PCAP suspect :
- Rapport : Statistiques et résumé des anomalies détectées.
- Alertes : Liste détaillée des paquets suspects avec timestamps, sources, etc.

## Sécurité et Avertissements

- Cet outil est destiné à des fins éducatives et forensiques. Ne l'utilisez pas pour des activités illégales.
- Analysez uniquement des fichiers PCAP que vous avez le droit d'examiner.
- Les seuils de détection sont configurables ; ajustez-les selon votre environnement.

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## Contributeurs

- [Votre nom] - Développement initial.

Pour des questions ou contributions, ouvrez une issue sur GitHub.