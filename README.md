# MCP SOC — Application MCP pour la Cybersécurité

Projet transversal PPP : Ecole Centrale des Logiciels Libres et de Télécommunications.

## Description

Serveur MCP (Model Context Protocol) exposant 12 outils de cybersécurité, connecté à Wazuh pour la détection, Keycloak pour l'authentification, et Ollama pour le raisonnement local. Enrichissement via AbuseIPDB, VirusTotal et NVD.

## Outils MCP disponibles

1. hello : Vérification serveur
2. query_siem : Recherche SIEM
3. get_alerts : Dernières alertes Wazuh
4. search_ioc : Recherche IOC
5. get_timeline : Chronologie agent
6. lookup_ip : Réputation IP via AbuseIPDB
7. analyze_hash : Analyse hash via VirusTotal
8. get_cve_info : Info CVE via NVD
9. block_ip_firewall : Blocage IP (DRY-RUN)
10. isolate_endpoint : Isolation agent (DRY-RUN)
11. create_incident : Création incident (DRY-RUN)
12. send_notification : Notification (DRY-RUN)

## RBAC

Roles disponibles : L1, L2, L3, RSSI.

Permissions :
- L1 : lecture
- L2 : lecture, investigation, incident
- L3 : lecture, investigation, incident, response
- RSSI : toutes + administration

Politique complète dans RBAC.md.

## Sécurité

- Authentification JWT RS256 via Keycloak OIDC
- Sanitisation anti-injection des sorties d'outils
- Liste blanche d'actifs protégés (whitelist.json)
- Validation humaine obligatoire pour toute action sensible
- Journal d'audit dans audit.log

## Installation

Prérequis : Python 3.10, Keycloak, Wazuh, Ollama.

Installation locale :

    git clone https://github.com/votre-user/mcp-soc.git
    cd mcp-soc
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env
    nano .env
    python server.py

Installation Docker :

    docker compose up -d

## Configuration

Fichier .env :

    KEYCLOAK_ISSUER=http://localhost:8080/realms/SOC
    KEYCLOAK_CLIENT_ID=mcp-soc
    WAZUH_INDEXER_PASSWORD=admin
    ABUSEIPDB_API_KEY=votre_cle
    VIRUSTOTAL_API_KEY=votre_cle
    MCP_TEST_MODE=0

## Utilisation

Mode test sans JWT :

    MCP_TEST_MODE=1 python server.py

Mode production avec JWT :

    python server.py

Lancer le client :

    python client_soc.py

## Structure du projet

- server.py : serveur MCP avec les 12 outils
- client_soc.py : client Python qui pilote le LLM
- whitelist.json : actifs protégés
- audit.log : journal d'audit
- requirements.txt : dépendances Python
- Dockerfile : image Docker
- docker-compose.yml : orchestration
- .env.example : template de configuration
- .gitignore : exclusions Git
- README.md : ce fichier
- RBAC.md : politique RBAC

## Tests

Vérifier le serveur :

    curl http://192.168.20.10:8000/sse

Tester un outil dans le client :

    Question > Utilise get_alerts avec limit=3

Tester la sécurité :

- Injection : log contenant "ignore previous instructions" doit être neutralisé
- Whitelist : block_ip_firewall sur 192.168.20.10 doit être bloqué
- Humain : toute action sensible demande confirmation

## Auteur

Nom : PPP Cybersécurité 2026
