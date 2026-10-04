# Politique RBAC — MCP SOC

Document de référence décrivant les rôles, permissions et règles d'accès du système MCP SOC.

Conforme aux sections A.6 (Sécurité commune) et B.6 (RBAC SOC) du cahier des charges PPP.

## Conformité au cahier des charges

### Section B.6 — RBAC SOC

Le cahier des charges impose quatre rôles :

- L1 : lecture
- L2 : lecture, query_siem, get_timeline, create_incident
- L3 : L2 plus block, isolate
- RSSI : supervision et administration

Cette politique implémente ces quatre rôles.

### Section A.6 — Sécurité commune

Le cahier des charges exige :

- RBAC avec JWT via Keycloak OIDC
- OAuth 2.1 + PKCE, interdiction du token passthrough
- Consentement à chaque action
- Humain dans la boucle pour toute action impactante
- Sorties d'outils considérées comme non fiables
- Journal d'audit

Toutes ces exigences sont implémentées et détaillées dans les sections suivantes.

## Rôles et permissions

Quatre rôles sont définis dans le realm SOC de Keycloak. Chaque rôle correspond à un niveau de responsabilité dans la chaîne de traitement des incidents.

### L1 — Analyste niveau 1

Mission : triage initial des alertes, consultation des tableaux de bord.

Permissions : lecture

Outils autorisés :
- hello
- get_alerts

Cas d'usage : un analyste L1 consulte les dernières alertes Wazuh pour un triage préliminaire. Il identifie les alertes suspectes et les escalade vers un L2.

Restrictions : ne peut pas investiguer (pas d'accès à query_siem, search_ioc, lookup_ip), ne peut pas créer d'incident, ne peut pas agir.

### L2 — Analyste niveau 2

Mission : investigation approfondie des incidents suspects remontés par L1.

Permissions : lecture, investigation, incident

Outils autorisés :
- hello
- get_alerts
- query_siem
- search_ioc
- get_timeline
- lookup_ip
- analyze_hash
- get_cve_info
- create_incident

Cas d'usage : un analyste L2 enrichit un IOC via AbuseIPDB et VirusTotal, consulte la chronologie d'un agent compromis, vérifie les CVE associées et crée un incident documenté.

Restrictions : ne peut pas bloquer d'IP ni isoler d'endpoint (pas de permission response).

### L3 — Analyste niveau 3

Mission : réponse à incident, actions de remédiation.

Permissions : lecture, investigation, incident, response

Outils autorisés : tous les outils de L2, plus :
- block_ip_firewall
- isolate_endpoint

Cas d'usage : un analyste L3 bloque une IP malveillante identifiée par L2, ou isole un endpoint compromis. Chaque action est soumise à validation humaine dans le client MCP.

Restrictions : ne peut pas modifier la configuration système (pas de permission administration).

### RSSI

Mission : supervision, administration, gestion des politiques.

Permissions : lecture, investigation, incident, response, administration

Outils autorisés : tous les outils MCP (12).

Cas d'usage : le RSSI peut consulter l'ensemble des logs d'audit, ajuster la liste blanche d'actifs protégés, superviser les actions sensibles des L3 et auditer la conformité.

## Matrice des permissions

| Outil | Permission requise | L1 | L2 | L3 | RSSI |
|---|---|---|---|---|---|
| hello | public | oui | oui | oui | oui |
| get_alerts | lecture | oui | oui | oui | oui |
| query_siem | investigation | non | oui | oui | oui |
| search_ioc | investigation | non | oui | oui | oui |
| get_timeline | investigation | non | oui | oui | oui |
| lookup_ip | investigation | non | oui | oui | oui |
| analyze_hash | investigation | non | oui | oui | oui |
| get_cve_info | investigation | non | oui | oui | oui |
| create_incident | incident | non | oui | oui | oui |
| block_ip_firewall | response | non | non | oui | oui |
| isolate_endpoint | response | non | non | oui | oui |
| send_notification | incident | non | oui | oui | oui |

## Implémentation technique

### Authentification

- Fournisseur : Keycloak (OpenID Connect)
- Type de token : JWT signé RS256
- Validation : clés publiques JWKS récupérées dynamiquement depuis Keycloak
- Champs vérifiés :
  - issuer (doit correspondre à http://localhost:8080/realms/SOC)
  - azp (doit correspondre à mcp-soc)
  - realm_access.roles (doit contenir un rôle autorisé)
- Expiration : vérifiée à chaque appel

### Autorisation

- Dictionnaire ROLES_AUTORISES dans server.py
- Vérification de la permission requise avant exécution de chaque outil
- Refus explicite si permission manquante (message retourné au LLM)
- Aucun token passthrough : le JWT est validé côté serveur MCP, jamais transmis à un service tiers

### Consentement à chaque action

Conformément à A.6, les actions impactantes (block_ip_firewall, isolate_endpoint) nécessitent une validation humaine explicite dans le client MCP avant exécution. Voir la section Validation humaine ci-dessous.

### Sorties d'outils non fiables

Conformément à A.6, toutes les sorties d'outils sont sanitisées avant d'être transmises au LLM. Les tentatives d'injection de prompt présentes dans les logs (par exemple "ignore previous instructions") sont neutralisées. Voir la section Sanitisation ci-dessous.

## Règles de sécurité

### Règle 1 — Validation du JWT

Le JWT doit être :
- présent dans le header Authorization sous forme Bearer
- non expiré
- signé par une clé valide de Keycloak
- émis pour le client mcp-soc
- porteur d'un rôle autorisé

Si l'une de ces conditions échoue, l'accès est refusé.

### Règle 2 — Séparation détection / investigation / remédiation

- L1 : détection uniquement
- L2 : investigation
- L3 : remédiation
- RSSI : supervision

Un L1 ou L2 ne peut jamais, même avec un JWT valide, exécuter une action de remédiation. Cette séparation garantit qu'aucune action destructive ne peut être déclenchée par un compte à faible privilège.

### Règle 3 — Humain dans la boucle

Conformément à A.6, toute action impactante (block_ip_firewall, isolate_endpoint) doit être validée par un analyste humain. Le client MCP affiche un récapitulatif de l'action et demande une confirmation explicite (y/n) avant exécution.

### Règle 4 — Liste blanche

Les actifs critiques (serveurs SOC, pare-feu, contrôleurs de domaine) sont inscrits dans whitelist.json. Toute tentative de blocage ou d'isolation sur ces actifs est refusée automatiquement, même avec un rôle L3 ou RSSI.

### Règle 5 — Sanitisation des sorties

Les sorties d'outils sont considérées comme non fiables. Elles sont limitées à 8000 caractères et les tentatives d'injection de prompt sont neutralisées avant transmission au LLM.

### Règle 6 — Journal d'audit

Toutes les actions sensibles sont journalisées dans audit.log avec horodatage UTC, outil, rôle, arguments et résultat. Ce journal est consultable par le RSSI.

### Règle 7 — Mode test

Le mode test (MCP_TEST_MODE=1) contourne l'authentification pour faciliter le développement. Ce mode doit être désactivé en production.

## Validation humaine

Conformément à A.6, les actions impactantes suivent ce flux :

1. Le LLM décide d'appeler un outil d'action (block_ip_firewall ou isolate_endpoint)
2. Le client MCP intercepte l'appel
3. Le client affiche l'outil et les arguments
4. Le client demande une confirmation explicite (y/n)
5. Si refus : l'action n'est pas exécutée, le LLM reçoit un message "refusé par l'analyste"
6. Si accord : l'action est transmise au serveur MCP
7. Le serveur MCP vérifie les permissions, la liste blanche, puis exécute en DRY-RUN
8. L'action est journalisée dans audit.log

Ce double contrôle (côté client + côté serveur) garantit qu'aucune action n'est exécutée sans validation humaine et sans vérification des règles.

## Sanitisation anti-injection

Conformément à A.6, les sorties d'outils sont traitées comme des entrées non fiables.

Mesures appliquées :

1. Limitation de taille : 8000 caractères maximum
2. Détection de mots-clés suspects : expressions longues comme "ignore previous", "forget previous", "jailbreak", "dan mode", "your new role", etc.
3. Neutralisation : les expressions détectées sont remplacées par [MOT-SUSPECT:...]
4. Suppression des caractères de contrôle non imprimables

Cette approche réduit le risque d'injection de prompt via les logs Wazuh. Elle ne l'élimine pas totalement mais constitue une défense en profondeur.

## Traçabilité

Toutes les actions sensibles sont journalisées dans audit.log.

Format d'une ligne :
timestamp_utc | outil=nom | role=role | args={...} | resultat=...

Exemples :

2026-10-04T19:07:48Z | outil=block_ip_firewall | role=L3 | args={'ip': '192.168.20.10'} | resultat=BLOQUE:whitelist
2026-10-04T19:28:07Z | outil=block_ip_firewall | role=L3 | args={'ip': '10.10.10.10'} | resultat=DRY-RUN autorise

Le journal permet de reconstituer qui a fait quoi, quand, et avec quel résultat.

## Test de la politique

### Test 1 — Vérifier les permissions par rôle

Pour chaque rôle, obtenir un token et tester un outil autorisé et un outil interdit.

Exemple pour L1 :

    TOKEN=$(curl -s -X POST http://localhost:8080/realms/SOC/protocol/openid-connect/token -d "client_id=mcp-soc" -d "username=analyst-l1" -d "password=0987654321" -d "grant_type=password" | jq -r .access_token)

Résultat attendu :
- get_alerts fonctionne
- query_siem retourne "Accès refusé : le rôle L1 ne possède pas la permission investigation"
- block_ip_firewall retourne "Accès refusé : le rôle L1 ne possède pas la permission response"

### Test 2 — Vérifier le blocage whitelist

Sur un compte L3, tester :

    block_ip_firewall(ip="192.168.20.10")

Résultat attendu : "ACTION BLOQUEE : l'IP 192.168.20.10 est un actif protege"

### Test 3 — Vérifier la validation humaine

Dans le client MCP, appeler une action sensible. Le client doit afficher la demande de confirmation.

Si l'utilisateur tape "n", l'action ne doit pas être exécutée.

### Test 4 — Vérifier l'audit

Après quelques actions, vérifier audit.log :

    cat ~/mcp-soc/audit.log

Chaque action sensible doit apparaître avec horodatage, outil, rôle, arguments et résultat.
